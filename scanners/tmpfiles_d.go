package scanners

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// TmpfilesResult represents a security misconfiguration or writable component in systemd-tmpfiles.
type TmpfilesResult struct {
	Path          string `json:"path"`
	Type          string `json:"type"` // "writable-dir", "writable-conf", "dangerous-directive"
	LineNumber    int    `json:"line_number,omitempty"`
	Directive     string `json:"directive,omitempty"`
	Target        string `json:"target,omitempty"`
	RiskLevel     string `json:"risk_level"`
	Reason        string `json:"reason"`
	ExploitHint   string `json:"exploit_hint,omitempty"`
	Remediation   string `json:"remediation,omitempty"`
	ComplianceTag string `json:"compliance_tag,omitempty"`
	IsDangerous   bool   `json:"is_dangerous"`
}

var defaultTmpfilesSearchDirs = []string{
	"/etc/tmpfiles.d",
	"/run/tmpfiles.d",
	"/usr/lib/tmpfiles.d",
}

var sensitiveSystemPaths = []string{
	"/etc/shadow",
	"/etc/passwd",
	"/etc/sudoers",
	"/etc/ld.so.preload",
}

// evaluateTmpfileDirective inspects a single line directive inside a tmpfiles configuration.
func evaluateTmpfileDirective(confPath string, lineNum int, line string, userCtx *UserContext) *TmpfilesResult {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return nil
	}

	dType := strings.TrimRight(fields[0], "!+-")
	target := fields[1]
	mode := ""
	if len(fields) >= 3 {
		mode = fields[2]
	}

	// 1. Check for world-writable mode permissions (e.g. 0666, 0777, 666, 777)
	if mode == "0666" || mode == "0777" || mode == "666" || mode == "777" {
		for _, sens := range sensitiveSystemPaths {
			if target == sens || strings.HasPrefix(target, sens) {
				return &TmpfilesResult{
					Path:          confPath,
					Type:          "dangerous-directive",
					LineNumber:    lineNum,
					Directive:     line,
					Target:        target,
					RiskLevel:     "CRITICAL",
					Reason:        fmt.Sprintf("Directive applies world-writable mode (%s) to critical system path %s", mode, target),
					ExploitHint:   fmt.Sprintf("Wait for systemd-tmpfiles execution, then modify %s directly", target),
					Remediation:   fmt.Sprintf("Restrict mode for %s to secure permissions (0644 or 0600)", target),
					ComplianceTag: "CIS-Linux-1.1 / NIST-CM-6",
					IsDangerous:   true,
				}
			}
		}
	}

	// 2. Check for ownership manipulation (z, Z) or file creation (f, F, L) in user-writable targets
	if dType == "z" || dType == "Z" || dType == "f" || dType == "F" || dType == "L" {
		if info, err := os.Stat(target); err == nil {
			if stat, ok := info.Sys().(*syscall.Stat_t); ok {
				if userCtx.CanWrite(int(stat.Uid), int(stat.Gid), stat.Mode) && stat.Uid != 0 {
					return &TmpfilesResult{
						Path:          confPath,
						Type:          "dangerous-directive",
						LineNumber:    lineNum,
						Directive:     line,
						Target:        target,
						RiskLevel:     "HIGH",
						Reason:        fmt.Sprintf("Directive %s targets user-writable path %s: permits symlink/TOCTOU privilege escalation", dType, target),
						ExploitHint:   fmt.Sprintf("Replace %s with a symlink targeting sensitive files before tmpfiles run", target),
						Remediation:   fmt.Sprintf("Remove or restrict %s directive on user-controlled path %s", dType, target),
						ComplianceTag: "CIS-Linux-1.1 / NIST-CM-6",
						IsDangerous:   true,
					}
				}
			}
		}
	}

	return nil
}

// auditTmpfileDirectives streams lines from a .conf file and inspects directives.
func auditTmpfileDirectives(confPath string, userCtx *UserContext) []TmpfilesResult {
	var results []TmpfilesResult
	f, err := os.Open(confPath)
	if err != nil {
		return results
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() && lineNum < 2000 {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		if res := evaluateTmpfileDirective(confPath, lineNum, line, userCtx); res != nil {
			results = append(results, *res)
		}
	}
	return results
}

// auditTmpfilesDir audits a single tmpfiles directory and its contained .conf files.
func auditTmpfilesDir(dir string, userCtx *UserContext) []TmpfilesResult {
	var results []TmpfilesResult

	dInfo, err := os.Stat(dir)
	if err != nil || !dInfo.IsDir() {
		return results
	}

	// Check if directory itself is writable by unprivileged user
	if dStat, ok := dInfo.Sys().(*syscall.Stat_t); ok {
		if userCtx.CanWrite(int(dStat.Uid), int(dStat.Gid), dStat.Mode) {
			results = append(results, TmpfilesResult{
				Path:          dir,
				Type:          "writable-dir",
				RiskLevel:     "CRITICAL",
				Reason:        fmt.Sprintf("Directory %s is user-writable: attacker can drop .conf files executed as root at boot/cleanup", dir),
				ExploitHint:   fmt.Sprintf("echo 'z /etc/shadow 0666 root root - -' > %s/pwn.conf", dir),
				Remediation:   fmt.Sprintf("Restrict directory permissions on %s (chmod 0755 %s; chown root:root %s)", dir, dir, dir),
				ComplianceTag: "CIS-Linux-1.1 / NIST-CM-6",
				IsDangerous:   true,
			})
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return results
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".conf") {
			continue
		}

		confPath := filepath.Join(dir, entry.Name())
		if info, err := entry.Info(); err == nil {
			if stat, ok := info.Sys().(*syscall.Stat_t); ok {
				if userCtx.CanWrite(int(stat.Uid), int(stat.Gid), stat.Mode) {
					results = append(results, TmpfilesResult{
						Path:          confPath,
						Type:          "writable-conf",
						RiskLevel:     "CRITICAL",
						Reason:        fmt.Sprintf("Configuration file %s is writable by current user: directives run as root", confPath),
						ExploitHint:   fmt.Sprintf("echo 'z /etc/shadow 0666 root root - -' >> %s", confPath),
						Remediation:   fmt.Sprintf("Restrict permissions on %s (chmod 0644 %s; chown root:root %s)", confPath, confPath, confPath),
						ComplianceTag: "CIS-Linux-1.1 / NIST-CM-6",
						IsDangerous:   true,
					})
				}
			}
		}

		results = append(results, auditTmpfileDirectives(confPath, userCtx)...)
	}

	return results
}

// scanTmpfilesInternal executes tmpfiles auditing across the configured directory list.
func scanTmpfilesInternal(searchDirs []string, userCtx *UserContext) []TmpfilesResult {
	var results []TmpfilesResult
	if userCtx == nil {
		return results
	}

	for _, dir := range searchDirs {
		results = append(results, auditTmpfilesDir(dir, userCtx)...)
	}
	return results
}

// ScanTmpfilesD audits systemd-tmpfiles configurations for writable drop-ins and insecure directives.
func ScanTmpfilesD() ([]TmpfilesResult, error) {
	return scanTmpfilesInternal(defaultTmpfilesSearchDirs, GetUserContext()), nil
}
