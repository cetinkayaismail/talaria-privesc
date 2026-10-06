package scanners

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"

	"talaria/internal/walkpool"
)

// CronJobResult matches your main.go expectations
type CronJobResult struct {
	Owner           string `json:"owner"`
	Schedule        string `json:"schedule"`
	Command         string `json:"command"`
	IsRootJob       bool   `json:"is_root_job"`
	IsPrivilegedJob bool   `json:"is_privileged_job"`
	IsDangerous     bool   `json:"is_dangerous"`
	RiskLevel       string `json:"risk_level,omitempty"`
	Reason          string `json:"reason,omitempty"`
	CronFile        string `json:"cron_file,omitempty"`
	Remediation     string `json:"remediation,omitempty"`
	ComplianceTag   string `json:"compliance_tag,omitempty"`
}

type SystemdTimerResult struct {
	Path          string `json:"path"`
	ServiceName   string `json:"service_name,omitempty"`
	IsDangerous   bool   `json:"is_dangerous"`
	Reason        string `json:"reason,omitempty"`
	Remediation   string `json:"remediation,omitempty"`
	ComplianceTag string `json:"compliance_tag,omitempty"`
}

// ScanCronJobs analyzes time-based execution for vulnerabilities
func ScanCronJobs() ([]CronJobResult, error) {
	var results []CronJobResult
	userCtx := GetUserContext()
	uid := userCtx.UID

	// Search standard cron paths: /etc/crontab, /etc/cron.d,
	// Debian/Ubuntu (/var/spool/cron/crontabs), and RHEL/CentOS/Fedora (/var/spool/cron)
	cronPaths := []string{"/etc/crontab", "/etc/cron.d", "/var/spool/cron", "/var/spool/cron/crontabs"}
	seenFiles := make(map[string]bool)

	for _, path := range cronPaths {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}

		if info.IsDir() {
			entries, _ := os.ReadDir(path)
			for _, entry := range entries {
				if !entry.IsDir() {
					targetPath := filepath.Join(path, entry.Name())
					if !seenFiles[targetPath] {
						seenFiles[targetPath] = true
						results = append(results, parseFile(targetPath, uid)...)
					}
				}
			}
		} else {
			if !seenFiles[path] {
				seenFiles[path] = true
				results = append(results, parseFile(path, uid)...)
			}
		}
	}
	return results, nil
}

func parseFile(filePath string, currentUID int) []CronJobResult {
	var results []CronJobResult
	file, err := os.Open(filePath)
	if err != nil {
		return results
	}
	defer file.Close()

	// System maintenance cron jobs to skip (low priority)
	skipPatterns := []string{
		"run-parts", "anacron", "popularity-contest", "checkarray",
		"ua-reboot", "ubuntu-advantage", "apt", "dpkg", "update-notifier",
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// A1: Detect dangerous environment variable definitions in crontab files
		// instead of silently skipping them. LD_PRELOAD, LD_LIBRARY_PATH, PATH, SHELL
		// in a writable crontab can be abused to hijack root cron job execution.
		if strings.Contains(line, "=") {
			dangerousEnvVars := []string{"LD_PRELOAD", "LD_LIBRARY_PATH", "PATH", "SHELL"}
			parts := strings.SplitN(line, "=", 2)
			envKey := strings.TrimSpace(parts[0])
			envVal := ""
			if len(parts) > 1 {
				envVal = strings.TrimSpace(parts[1])
			}
			for _, dangerous := range dangerousEnvVars {
				if strings.EqualFold(envKey, dangerous) {
					// Check if the crontab file itself is writable by the current user
					if info, statErr := os.Stat(filePath); statErr == nil {
						if stat, ok := info.Sys().(*syscall.Stat_t); ok {
							userCtx := GetUserContext()
							if userCtx != nil && userCtx.CanWrite(int(stat.Uid), int(stat.Gid), stat.Mode) {
								results = append(results, CronJobResult{
									Owner:       "root",
									Schedule:    "env",
									Command:     line,
									IsRootJob:   true,
									IsDangerous: true,
									Reason:      fmt.Sprintf("Writable crontab sets dangerous env var %s=%s — can hijack root job execution", envKey, envVal),
									CronFile:    filePath,
								})
							}
						}
					}
					break
				}
			}
			continue
		}

		// Skip system maintenance cron jobs
		shouldSkip := false
		for _, pattern := range skipPatterns {
			if strings.Contains(line, pattern) {
				shouldSkip = true
				break
			}
		}
		if shouldSkip {
			continue
		}

		res := analyzeCronLine(line, filePath, currentUID)
		if res != nil {
			results = append(results, *res)
		}
	}
	return results
}

type cronExtractedTarget struct {
	path       string
	workingDir string
	hasSudo    bool
}

func extractCronTargets(command string) []cronExtractedTarget {
	cmdNormalized := command
	for _, op := range []string{"&&", "||", ";", "|"} {
		cmdNormalized = strings.ReplaceAll(cmdNormalized, op, "\n")
	}
	subCmds := strings.Split(cmdNormalized, "\n")

	var workingDir string
	var targets []cronExtractedTarget

	for _, sub := range subCmds {
		sub = strings.TrimSpace(sub)
		if sub == "" {
			continue
		}
		if strings.HasPrefix(sub, "cd ") {
			dir := strings.TrimSpace(strings.TrimPrefix(sub, "cd "))
			dir = strings.Trim(dir, "\"'")
			if dir != "" {
				workingDir = dir
			}
			continue
		}

		tokens := strings.Fields(sub)
		if len(tokens) == 0 {
			continue
		}

		// Skip leading variable assignments e.g. FOO=bar
		idx := 0
		for idx < len(tokens) && strings.Contains(tokens[idx], "=") && !strings.HasPrefix(tokens[idx], "-") {
			idx++
		}
		if idx >= len(tokens) {
			continue
		}

		hasSudo := false
		// Strip wrappers: sudo, env, nice, nohup
		for idx < len(tokens) {
			base := filepath.Base(tokens[idx])
			if base == "sudo" {
				hasSudo = true
				idx++
				for idx < len(tokens) && strings.HasPrefix(tokens[idx], "-") {
					if tokens[idx] == "-u" || tokens[idx] == "-g" {
						idx += 2
					} else {
						idx++
					}
				}
				continue
			}
			if base == "env" || base == "nohup" || base == "nice" {
				idx++
				for idx < len(tokens) && strings.HasPrefix(tokens[idx], "-") {
					idx++
				}
				continue
			}
			break
		}
		if idx >= len(tokens) {
			continue
		}

		execToken := tokens[idx]
		baseExec := filepath.Base(execToken)
		interpreters := map[string]bool{
			"python": true, "python2": true, "python3": true,
			"bash": true, "sh": true, "dash": true, "zsh": true,
			"perl": true, "ruby": true, "php": true, "node": true,
		}

		var targetPath string
		if interpreters[baseExec] {
			for a := idx + 1; a < len(tokens); a++ {
				arg := tokens[a]
				if !strings.HasPrefix(arg, "-") {
					targetPath = arg
					break
				}
			}
		} else {
			targetPath = execToken
		}

		if targetPath != "" {
			targetPath = strings.Trim(targetPath, "\"'")
			resolved := targetPath
			if !filepath.IsAbs(targetPath) && workingDir != "" {
				resolved = filepath.Join(workingDir, strings.TrimPrefix(targetPath, "./"))
			}
			targets = append(targets, cronExtractedTarget{
				path:       resolved,
				workingDir: workingDir,
				hasSudo:    hasSudo,
			})
		}
	}
	return targets
}

func analyzeCronLine(line string, filePath string, currentUID int) *CronJobResult {
	fields := strings.Fields(line)
	if len(fields) < 6 {
		return nil
	}

	var jobOwner, command string
	if _, err := user.Lookup(fields[5]); err == nil {
		jobOwner = fields[5]
		command = strings.Join(fields[6:], " ")
	} else {
		jobOwner = "root"
		command = strings.Join(fields[5:], " ")
	}

	isRoot := (jobOwner == "root" || jobOwner == "0")
	isDangerous := false
	riskLevel := "INFO"
	reason := ""

	targets := extractCronTargets(command)
	userCtx := GetUserContext()

	for _, tgt := range targets {
		target := tgt.path
		targetBase := filepath.Base(target)

		// 1. Check writability of target file
		if info, err := os.Stat(target); err == nil {
			stat, ok := info.Sys().(*syscall.Stat_t)
			if ok && userCtx != nil {
				if userCtx.CanWrite(int(stat.Uid), int(stat.Gid), stat.Mode) {
					isDangerous = true
					riskLevel = "CRITICAL"
					reason = fmt.Sprintf("Cron executes a WRITABLE target: %s", target)
					break
				}
				// If target is owned by non-root user (e.g. www-data, unprivileged user)
				if isRoot && stat.Uid != 0 {
					isDangerous = true
					riskLevel = "CRITICAL"
					reason = fmt.Sprintf("Root cron executes target owned by unprivileged user (UID %d): %s", stat.Uid, target)
					break
				}
			}
		}

		// 2. Check writability of parent directory
		parentDir := filepath.Dir(target)
		if info, err := os.Stat(parentDir); err == nil {
			stat, ok := info.Sys().(*syscall.Stat_t)
			if ok && userCtx != nil && userCtx.CanWrite(int(stat.Uid), int(stat.Gid), stat.Mode) {
				isDangerous = true
				riskLevel = "CRITICAL"
				reason = fmt.Sprintf("Cron executes target in a WRITABLE directory: %s", parentDir)
				break
			}
		}

		// 3. Suspicious Root Cron heuristics (non-standard paths, hidden scripts, sudo)
		if isRoot {
			isSuspiciousLocation := false
			for _, suspiciousDir := range []string{"/var/www", "/tmp", "/dev/shm", "/var/tmp", "/srv", "/home"} {
				if strings.HasPrefix(target, suspiciousDir) || strings.HasPrefix(tgt.workingDir, suspiciousDir) {
					isSuspiciousLocation = true
					break
				}
			}

			isHidden := strings.HasPrefix(targetBase, ".")
			hasSecretKeyword := strings.Contains(strings.ToLower(command), "secret") ||
				strings.Contains(strings.ToLower(targetBase), "secret") ||
				strings.Contains(strings.ToLower(targetBase), "backdoor") ||
				strings.Contains(strings.ToLower(targetBase), "exploit")

			if isHidden || isSuspiciousLocation || hasSecretKeyword || tgt.hasSudo {
				isDangerous = true
				riskLevel = "CRITICAL"
				var details []string
				if isHidden {
					details = append(details, "hidden script execution")
				}
				if isSuspiciousLocation {
					loc := target
					if tgt.workingDir != "" {
						loc = tgt.workingDir
					}
					details = append(details, fmt.Sprintf("non-standard/web directory: %s", loc))
				}
				if hasSecretKeyword {
					details = append(details, "suspicious script keyword")
				}
				if tgt.hasSudo {
					details = append(details, "invokes sudo from root")
				}
				reason = fmt.Sprintf("Root cron executes anomalous task: %s", strings.Join(details, ", "))
				break
			}
		}
	}

	// Check for Wildcard Injection vectors (Critical finding)
	if !isDangerous {
		vulnerableCmds := []string{"tar", "chown", "chmod", "rsync", "7z", "zip", "rar", "7zip"}
		for _, vulnerableCmd := range vulnerableCmds {
			pattern := vulnerableCmd + " "
			if strings.Contains(command, pattern) && strings.Contains(command, "*") {
				isDangerous = true
				riskLevel = "CRITICAL"
				reason = "Cron executes '" + vulnerableCmd + "' with wildcard (*) - vulnerable to Wildcard Injection"
				break
			}
		}
	}

	if isRoot || isDangerous {
		remediation := ""
		complianceTag := "CIS-Linux-5.1.2 / NIST-CM-6"
		if isDangerous {
			remediation = fmt.Sprintf("chown root:root %s && chmod 0600 %s", filePath, filePath)
		}
		return &CronJobResult{
			Owner:           jobOwner,
			Schedule:        strings.Join(fields[0:5], " "),
			Command:         command,
			IsRootJob:       isRoot,
			IsPrivilegedJob: isRoot,
			IsDangerous:     isDangerous,
			RiskLevel:       riskLevel,
			Reason:          reason,
			CronFile:        filePath,
			Remediation:     remediation,
			ComplianceTag:   complianceTag,
		}
	}
	return nil
}

// ScanAnacronWritability checks if /etc/anacrontab is writable (B4).
// Anacrontab defines delayed root jobs — writable file allows code execution as root.
func ScanAnacronWritability() ([]WriteableResult, error) {
	var results []WriteableResult
	ctx := GetUserContext()

	info, err := os.Stat("/etc/anacrontab")
	if err != nil {
		return results, nil
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return results, nil
	}
	if ctx.CanWrite(int(stat.Uid), int(stat.Gid), stat.Mode) {
		results = append(results, WriteableResult{
			Path:            "/etc/anacrontab",
			OwnerUID:        int(stat.Uid),
			CurrentUserOwns: ctx.UID == int(stat.Uid),
			IsExecutable:    false,
			IsDangerous:     true,
			Type:            "Writable Anacrontab",
			RiskLevel:       "CRITICAL",
			Reason:          "Anacrontab is writable. Inject or modify delayed root jobs for privilege escalation.",
		})
	}
	return results, nil
}

// ScanSystemdTimers checks for writeable systemd timer or service files this might lead direct root
func ScanSystemdTimers() ([]SystemdTimerResult, error) {
	var results []SystemdTimerResult
	userCtx := GetUserContext()
	if userCtx == nil {
		return results, nil
	}

	systemdPaths := []string{
		"/etc/systemd/system",
		"/run/systemd/system",
		"/lib/systemd/system",
		"/usr/lib/systemd/system",
	}

	for _, path := range systemdPaths {
		if _, err := os.Stat(path); err != nil {
			continue
		}

		for entry := range walkpool.Walk(context.Background(), path, poolWorkers(), nil) {
			p := entry.Path
			d := entry.Entry

			// We care about .timer and .service files
			if strings.HasSuffix(d.Name(), ".timer") || strings.HasSuffix(d.Name(), ".service") {

				// Helper to check if a REAL file (not symlink) is writable by us
				checkWriteable := func(fpath string) (bool, string) {
					info, err := os.Stat(fpath) // Stat follows symlinks — gives us target perms
					if err != nil {
						return false, ""
					}
					stat, ok := info.Sys().(*syscall.Stat_t)
					if !ok {
						return false, ""
					}
					if userCtx.CanWrite(int(stat.Uid), int(stat.Gid), stat.Mode) {
						if info.Mode()&0002 != 0 {
							return true, "world-writeable"
						}
						if int(stat.Uid) == userCtx.UID {
							return true, "owner-writeable"
						}
						return true, "group-writeable"
					}
					return false, ""
				}

				info, err := d.Info()
				if err != nil {
					continue
				}

				isSymlink := (info.Mode() & os.ModeSymlink) != 0

				if isSymlink {
					// IMPORTANT: Linux symlink permission bits are ALWAYS 0777 (lrwxrwxrwx).
					// Checking Lstat on a symlink will ALWAYS report world-writable — this is a
					// kernel invariant and a classic false positive source.
					// Instead: check if the symlink TARGET is writable (that's the real risk).
					targetPath, err := filepath.EvalSymlinks(p)
					if err == nil && targetPath != p && targetPath != "/dev/null" {
						if writable, reason := checkWriteable(targetPath); writable {
							results = append(results, SystemdTimerResult{
								Path:          p,
								IsDangerous:   true,
								Reason:        fmt.Sprintf("Systemd symlink target is writable: %s (%s)", targetPath, reason),
								Remediation:   fmt.Sprintf("chown root:root %s && chmod 0644 %s", targetPath, targetPath),
								ComplianceTag: "CIS-Linux-5.1.9 / NIST-CM-6",
							})
						}
					}
				} else {
					// Real file — check directly
					if writable, reason := checkWriteable(p); writable {
						results = append(results, SystemdTimerResult{
							Path:          p,
							IsDangerous:   true,
							Reason:        fmt.Sprintf("Writable systemd unit file (%s)", reason),
							Remediation:   fmt.Sprintf("chown root:root %s && chmod 0644 %s && systemctl daemon-reload", p, p),
							ComplianceTag: "CIS-Linux-5.1.9 / NIST-CM-6",
						})
					}
				}

				// Deep Service Analysis (Service Writeability Tracking)
				// Even if the unit file is read-only, the script it executes might be writable!
				if file, err := os.Open(p); err == nil {
					scanner := bufio.NewScanner(file)
					for scanner.Scan() {
						line := strings.TrimSpace(scanner.Text())
						var cmdLine string
						switch {
						case strings.HasPrefix(line, "ExecStartPre="):
							cmdLine = strings.TrimPrefix(line, "ExecStartPre=")
						case strings.HasPrefix(line, "ExecStartPost="):
							cmdLine = strings.TrimPrefix(line, "ExecStartPost=")
						case strings.HasPrefix(line, "ExecStart="):
							cmdLine = strings.TrimPrefix(line, "ExecStart=")
						default:
							continue
						}

						// Strip systemd modifiers (- ignore error, @ change argv0, + full privs, ! capabilities)
						cmdLine = strings.TrimLeft(cmdLine, "-@+!")
						fields := strings.Fields(cmdLine)
						if len(fields) > 0 {
							execPath := fields[0]
							// Fast check if it's an absolute path
							if strings.HasPrefix(execPath, "/") {
								if writable, reason := checkWriteable(execPath); writable {
									results = append(results, SystemdTimerResult{
										Path:          p,
										IsDangerous:   true,
										Reason:        fmt.Sprintf("Service executes a writable script/binary: %s (%s)", execPath, reason),
										Remediation:   fmt.Sprintf("chown root:root %s && chmod 0755 %s", execPath, execPath),
										ComplianceTag: "CIS-Linux-5.1.9 / NIST-SI-7",
									})
								}
							}
						}
					}
					file.Close()
				}
			}
		}
	}

	return results, nil
}
