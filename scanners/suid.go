package scanners

import (
	"context"
	"debug/elf"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"talaria/internal/walkpool"
)

type SUIDResult struct {
	Path                 string   `json:"path"`
	IsDangerous          bool     `json:"is_dangerous"`
	Reason               string   `json:"reason,omitempty"`
	WritableLibraryPaths []string `json:"writable_library_paths,omitempty"`
	ExploitHint          string   `json:"exploit_hint,omitempty"`
	Remediation          string   `json:"remediation,omitempty"`
	ComplianceTag        string   `json:"compliance_tag,omitempty"`
}

// SGIDResult holds findings for SGID binaries
type SGIDResult struct {
	Path          string `json:"path"`
	OwnerGroup    string `json:"owner_group,omitempty"`
	IsDangerous   bool   `json:"is_dangerous"`
	Reason        string `json:"reason,omitempty"`
	ExploitHint   string `json:"exploit_hint,omitempty"`
	Remediation   string `json:"remediation,omitempty"`
	ComplianceTag string `json:"compliance_tag,omitempty"`
}

// PrivilegedGroupsForSGID: owning group of an SGID binary makes it dangerous
var privilegedSGIDGroups = map[string]bool{
	"shadow": true, "disk": true, "kmem": true, "tty": true,
	"audio": true, "video": true, "staff": true,
}

var (
	apparmorProfilesOnce   sync.Once
	cachedApparmorProfiles string
)

// hasAppArmorProfile checks if a specific profile name pattern is loaded in AppArmor.
func hasAppArmorProfile(name string) bool {
	apparmorProfilesOnce.Do(func() {
		if data, err := os.ReadFile("/sys/kernel/security/apparmor/profiles"); err == nil {
			cachedApparmorProfiles = string(data)
		}
	})
	return strings.Contains(cachedApparmorProfiles, name)
}

// Standard system SUID binaries that are safe/necessary — skip these to
// avoid noise. They are legitimate and well-audited.
var systemSUIDBinaries = map[string]bool{
	"chfn": true, "chsh": true, "gpasswd": true, "newgidmap": true,
	"newuidmap": true, "passwd": true, "su": true, "sudo": true,
	"pkexec": true, "mount": true, "umount": true, "ping": true, "ping6": true,
	"traceroute": true, "traceroute6": true, "at": true, "newgrp": true,
	"doas": true, "ssh-keysign": true, "fusermount": true, "fusermount3": true,
}

func isSandboxedApp(path string) bool {
	if strings.HasPrefix(path, "/snap/") && hasAppArmorProfile("snap.") {
		return true
	}
	if (strings.Contains(path, "/flatpak/") || strings.HasPrefix(path, "/var/lib/flatpak/")) && hasAppArmorProfile("flatpak") {
		return true
	}
	return false
}

func formatGTFORisk(entry gtfobinsEntry, isRootOwned bool, uid uint32) string {
	var caps []string
	if entry.Shell {
		caps = append(caps, "shell")
	}
	if entry.FileRead {
		caps = append(caps, "file-read")
	}
	if entry.FileWrite {
		caps = append(caps, "file-write")
	}
	capStr := strings.Join(caps, ", ")
	if capStr == "" {
		capStr = "privilege-escalation"
	}
	if isRootOwned {
		return fmt.Sprintf("GTFOBins match — SUID capabilities: [%s]. Can be abused for privilege escalation to root.", capStr)
	}
	return fmt.Sprintf("GTFOBins match — SUID capabilities: [%s]. Owned by UID %d — lateral movement / user pivoting risk.", capStr, uid)
}

func checkInterpreterLibraries(fileNameLower string) []string {
	switch fileNameLower {
	case "python", "python2", "python3":
		return checkWritableDirs([]string{
			"/usr/local/lib/python3.8/dist-packages", "/usr/local/lib/python3.9/dist-packages",
			"/usr/local/lib/python3.10/dist-packages", "/usr/local/lib/python3.11/dist-packages",
			"/usr/local/lib/python3.12/dist-packages",
			"/usr/lib/python3/dist-packages", "/usr/lib/python3.8/site-packages",
			"/usr/lib/python3.9/site-packages", "/usr/lib/python3.10/site-packages",
		})
	case "perl":
		return checkWritableDirs([]string{
			"/usr/local/lib/site_perl", "/usr/lib/x86_64-linux-gnu/perl5/5.30",
			"/usr/lib/x86_64-linux-gnu/perl5/5.34", "/usr/share/perl5",
		})
	case "ruby":
		return checkWritableDirs([]string{
			"/usr/local/lib/site_ruby", "/var/lib/gems",
		})
	}
	return nil
}

func evaluateSUIDBinary(path string, info os.FileInfo, runDeepELF bool) (SUIDResult, bool) {
	if isSandboxedApp(path) {
		return SUIDResult{}, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return SUIDResult{}, false
	}
	isRootOwned := (stat.Uid == 0)
	fileNameLower := strings.ToLower(filepath.Base(path))

	if systemSUIDBinaries[fileNameLower] {
		return SUIDResult{}, false
	}

	gtfoEntry, inGTFOBins := LookupGTFOBin(fileNameLower)
	isDangerous := false
	reason := ""
	var writableLibs []string

	if inGTFOBins && gtfoEntry.SUID {
		isDangerous = true
		reason = formatGTFORisk(gtfoEntry, isRootOwned, stat.Uid)
		writableLibs = checkInterpreterLibraries(fileNameLower)
		if len(writableLibs) > 0 {
			reason += " | POTENTIAL HIJACKING: Writable library paths found."
		}
	}

	rpathDirs := checkRPATH(path)
	if len(rpathDirs) > 0 {
		isDangerous = true
		reason += " | SO HIJACKING: Writable RPATH/RUNPATH found: " + strings.Join(rpathDirs, ", ")
		writableLibs = append(writableLibs, rpathDirs...)
	}

	exploitHint := ""
	if inGTFOBins && gtfoEntry.ExploitHint != "" {
		exploitHint = gtfoEntry.ExploitHint
	} else if isDangerous {
		exploitHint = GetExploitHint(path, "suid")
		if exploitHint == "" {
			exploitHint = "Create a malicious .so in one of the writable paths and run the binary."
		}
	}

	// Filter 1: Deep ELF String & PATH Hijack Analysis for custom root SUID binaries
	if !isDangerous && runDeepELF && isRootOwned && !inGTFOBins {
		if match, err := AnalyzeDeepELF(path); err == nil && match != nil {
			isDangerous = true
			reason = fmt.Sprintf(
				"Deep ELF Analysis: custom root SUID binary imports libc '%s()' and calls relative command '%s' (from string \"%s\") without absolute path — vulnerable to PATH hijacking.",
				match.ExecSymbol, match.Command, match.RawString,
			)
			exploitHint = fmt.Sprintf(
				"PATH hijack: create malicious executable /tmp/%s, export PATH=/tmp:$PATH, and execute %s",
				match.Command, path,
			)
		}
	}

	remediation := ""
	complianceTag := ""
	if isDangerous {
		remediation = fmt.Sprintf("chmod u-s %s", path)
		complianceTag = "CIS-Linux-6.1.13 / NIST-AC-6(1)"
	}

	return SUIDResult{
		Path:                 path,
		IsDangerous:          isDangerous,
		Reason:               reason,
		WritableLibraryPaths: writableLibs,
		ExploitHint:          exploitHint,
		Remediation:          remediation,
		ComplianceTag:        complianceTag,
	}, true
}

func ScanSUID(root string, deepELF ...bool) ([]SUIDResult, error) {
	var results []SUIDResult
	runDeepELF := len(deepELF) > 0 && deepELF[0]

	for entry := range walkpool.Walk(context.Background(), root, poolWorkers(), ShouldIgnore) {
		info, err := entry.Entry.Info()
		if err != nil || info.Mode()&os.ModeSetuid == 0 {
			continue
		}
		if res, ok := evaluateSUIDBinary(entry.Path, info, runDeepELF); ok {
			results = append(results, res)
		}
	}

	return results, nil
}

// checkRPATH extracts RPATH and RUNPATH from ELF and checks if they are writable.
func checkRPATH(path string) []string {
	f, err := elf.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var paths []string
	addTags := func(tags []string) {
		for _, tag := range tags {
			for _, p := range strings.Split(tag, ":") {
				p = strings.TrimSpace(p)
				if p != "" {
					paths = append(paths, p)
				}
			}
		}
	}
	if tags, err := f.DynString(elf.DT_RPATH); err == nil {
		addTags(tags)
	}
	if tags, err := f.DynString(elf.DT_RUNPATH); err == nil {
		addTags(tags)
	}

	if len(paths) == 0 {
		return nil
	}
	return checkWritableDirs(paths)
}

// ScanSGID finds binaries with the SGID bit set.
func ScanSGID(root string) ([]SGIDResult, error) {
	var results []SGIDResult

	// walkpool.Walk handles ShouldIgnore at the dispatcher level (SkipDir semantics).
	// Entries are delivered one at a time; appends to results are single-threaded.
	for entry := range walkpool.Walk(context.Background(), root, poolWorkers(), ShouldIgnore) {
		path := entry.Path
		d := entry.Entry

		info, err := d.Info()
		if err != nil {
			continue
		}

		// Check for SGID bit
		if info.Mode()&os.ModeSetgid != 0 {
			ownerGroup := "unknown"
			isDangerous := false

			if stat, ok := info.Sys().(*syscall.Stat_t); ok {
				ownerGroup = CachedGroupName(int(stat.Gid))
				if privilegedSGIDGroups[strings.ToLower(ownerGroup)] {
					isDangerous = true
				}
			}

			fileName := strings.ToLower(filepath.Base(path))

			// Safe privileged SGID binaries
			safePrivilegedSGID := map[string]bool{
				"chage": true, "expiry": true, "unix_chkpwd": true, "pam_extrausers_chkpwd": true, "bsd-write": true,
				"wall": true, "write": true,
			}

			if isDangerous && safePrivilegedSGID[fileName] {
				isDangerous = false
			}

			reason := ""
			if isDangerous {
				reason = "SGID binary owned by privileged group '" + ownerGroup + "'. Can be abused to gain group privileges."
			}

			// Standard system SGID binaries
			skipSystemSGID := map[string]bool{
				"write": true, "wall": true, "crontab": true, "ssh-agent": true,
				"dotlock.mailutils": true, "mail": true, "mailx": true,
			}
			if skipSystemSGID[fileName] && !isDangerous {
				continue
			}

			exploitHint := ""
			if isDangerous {
				exploitHint = "Binary is owned by privileged group '" + ownerGroup + "'. Exploit to gain group access."
			}

			remediation := ""
			complianceTag := ""
			if isDangerous {
				remediation = fmt.Sprintf("chmod g-s %s", path)
				complianceTag = "CIS-Linux-6.1.14 / NIST-AC-6(1)"
			}

			results = append(results, SGIDResult{
				Path:          path,
				OwnerGroup:    ownerGroup,
				IsDangerous:   isDangerous,
				Reason:        reason,
				ExploitHint:   exploitHint,
				Remediation:   remediation,
				ComplianceTag: complianceTag,
			})
		}
	}

	return results, nil
}

// checkWritableDirs checks if any of the provided directories exist and are
// writable by the current user. Uses the cached UserContext (D2) to avoid
// redundant user.Current() / GroupIds() syscalls.
func checkWritableDirs(dirs []string) []string {
	var writable []string
	ctx := GetUserContext()

	for _, dir := range dirs {
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			continue
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}
		if ctx.CanWrite(int(stat.Uid), int(stat.Gid), stat.Mode) {
			writable = append(writable, dir)
		}
	}
	return writable
}
