package scanners

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
	"syscall"
)

// ContainerEscapeResult holds findings about container environments and escape vectors
type ContainerEscapeResult struct {
	Vector        string `json:"vector"`
	IsDangerous   bool   `json:"is_dangerous"`
	Reason        string `json:"reason"`
	Remediation   string `json:"remediation,omitempty"`
	ComplianceTag string `json:"compliance_tag,omitempty"`
}

// IsCIEnvironment returns true if running within common CI/CD environments (GitHub Actions, GitLab CI, generic CI).
func IsCIEnvironment() bool {
	return os.Getenv("CI") != "" || os.Getenv("GITHUB_ACTIONS") != "" || os.Getenv("GITLAB_CI") != ""
}

// DetectContainerEnvironment detects if execution is occurring inside a container (Docker/LXC/k8s/overlay)
// and returns whether a container was detected along with its type description.
func DetectContainerEnvironment() (bool, string) {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true, "Docker"
	}

	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		content := string(data)
		if strings.Contains(content, "docker") {
			return true, "Docker (cgroup)"
		} else if strings.Contains(content, "lxc") {
			return true, "LXC (cgroup)"
		} else if strings.Contains(content, "kubepods") {
			return true, "Kubernetes Pod"
		} else if strings.TrimSpace(content) == "0::/" || strings.Contains(content, "0::/") {
			if mountData, err := os.ReadFile("/proc/1/mountinfo"); err == nil {
				mc := string(mountData)
				if strings.Contains(mc, "overlay") || strings.Contains(mc, "docker") || strings.Contains(mc, "containerd") {
					return true, "Container (cgroupv2 + overlay)"
				}
			}
		}
	}

	if data, err := os.ReadFile("/proc/1/sched"); err == nil {
		firstLine := strings.SplitN(string(data), "\n", 2)[0]
		if !strings.Contains(firstLine, "systemd") && !strings.Contains(firstLine, "init") {
			return true, "Container (sched heuristic: PID1=" + strings.Fields(firstLine)[0] + ")"
		}
	}

	return false, "unknown"
}

// IsContainerEnvironment returns true if the host is running within a container or namespace jail.
func IsContainerEnvironment() bool {
	isContainer, _ := DetectContainerEnvironment()
	return isContainer
}

// ScanContainer detects if we are running inside a container (Docker/LXC/podman)
// and then checks for common escape vectors.
func ScanContainer() ([]ContainerEscapeResult, error) {
	var results []ContainerEscapeResult

	isContainer, containerType := DetectContainerEnvironment()
	if !isContainer {
		// Not in a container — no escape vectors to report
		return results, nil
	}

	results = append(results, ContainerEscapeResult{
		Vector:      "Container Detected: " + containerType,
		IsDangerous: false,
		Reason:      "Running inside a container. Checking for escape vectors...",
	})

	// 2. Check for privileged container (--privileged)
	// In a privileged container, all capabilities are available
	if data, err := os.ReadFile("/proc/self/status"); err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		for scanner.Scan() {
			line := scanner.Text()
			// CapEff: ffffffffffffffff means ALL capabilities (privileged)
			if strings.HasPrefix(line, "CapEff:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 && (strings.ToLower(fields[1]) == "000001ffffffffff" ||
					strings.ToLower(fields[1]) == "ffffffffffffffff") {
					results = append(results, ContainerEscapeResult{
						Vector:        "Privileged Container",
						IsDangerous:   true,
						Reason:        "Container running with --privileged: all capabilities available. Mount host filesystem and chroot to escape.",
						Remediation:   "Disallow --privileged mode and drop unnecessary capabilities in container runtime spec",
						ComplianceTag: "CIS-Docker-5.4 / NIST-AC-6",
					})
				}
			}
		}
	}

	// 3. Check for Docker socket mounted inside the container
	dockerSockPaths := []string{"/var/run/docker.sock", "/run/docker.sock"}
	for _, dsp := range dockerSockPaths {
		if info, err := os.Stat(dsp); err == nil && (info.Mode()&os.ModeSocket) != 0 {
			results = append(results, ContainerEscapeResult{
				Vector:        "Docker Socket in Container",
				IsDangerous:   true,
				Reason:        dsp + " is mounted inside the container. Use docker run to spawn a privileged container and mount the host filesystem.",
				Remediation:   "Remove " + dsp + " mount from container volume configuration",
				ComplianceTag: "CIS-Docker-2.1 / NIST-AC-6",
			})
		}
	}

	// 4. Check for host PID namespace (--pid=host)
	// In host PID, we can see and signal all host processes
	if data, err := os.ReadFile("/proc/1/cmdline"); err == nil {
		cmd := strings.ReplaceAll(string(data), "\x00", " ")
		// On host, PID 1 is systemd or init
		if strings.Contains(cmd, "systemd") || strings.Contains(cmd, "/sbin/init") {
			results = append(results, ContainerEscapeResult{
				Vector:        "Host PID Namespace",
				IsDangerous:   true,
				Reason:        "Container shares host PID namespace (--pid=host): can signal/ptrace host processes directly.",
				Remediation:   "Do not configure host PID namespace sharing (--pid=host) for unprivileged containers",
				ComplianceTag: "CIS-Docker-5.15 / NIST-SC-7",
			})
		}
	}

	// 5. Check for writable /proc/sysrq-trigger (requires host filesystem mount)
	if f, err := os.OpenFile("/proc/sysrq-trigger", os.O_WRONLY, 0); err == nil {
		f.Close()
		results = append(results, ContainerEscapeResult{
			Vector:        "Writable /proc/sysrq-trigger",
			IsDangerous:   true,
			Reason:        "Can write to sysrq-trigger: may indicate privileged access to host kernel interface.",
			Remediation:   "Mount /proc with read-only permissions inside container",
			ComplianceTag: "CIS-Docker-5.4 / NIST-SI-16",
		})
	}

	// 6. Check for sensitive host paths mounted inside container via mountinfo
	mountedTargets := make(map[string]bool)
	mountData, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		mountData, _ = os.ReadFile("/proc/mounts")
	}
	if len(mountData) > 0 {
		for _, line := range strings.Split(string(mountData), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 5 {
				mountedTargets[fields[4]] = true
			}
			if len(fields) >= 2 {
				mountedTargets[fields[1]] = true
			}
		}
	}

	sensitiveMounts := []string{"/etc/shadow", "/etc/sudoers", "/root/.ssh", "/host", "/hostfs", "/rootfs"}
	for _, p := range sensitiveMounts {
		if mountedTargets[p] {
			results = append(results, ContainerEscapeResult{
				Vector:        "Sensitive Host Path Mounted: " + p,
				IsDangerous:   true,
				Reason:        "Host path " + p + " is confirmed mounted inside container — permits host filesystem tampering or direct breakout.",
				Remediation:   "Remove bind mounts of sensitive host paths from container configuration",
				ComplianceTag: "CIS-Docker-5.4 / NIST-AC-6",
			})
		}
	}

	return results, nil
}

// DBusPolicyResult holds a finding from the D-Bus system policy scanner.
// Severity is tiered: CRITICAL (CVE match), HIGH (wildcard allow + running),
// MEDIUM (permissive policy + running, Polkit status unconfirmed), INFO (policy
// loose but service not running or only console-accessible).
type DBusPolicyResult struct {
	ConfigFile     string   `json:"config_file"`
	ServiceName    string   `json:"service_name"`
	RiskLevel      string   `json:"risk_level"`
	IsDangerous    bool     `json:"is_dangerous"`
	ServiceRunning bool     `json:"service_running"`
	AllowRules     []string `json:"allow_rules,omitempty"`
	ExploitHint    string   `json:"exploit_hint,omitempty"`
	CVENote        string   `json:"cve_note,omitempty"`
	Reason         string   `json:"reason"`
	Remediation    string   `json:"remediation,omitempty"`
	ComplianceTag  string   `json:"compliance_tag,omitempty"`
}

// dbusHighValueTarget describes a well-known D-Bus name worth auditing.
type dbusHighValueTarget struct {
	description string
	exploitHint string
	cveNote     string
}

// dbusHighValue maps well-known D-Bus names to their exploit description.
// Kept conservative — only names with documented abuse potential.
var dbusHighValue = map[string]dbusHighValueTarget{
	"org.freedesktop.PackageKit": {
		description: "Package manager service — can install arbitrary packages as root",
		exploitHint: "dbus-send --system --dest=org.freedesktop.PackageKit /org/freedesktop/PackageKit org.freedesktop.PackageKit.InstallPackages uint32:0 array:string:\"<pkg>\"",
		cveNote:     "Abuse requires Polkit interaction on modern systems; confirm with pkcheck first",
	},
	"org.freedesktop.Accounts": {
		description: "User accounts service — can create/modify system accounts",
		exploitHint: "dbus-send --system --dest=org.freedesktop.Accounts /org/freedesktop/Accounts org.freedesktop.Accounts.CreateUser string:\"attacker\" string:\"\" int32:1",
		cveNote:     "Related to CVE-2021-3560 (Polkit race on AccountsService)",
	},
	"com.ubuntu.USBCreator": {
		description: "USBCreator helper — arbitrary file write as root (CVE-2020-15708)",
		exploitHint: "dbus-send --system --dest=com.ubuntu.USBCreator /com/ubuntu/USBCreator com.ubuntu.USBCreator.Image string:/etc/shadow string:/tmp/shadow boolean:true",
		cveNote:     "CVE-2020-15708: affects ubuntu-gnome-disk-utility < 3.36.1 on Ubuntu 20.04",
	},
	"org.freedesktop.NetworkManager": {
		description: "NetworkManager — can add/activate VPN/network connections with arbitrary scripts",
		exploitHint: "nmcli connection add ... (requires active NetworkManager session); dispatcher scripts run as root",
		cveNote:     "Dispatcher scripts in /etc/NetworkManager/dispatcher.d/ run as root on connection events",
	},
	"org.freedesktop.hostname1": {
		description: "Hostname service — can write /etc/hostname; potential symlink abuse to overwrite files as root",
		exploitHint: "dbus-send --system --dest=org.freedesktop.hostname1 /org/freedesktop/hostname1 org.freedesktop.hostname1.SetHostname string:\"<name>\" boolean:false",
		cveNote:     "Low direct impact; useful for hostname-dependent trust relationships",
	},
	"org.freedesktop.login1": {
		description: "Logind session manager — can reboot, suspend, or manipulate active user sessions",
		exploitHint: "dbus-send --system --dest=org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager.Reboot boolean:false",
		cveNote:     "Session manipulation may enable TOCTOU attacks on credential files",
	},
}

// dbusNoisyNames are always present and well-understood — skip or suppress.
var dbusNoisyNames = map[string]bool{
	"org.freedesktop.DBus":       true, // The bus broker itself
	"org.freedesktop.PolicyKit1": true, // Polkit — always present
	"org.freedesktop.systemd1":   true, // systemd_overrides.go covers this
	"fi.w1.wpa_supplicant1":      true, // wpa_supplicant — low-value noise
}

// Pre-compiled patterns for D-Bus XML policy parsing
var (
	reDBusSendDest  = regexp.MustCompile(`send_destination\s*=\s*"([^"]*)"`)
	reDBusOwn       = regexp.MustCompile(`\bown\s*=\s*"([^"]*)"`)
	reDBusSendIface = regexp.MustCompile(`send_interface\s*=\s*"([^"]*)"`)
	reDBusAllow     = regexp.MustCompile(`(?i)<allow\b([^/]*?)/>`)
)

// ScanDBusPolicy audits /etc/dbus-1/system.d/ and /usr/share/dbus-1/system.d/
// for overly permissive allow rules that expose privileged D-Bus interfaces to
// unprivileged callers. Uses a 4-tier severity model to minimise false positives:
//
//	CRITICAL — writable config file (direct policy injection vector)
//	HIGH     — wildcard allow rule + service confirmed running (ProcSnapshot)
//	MEDIUM   — permissive policy for a high-value name + service running (Polkit status unconfirmed)
//	INFO     — permissive policy but service not running, or console-only scope
func ScanDBusPolicy() ([]DBusPolicyResult, error) {
	var results []DBusPolicyResult
	userCtx := GetUserContext()
	if userCtx == nil {
		return results, nil
	}

	// Attempt to get a process snapshot for service liveness checks.
	// Failure is non-fatal: we fall back to marking services as "unknown running state".
	snap, _ := GetProcSnapshot()

	configDirs := []string{"/etc/dbus-1/system.d", "/usr/share/dbus-1/system.d"}

	for _, dir := range configDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".conf") {
				continue
			}

			filePath := dir + "/" + entry.Name()
			serviceName := strings.TrimSuffix(entry.Name(), ".conf")

			// Skip definitively noisy well-known names
			if dbusNoisyNames[serviceName] {
				continue
			}

			// --- Gate 1: Writable config file (CRITICAL — direct injection) ---
			info, err := os.Stat(filePath)
			if err != nil {
				continue
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				continue
			}
			if userCtx.CanWrite(int(stat.Uid), int(stat.Gid), stat.Mode) {
				results = append(results, DBusPolicyResult{
					ConfigFile:     filePath,
					ServiceName:    serviceName,
					RiskLevel:      "CRITICAL",
					IsDangerous:    true,
					ServiceRunning: isDBusServiceRunning(snap, serviceName),
					Reason:         fmt.Sprintf("D-Bus policy file '%s' is writable by current user — can inject allow rules to gain unrestricted access to privileged service methods", filePath),
					Remediation:    fmt.Sprintf("chown root:root %s && chmod 0644 %s", filePath, filePath),
					ComplianceTag:  "CIS-Linux-5.3.5 / NIST-CM-6",
				})
				continue // No need to also parse the content
			}

			// --- Gate 2: Parse XML allow rules for permissive policies ---
			allowRules, hasWildcard, hasConsoleOnly := parseDBusAllowRules(filePath)
			if len(allowRules) == 0 {
				continue
			}

			hvTarget, isHighValue := dbusHighValue[serviceName]
			running := isDBusServiceRunning(snap, serviceName)

			var riskLevel string
			var reason, exploitHint, cveNote string
			isDangerous := false

			switch {
			case hasWildcard && running:
				// Wildcard send_destination or own="*" with service running — HIGH
				riskLevel = "HIGH"
				isDangerous = true
				reason = fmt.Sprintf("D-Bus policy for '%s' contains a wildcard allow rule with no interface restriction. Service is running — unprivileged callers may invoke privileged methods.", serviceName)
				if isHighValue {
					exploitHint = hvTarget.exploitHint
					cveNote = hvTarget.cveNote
				} else {
					exploitHint = fmt.Sprintf("dbus-send --system --dest=%s / --print-reply org.freedesktop.DBus.Introspectable.Introspect", serviceName)
				}

			case hasWildcard && !running:
				// Wildcard rule but service not active — INFO
				riskLevel = "INFO"
				isDangerous = false
				reason = fmt.Sprintf("D-Bus policy for '%s' has a permissive wildcard allow rule but the service does not appear to be running.", serviceName)

			case isHighValue && running:
				// Permissive (non-wildcard) rule for a known high-value service — MEDIUM
				riskLevel = "MEDIUM"
				isDangerous = false // Polkit gating unconfirmed
				reason = fmt.Sprintf("D-Bus policy for '%s' (%s) allows broad access. Service is running — Polkit gating status unconfirmed. Manual verification recommended.", serviceName, hvTarget.description)
				exploitHint = hvTarget.exploitHint
				cveNote = hvTarget.cveNote

			case hasConsoleOnly:
				// at_console="true" rules — only relevant for GUI sessions
				riskLevel = "INFO"
				isDangerous = false
				reason = fmt.Sprintf("D-Bus policy for '%s' has at_console='true' allow rules — exploitable only from an active local/GUI session.", serviceName)

			default:
				// Generic permissive rule for an unknown service — INFO only
				riskLevel = "INFO"
				isDangerous = false
				reason = fmt.Sprintf("D-Bus policy file '%s' contains permissive allow rules. Low confidence without service context.", filePath)
			}

			results = append(results, DBusPolicyResult{
				ConfigFile:     filePath,
				ServiceName:    serviceName,
				RiskLevel:      riskLevel,
				IsDangerous:    isDangerous,
				ServiceRunning: running,
				AllowRules:     allowRules,
				ExploitHint:    exploitHint,
				CVENote:        cveNote,
				Reason:         reason,
				Remediation:    fmt.Sprintf("Review /etc/dbus-1/system.d/%s.conf and restrict allow rules to specific send_interface values", serviceName),
				ComplianceTag:  "CIS-Linux-5.3.5 / NIST-CM-6 / MITRE-T1548",
			})
		}
	}

	return results, nil
}

// parseDBusAllowRules scans a D-Bus XML policy file for <allow .../> rules.
// Returns: the list of rule summaries, whether any wildcard rule was found,
// and whether all rules are console-only.
func parseDBusAllowRules(filePath string) (rules []string, hasWildcard bool, consoleOnly bool) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, false, false
	}
	defer f.Close()

	var sb strings.Builder
	buf := make([]byte, 32768)
	for {
		n, err := f.Read(buf)
		if n > 0 {
			sb.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}
	content := sb.String()

	matches := reDBusAllow.FindAllStringSubmatch(content, -1)
	if len(matches) == 0 {
		return nil, false, false
	}

	allConsole := true
	for _, m := range matches {
		attrs := m[1] // capture group: attribute string inside <allow ... />

		// Skip comment-only lines
		if strings.TrimSpace(attrs) == "" {
			continue
		}

		// Check for at_console scope
		isConsole := strings.Contains(attrs, "at_console=\"true\"") || strings.Contains(attrs, "at_console='true'")
		if !isConsole {
			allConsole = false
		}

		// Extract send_destination
		destMatch := reDBusSendDest.FindStringSubmatch(attrs)
		// Extract own=
		ownMatch := reDBusOwn.FindStringSubmatch(attrs)
		// Check for send_interface restriction (narrows scope)
		ifaceMatch := reDBusSendIface.FindStringSubmatch(attrs)

		dest := ""
		if len(destMatch) > 1 {
			dest = destMatch[1]
		}
		own := ""
		if len(ownMatch) > 1 {
			own = ownMatch[1]
		}
		iface := ""
		if len(ifaceMatch) > 1 {
			iface = ifaceMatch[1]
		}

		// A wildcard is: send_destination="*" or own="*", AND no interface restriction
		isWild := (dest == "*" || own == "*") && iface == ""
		if isWild {
			hasWildcard = true
		}

		// Build a human-readable rule summary
		var parts []string
		if dest != "" {
			parts = append(parts, "send_destination="+dest)
		}
		if own != "" {
			parts = append(parts, "own="+own)
		}
		if iface != "" {
			parts = append(parts, "send_interface="+iface)
		}
		if isConsole {
			parts = append(parts, "at_console=true")
		}
		if len(parts) > 0 {
			rules = append(rules, strings.Join(parts, " "))
		}
	}

	// consoleOnly is only meaningful if we actually found rules
	if len(rules) == 0 {
		return nil, false, false
	}
	return rules, hasWildcard, allConsole
}

// isDBusServiceRunning checks if a process matching the D-Bus service name
// is currently running, using the shared ProcSnapshot.
// Returns false (conservatively) if the snapshot is unavailable.
func isDBusServiceRunning(snap *ProcSnapshot, serviceName string) bool {
	if snap == nil {
		return false
	}
	// Derive likely process names from the D-Bus service name.
	// e.g. "org.freedesktop.PackageKit" → ["packagekitd", "packagekit"]
	parts := strings.Split(serviceName, ".")
	candidates := make(map[string]bool)
	if len(parts) > 0 {
		last := strings.ToLower(parts[len(parts)-1])
		candidates[last] = true
		candidates[last+"d"] = true
		candidates[last+"-daemon"] = true
	}
	// Also try the second-to-last component (e.g. "ubuntu" from "com.ubuntu.USBCreator")
	if len(parts) > 1 {
		second := strings.ToLower(parts[len(parts)-2])
		if second != "freedesktop" && second != "com" && second != "org" && second != "fi" {
			candidates[second] = true
		}
	}

	for i := range snap.Processes {
		comm := strings.ToLower(snap.Processes[i].Comm)
		cmdline := strings.ToLower(snap.Processes[i].Cmdline)
		if candidates[comm] {
			return true
		}
		// Fallback: check if the service name fragment appears in the full cmdline
		for c := range candidates {
			if len(c) > 4 && strings.Contains(cmdline, c) {
				return true
			}
		}
	}
	return false
}
