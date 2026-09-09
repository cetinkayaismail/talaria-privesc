package scanners

import (
	"os/user"
	"strconv"
)

type GroupResult struct {
	GroupName     string `json:"group_name"`
	IsDangerous   bool   `json:"is_dangerous"`
	Reason        string `json:"reason"`
	ExploitHint   string `json:"exploit_hint,omitempty"`
	Remediation   string `json:"remediation,omitempty"`
	ComplianceTag string `json:"compliance_tag,omitempty"`
}

// PrivilegedGroups lists groups that often lead to privilege escalation usefull docker privescalation and lateral movement
var PrivilegedGroups = map[string]string{
	"docker": "Can spin up root containers and mount host filesystem.",
	"lxd":    "Can spin up root containers and mount host filesystem.",
	"lxc":    "Can spin up root containers and mount host filesystem.",
	"disk":   "Can directly read/write raw disk devices (e.g., /dev/sda).",
	"shadow": "Can read the /etc/shadow file to crack passwords.",
	"adm":    "Can read sensitive logs in /var/log.",
	"staff":  "Often has write permissions to /usr/local/bin.",
	"sudo":   "Can execute commands as root (check sudo -l).",
	"wheel":  "Can execute commands as root (check sudo -l).",
	"root":   "Is the root group.",
	"video":  "Can access the framebuffer (/dev/fb*) for keylogging or screen capture.",
	"input":  "Can read raw input events from /dev/input/* for keylogging.",
}

// GroupExploits maps dangerous groups to actionable GTFOBins or operational exploit hints
var GroupExploits = map[string]string{
	"docker": "docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
	"lxd":    "lxc init ubuntu:22.04 priv -c security.privileged=true && lxc config device add priv host-root disk source=/ path=/mnt/root recursive=true && lxc start priv && lxc exec priv /bin/sh",
	"lxc":    "lxc-start -n container_name -F /bin/sh",
	"disk":   "debugfs -w /dev/sda1 (or inspect/modify raw ext4 filesystem data)",
	"shadow": "john --wordlist=/usr/share/wordlists/rockyou.txt /etc/shadow",
	"staff":  "Plant wrapper script in /usr/local/bin shadowing standard system binary",
	"video":  "cat /dev/fb0 > /tmp/screen.raw (or ffmpeg -f fbdev -i /dev/fb0 /tmp/screen.mp4)",
	"input":  "evtest /dev/input/eventX (capture keyboard keystrokes including passwords)",
}

// ScanGroups checks if the current user belongs to any high-risk groups
func ScanGroups() ([]GroupResult, error) {
	var results []GroupResult

	userCtx := GetUserContext()
	if userCtx == nil {
		return results, nil
	}

	for gid := range userCtx.GIDs {
		group, err := user.LookupGroupId(strconv.Itoa(gid))
		if err != nil {
			continue
		}

		isDangerous := false
		reason := ""
		exploitHint := ""
		remediation := ""
		complianceTag := ""

		if desc, exists := PrivilegedGroups[group.Name]; exists {
			isDangerous = true
			reason = desc
			if hint, ok := GroupExploits[group.Name]; ok {
				exploitHint = hint
			}
			remediation = "gpasswd -d " + userCtx.Username + " " + group.Name
			complianceTag = "CIS-Linux-5.4.1 / NIST-AC-6(2)"
		}

		results = append(results, GroupResult{
			GroupName:     group.Name,
			IsDangerous:   isDangerous,
			Reason:        reason,
			ExploitHint:   exploitHint,
			Remediation:   remediation,
			ComplianceTag: complianceTag,
		})
	}

	return results, nil
}
