package scanners

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// DockerSocketResult represents an accessible container runtime UNIX socket on the host.
type DockerSocketResult struct {
	Path           string `json:"path"`
	Type           string `json:"type"`
	SocketOwnerUID int    `json:"socket_owner_uid"`
	SocketOwnerGID int    `json:"socket_owner_gid"`
	RiskLevel      string `json:"risk_level"`
	Reason         string `json:"reason"`
	ExploitHint    string `json:"exploit_hint,omitempty"`
	Remediation    string `json:"remediation,omitempty"`
	ComplianceTag  string `json:"compliance_tag,omitempty"`
	IsDangerous    bool   `json:"is_dangerous"`
}

var defaultDockerSocketCandidates = []string{
	"/var/run/docker.sock",
	"/run/docker.sock",
	"/var/run/podman/podman.sock",
	"/run/podman/podman.sock",
	"/run/containerd/containerd.sock",
	"/run/crio/crio.sock",
}

// isRootlessContainerSocket filters out rootless daemon sockets that execute within unprivileged user namespaces.
func isRootlessContainerSocket(path string, uid int) bool {
	clean := filepath.Clean(path)
	if strings.HasPrefix(clean, "/run/user/") || strings.HasPrefix(clean, "/home/") {
		return true
	}
	return false
}

// buildSocketExploitHint crafts the relevant GTFOBins container mount command.
func buildSocketExploitHint(path, service string) string {
	if strings.Contains(service, "podman") {
		return fmt.Sprintf("podman --remote --url unix://%s run --rm -v /:/host -it alpine chroot /host sh", path)
	}
	return fmt.Sprintf("docker -H unix://%s run --rm -v /:/host -it alpine chroot /host sh", path)
}

// evaluateSocketEntry evaluates a candidate socket path against the current user context.
func evaluateSocketEntry(path string, userCtx *UserContext) *DockerSocketResult {
	info, err := os.Stat(path)
	if err != nil || (info.Mode()&os.ModeSocket) == 0 {
		return nil
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}

	uid := int(stat.Uid)
	gid := int(stat.Gid)

	if isRootlessContainerSocket(path, uid) {
		return nil
	}

	canWrite := userCtx.CanWrite(uid, gid, stat.Mode)
	inGroup := userCtx.GIDs[gid]

	if !canWrite && !inGroup {
		return nil
	}

	serviceName := "docker"
	if strings.Contains(path, "podman") {
		serviceName = "podman"
	} else if strings.Contains(path, "containerd") {
		serviceName = "containerd"
	} else if strings.Contains(path, "crio") {
		serviceName = "crio"
	}

	reason := fmt.Sprintf("%s socket (%s) is accessible/writable: unprivileged access allows immediate host filesystem mount as root.", strings.ToUpper(serviceName), path)
	hint := buildSocketExploitHint(path, serviceName)

	return &DockerSocketResult{
		Path:           path,
		Type:           serviceName + "-socket",
		SocketOwnerUID: uid,
		SocketOwnerGID: gid,
		RiskLevel:      "CRITICAL",
		Reason:         reason,
		ExploitHint:    hint,
		Remediation:    fmt.Sprintf("Restrict socket permissions (0660 root:%s) and remove unprivileged users from %s group", serviceName, serviceName),
		ComplianceTag:  "CIS-Docker-2.1 / NIST-AC-6",
		IsDangerous:    true,
	}
}

// scanDockerSocketInternal performs the socket audit across a specified candidate list.
func scanDockerSocketInternal(candidates []string, userCtx *UserContext) []DockerSocketResult {
	var results []DockerSocketResult
	if userCtx == nil {
		return results
	}

	seenRealPaths := make(map[string]bool)
	for _, p := range candidates {
		realPath, err := filepath.EvalSymlinks(p)
		targetPath := p
		if err == nil {
			targetPath = realPath
		}
		if seenRealPaths[targetPath] {
			continue
		}

		res := evaluateSocketEntry(p, userCtx)
		if res != nil {
			seenRealPaths[targetPath] = true
			results = append(results, *res)
		}
	}
	return results
}

// ScanDockerSocket audits the host system for exposed container runtime sockets.
func ScanDockerSocket() ([]DockerSocketResult, error) {
	return scanDockerSocketInternal(defaultDockerSocketCandidates, GetUserContext()), nil
}
