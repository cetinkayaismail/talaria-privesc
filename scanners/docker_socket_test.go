package scanners

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestDockerSocketEvaluation(t *testing.T) {
	tmpDir := t.TempDir()
	sockPath := filepath.Join(tmpDir, "docker.sock")

	l, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("Failed to create test unix socket: %v", err)
	}
	defer l.Close()

	// Positive Test: User has write access
	userCtxWritable := &UserContext{
		UID:  1000,
		GID:  1000,
		GIDs: map[int]bool{1000: true, 999: true}, // 999 could be docker group
	}

	results := scanDockerSocketInternal([]string{sockPath}, userCtxWritable)
	if len(results) == 0 {
		t.Fatalf("Expected vulnerable socket to be detected, got 0 findings")
	}

	res := results[0]
	if !res.IsDangerous || res.RiskLevel != "CRITICAL" {
		t.Errorf("Expected CRITICAL dangerous result, got %s (dangerous=%v)", res.RiskLevel, res.IsDangerous)
	}
	if res.ExploitHint == "" {
		t.Errorf("Expected exploit hint with container mount command, got empty")
	}

	// Negative Test 1: User has NO write access and NOT in group
	userCtxNoAccess := &UserContext{
		UID:  2000,
		GID:  2000,
		GIDs: map[int]bool{2000: true},
	}
	// Restrict socket to owner-only so other users cannot write
	_ = os.Chmod(sockPath, 0600)
	deniedResults := scanDockerSocketInternal([]string{sockPath}, userCtxNoAccess)
	if len(deniedResults) != 0 {
		t.Errorf("Expected 0 findings for user without access, got %d", len(deniedResults))
	}

	// Negative Test 2: Rootless user socket filter
	if !isRootlessContainerSocket("/run/user/1000/docker.sock", 1000) {
		t.Errorf("Expected rootless socket in /run/user/1000 to be recognized as rootless")
	}
	if !isRootlessContainerSocket("/home/user/.docker/run/docker.sock", 1000) {
		t.Errorf("Expected rootless socket in /home to be recognized as rootless")
	}
	if isRootlessContainerSocket("/var/run/docker.sock", 0) {
		t.Errorf("Host root socket /var/run/docker.sock should NOT be considered rootless")
	}
}
