package scanners

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTmpfilesDAudit(t *testing.T) {
	tmpDir := t.TempDir()
	confDir := filepath.Join(tmpDir, "tmpfiles.d")
	if err := os.Mkdir(confDir, 0755); err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}

	userCtx := &UserContext{
		UID:  1000,
		GID:  1000,
		GIDs: map[int]bool{1000: true},
	}

	// 1. Positive Test: Writable .conf file
	vulnConf := filepath.Join(confDir, "vuln.conf")
	confContent := `# Test tmpfiles drop-in
z /etc/shadow 0666 root root - -
d /tmp/app 0755 root root - -
`
	if err := os.WriteFile(vulnConf, []byte(confContent), 0666); err != nil {
		t.Fatalf("Failed to write test conf: %v", err)
	}

	results := scanTmpfilesInternal([]string{confDir}, userCtx)
	if len(results) == 0 {
		t.Fatalf("Expected findings for writable conf and dangerous directive, got 0")
	}

	hasWritableConf := false
	hasDangerousDirective := false
	for _, r := range results {
		if r.Type == "writable-conf" && r.RiskLevel == "CRITICAL" {
			hasWritableConf = true
		}
		if r.Type == "dangerous-directive" && r.Target == "/etc/shadow" && r.RiskLevel == "CRITICAL" {
			hasDangerousDirective = true
		}
	}

	if !hasWritableConf {
		t.Errorf("Expected writable-conf finding, but was missing")
	}
	if !hasDangerousDirective {
		t.Errorf("Expected dangerous-directive finding targeting /etc/shadow, but was missing")
	}

	// 2. Negative Test: Safe non-writable .conf with standard safe directives
	safeDir := filepath.Join(tmpDir, "safe_tmpfiles.d")
	if err := os.Mkdir(safeDir, 0755); err != nil {
		t.Fatalf("Failed to create safe dir: %v", err)
	}
	safeConf := filepath.Join(safeDir, "safe.conf")
	safeContent := `# Standard vendor tmpfiles drop-in
d /run/systemd 0755 root root - -
f /run/motd.dynamic 0644 root root - -
`
	if err := os.WriteFile(safeConf, []byte(safeContent), 0644); err != nil {
		t.Fatalf("Failed to write safe conf: %v", err)
	}

	userCtxOther := &UserContext{
		UID:  2000,
		GID:  2000,
		GIDs: map[int]bool{2000: true},
	}

	safeResults := scanTmpfilesInternal([]string{safeDir}, userCtxOther)
	if len(safeResults) != 0 {
		t.Errorf("Expected 0 findings for safe non-writable config, got %d: %+v", len(safeResults), safeResults)
	}
}
