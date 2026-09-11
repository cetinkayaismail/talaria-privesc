package scanners

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanShellRC(t *testing.T) {
	InitUserContext()
	tmpDir := t.TempDir()

	customRoot := filepath.Join(tmpDir, "custom_root")
	if err := os.Mkdir(customRoot, 0755); err != nil {
		t.Fatalf("failed to mkdir: %v", err)
	}

	mockPasswd := filepath.Join(tmpDir, "passwd")
	passwdContent := "root:x:0:0:root:" + customRoot + ":/bin/bash\nbin:x:1:1:bin:/bin:/sbin/nologin\n"
	if err := os.WriteFile(mockPasswd, []byte(passwdContent), 0644); err != nil {
		t.Fatalf("failed to write passwd: %v", err)
	}

	// 1. Resolve root home test
	resolved := resolveRootHome(mockPasswd)
	if resolved != customRoot {
		t.Fatalf("expected resolved root home %s, got %s", customRoot, resolved)
	}

	// 2. Symlink to /dev/null test (should be skipped)
	devNullLink := filepath.Join(customRoot, ".bashrc")
	if err := os.Symlink("/dev/null", devNullLink); err != nil {
		t.Fatalf("failed to symlink: %v", err)
	}

	res, err := scanShellRCInternal(mockPasswd, customRoot)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	for _, r := range res {
		if r.Path == devNullLink || r.Path == "/dev/null" {
			t.Errorf("symlink to /dev/null should be skipped, but got: %s", r.Path)
		}
	}
	_ = os.Remove(devNullLink)

	// 3. Writable .bashrc test (CRITICAL)
	realBashrc := filepath.Join(customRoot, ".bashrc")
	if err := os.WriteFile(realBashrc, []byte("# bashrc\n"), 0666); err != nil {
		t.Fatalf("failed to write bashrc: %v", err)
	}

	res, err = scanShellRCInternal(mockPasswd, customRoot)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	found := false
	for _, r := range res {
		if r.Path == realBashrc {
			found = true
			if r.RiskLevel != "CRITICAL" {
				t.Errorf("expected CRITICAL for root bashrc, got: %s", r.RiskLevel)
			}
		}
	}
	if !found {
		t.Errorf("expected finding for root bashrc %s, got none", realBashrc)
	}

	// 4. FP: When scanning as UID 0 (root), standard 0644 .bashrc must NOT be flagged
	userCtx := GetUserContext()
	origUID := userCtx.UID
	userCtx.UID = 0
	defer func() { userCtx.UID = origUID }()

	if err := os.Chmod(realBashrc, 0644); err != nil {
		t.Fatalf("failed to chmod: %v", err)
	}
	res, err = scanShellRCInternal(mockPasswd, customRoot)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	for _, r := range res {
		if r.Path == realBashrc {
			t.Errorf("standard 0644 root .bashrc should NOT be flagged as vulnerable when scanning as root (UID 0), got: %+v", r)
		}
	}
}
