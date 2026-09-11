package scanners

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanXinetd(t *testing.T) {
	InitUserContext()
	tmpDir := t.TempDir()

	// 1. FP: Missing directory
	res, err := scanXinetdInternal(filepath.Join(tmpDir, "nonexistent"))
	if err != nil || len(res) != 0 {
		t.Fatalf("expected 0 findings for missing dir, got %d", len(res))
	}

	xinetdDir := filepath.Join(tmpDir, "xinetd.d")
	if err := os.Mkdir(xinetdDir, 0755); err != nil {
		t.Fatalf("failed to mkdir: %v", err)
	}

	// 2. FP: Disabled service with writable config
	disabledConf := filepath.Join(xinetdDir, "disabled_svc")
	disabledContent := "service disabled_svc\n{\n    disable = yes\n    server = /bin/true\n}\n"
	if err := os.WriteFile(disabledConf, []byte(disabledContent), 0666); err != nil {
		t.Fatalf("failed to write disabled config: %v", err)
	}

	res, err = scanXinetdInternal(xinetdDir)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if len(res) != 0 {
		t.Errorf("expected 0 findings for disabled service, got: %+v", res)
	}
	_ = os.Remove(disabledConf)

	// 3. TP: Enabled service with server_args following server directive
	binPath := filepath.Join(tmpDir, "my_handler")
	if err := os.WriteFile(binPath, []byte("#!/bin/sh\n"), 0777); err != nil {
		t.Fatalf("failed to write binary: %v", err)
	}

	enabledConf := filepath.Join(xinetdDir, "custom_svc")
	enabledContent := "service custom_svc\n{\n    disable = no\n    server = " + binPath + "\n    server_args = -s /var/log\n}\n"
	if err := os.WriteFile(enabledConf, []byte(enabledContent), 0644); err != nil {
		t.Fatalf("failed to write enabled config: %v", err)
	}

	res, err = scanXinetdInternal(xinetdDir)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	foundBin := false
	for _, r := range res {
		if r.ServerBinary == binPath {
			foundBin = true
			if r.RiskLevel != "CRITICAL" {
				t.Errorf("expected CRITICAL for writable server binary, got: %s", r.RiskLevel)
			}
		}
	}
	if !foundBin {
		t.Errorf("expected finding for writable server binary %s (not overwritten by server_args), got none", binPath)
	}

	// 4. FP: Root user context (UID 0) scanning 0644 root-owned config should NOT produce false positive
	userCtx := GetUserContext()
	origUID := userCtx.UID
	userCtx.UID = 0
	defer func() { userCtx.UID = origUID }()

	// Normal config file with 0644 permissions
	normalConf := filepath.Join(xinetdDir, "normal_svc")
	normalContent := "service normal_svc\n{\n    disable = no\n    server = /bin/true\n}\n"
	if err := os.WriteFile(normalConf, []byte(normalContent), 0644); err != nil {
		t.Fatalf("failed to write normal config: %v", err)
	}

	res, err = scanXinetdInternal(xinetdDir)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	for _, r := range res {
		if r.ConfigFile == normalConf {
			t.Errorf("normal 0644 root config should NOT be flagged as writable when scanning as root (UID 0), got: %+v", r)
		}
	}
}
