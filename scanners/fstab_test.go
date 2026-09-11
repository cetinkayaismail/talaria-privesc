package scanners

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanFstab(t *testing.T) {
	InitUserContext()
	tmpDir := t.TempDir()
	fstabFile := filepath.Join(tmpDir, "fstab")

	fstabContent := `
# /etc/fstab mock
/dev/sda1   /         ext4    defaults            0 1
/dev/sda2   /home     ext4    defaults            0 2
/dev/sdb1   /mnt/usb  ext4    user,exec           0 0
/dev/sdc1   none      swap    sw                  0 0
tmpfs       /tmp      tmpfs   defaults,nosuid,nodev,noexec 0 0
`
	if err := os.WriteFile(fstabFile, []byte(fstabContent), 0644); err != nil {
		t.Fatalf("failed to write fstab: %v", err)
	}

	results, err := scanFstabInternal(fstabFile)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	// 1. Root partition '/' must NOT be in results
	for _, r := range results {
		if r.MountPoint == "/" {
			t.Errorf("system partition '/' must be skipped, but got: %+v", r)
		}
		if r.MountPoint == "/tmp" {
			t.Errorf("hardened '/tmp' must produce no findings, but got: %+v", r)
		}
	}

	// 2. /mnt/usb has user,exec without nosuid -> CRITICAL
	foundUSB := false
	for _, r := range results {
		if r.MountPoint == "/mnt/usb" {
			foundUSB = true
			if r.RiskLevel != "CRITICAL" {
				t.Errorf("expected CRITICAL for user mount without nosuid, got: %s", r.RiskLevel)
			}
		}
	}
	if !foundUSB {
		t.Errorf("expected finding for /mnt/usb user mount, got none")
	}

	// 3. /home has defaults (missing nosuid) -> HIGH
	foundHome := false
	for _, r := range results {
		if r.MountPoint == "/home" {
			foundHome = true
			if r.RiskLevel != "HIGH" {
				t.Errorf("expected HIGH for /home missing nosuid, got: %s", r.RiskLevel)
			}
		}
	}
	if !foundHome {
		t.Errorf("expected finding for /home missing nosuid, got none")
	}
}
