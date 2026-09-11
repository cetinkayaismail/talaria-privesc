package scanners

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanSudoersDropin(t *testing.T) {
	InitUserContext()
	tmpDir := t.TempDir()

	sudoersFile := filepath.Join(tmpDir, "sudoers")
	dropinDir := filepath.Join(tmpDir, "sudoers.d")

	// Create mock sudoers with #includedir
	sudoersContent := "# /etc/sudoers mock\n#includedir " + dropinDir + "\n"
	if err := os.WriteFile(sudoersFile, []byte(sudoersContent), 0640); err != nil {
		t.Fatalf("failed to write sudoers: %v", err)
	}

	// 1. FP: Missing directory
	res, err := scanSudoersDropinInternal(filepath.Join(tmpDir, "nonexistent"), sudoersFile)
	if err != nil || len(res) != 0 {
		t.Fatalf("expected 0 findings for nonexistent dir, got %d, err: %v", len(res), err)
	}

	// 2. Setup directory with 0755
	if err := os.Mkdir(dropinDir, 0755); err != nil {
		t.Fatalf("failed to mkdir: %v", err)
	}

	// 3. FP: Dotfiles and backup files with ~ should be ignored even if writable
	dotFile := filepath.Join(dropinDir, ".hidden_rules")
	if err := os.WriteFile(dotFile, []byte("ALL ALL=(ALL) ALL"), 0666); err != nil {
		t.Fatalf("failed to write dotfile: %v", err)
	}
	tildeFile := filepath.Join(dropinDir, "backup~")
	if err := os.WriteFile(tildeFile, []byte("ALL ALL=(ALL) ALL"), 0666); err != nil {
		t.Fatalf("failed to write tildfile: %v", err)
	}
	dotExtFile := filepath.Join(dropinDir, "rules.conf")
	if err := os.WriteFile(dotExtFile, []byte("ALL ALL=(ALL) ALL"), 0666); err != nil {
		t.Fatalf("failed to write dotExtFile: %v", err)
	}

	res, err = scanSudoersDropinInternal(dropinDir, sudoersFile)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	// Directory is owned by current test user so directory itself might be writable by user.
	// Let's verify files: dotfile and tildeFile should NOT appear in results.
	for _, r := range res {
		if r.Path == dotFile || r.Path == tildeFile || r.Path == dotExtFile {
			t.Errorf("dotfile/tilde file should be skipped by sudoers parser, but got finding: %s", r.Path)
		}
	}

	// 4. TP: Valid rule file without dot
	validRuleFile := filepath.Join(dropinDir, "99_custom_rules")
	if err := os.WriteFile(validRuleFile, []byte("ALL ALL=(ALL) ALL"), 0666); err != nil {
		t.Fatalf("failed to write validRuleFile: %v", err)
	}

	res, err = scanSudoersDropinInternal(dropinDir, sudoersFile)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	foundValid := false
	for _, r := range res {
		if r.Path == validRuleFile {
			foundValid = true
			if r.RiskLevel != "CRITICAL" {
				t.Errorf("expected CRITICAL risk, got %s", r.RiskLevel)
			}
		}
	}
	if !foundValid {
		t.Errorf("expected finding for valid rule file %s, but got none", validRuleFile)
	}

	// 5. FP: When scanning as UID 0 (root), standard 0750 directory / 0440 file must NOT be flagged
	userCtx := GetUserContext()
	origUID := userCtx.UID
	userCtx.UID = 0
	defer func() { userCtx.UID = origUID }()

	secureDir := filepath.Join(tmpDir, "secure_dropin.d")
	if err := os.Mkdir(secureDir, 0750); err != nil {
		t.Fatalf("failed to mkdir: %v", err)
	}
	secureRule := filepath.Join(secureDir, "01_secure")
	if err := os.WriteFile(secureRule, []byte("root ALL=(ALL) ALL"), 0440); err != nil {
		t.Fatalf("failed to write secure file: %v", err)
	}

	res, err = scanSudoersDropinInternal(secureDir, sudoersFile)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if len(res) != 0 {
		t.Errorf("standard 0750/0440 files should NOT be flagged as vulnerable when scanning as root (UID 0), got: %+v", res)
	}
}
