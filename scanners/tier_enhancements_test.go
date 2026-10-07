package scanners

import (
	"os"
	"testing"
)

func TestKeePassAndBrowserPatternMatching(t *testing.T) {
	testCases := []struct {
		fileName string
		path     string
		expected bool
	}{
		{"database.kdbx", "/home/user/database.kdbx", true},
		{"backup.keyring", "/home/user/.local/share/keyrings/backup.keyring", true},
		{"logins.json", "/home/user/.mozilla/firefox/profile/logins.json", true},
		{"cookies.sqlite", "/home/user/.mozilla/firefox/profile/cookies.sqlite", true},
		{"key4.db", "/home/user/.mozilla/firefox/profile/key4.db", true},
		{"random.txt", "/home/user/random.txt", false},
		{"id_rsa.pub", "/home/user/.ssh/id_rsa.pub", false},
	}

	for _, tc := range testCases {
		matched, _ := matchCriticalPattern(tc.fileName, tc.path)
		if matched != tc.expected {
			t.Errorf("matchCriticalPattern(%q, %q) = %v; want %v", tc.fileName, tc.path, matched, tc.expected)
		}
	}
}

func TestScanCompilers(t *testing.T) {
	// Audit mode test
	auditResults := ScanCompilers(true)
	for _, r := range auditResults {
		if r.RiskLevel != "INFO" {
			t.Errorf("expected RiskLevel INFO in audit mode, got %s", r.RiskLevel)
		}
		if r.IsDangerous {
			t.Errorf("expected IsDangerous=false in audit mode for compiler %s", r.Name)
		}
	}

	// CTF mode test
	ctfResults := ScanCompilers(false)
	for _, r := range ctfResults {
		if r.RiskLevel != "INFO" {
			t.Errorf("expected RiskLevel INFO in ctf mode, got %s", r.RiskLevel)
		}
		if !r.IsDangerous {
			t.Errorf("expected IsDangerous=true in ctf mode for compiler %s", r.Name)
		}
	}
}

func TestScanNetworkEnvironment(t *testing.T) {
	// Test proxy environment variable capture
	os.Setenv("http_proxy", "http://10.0.0.1:8080")
	defer os.Unsetenv("http_proxy")

	results := ScanNetworkEnvironment()
	foundProxy := false
	for _, r := range results {
		if r.Protocol == "proxy" && r.ProcessName == "http://10.0.0.1:8080" {
			foundProxy = true
			if r.RiskLevel != "INFO" {
				t.Errorf("expected proxy RiskLevel to be INFO, got %s", r.RiskLevel)
			}
			break
		}
	}

	if !foundProxy {
		t.Errorf("expected to find active http_proxy in ScanNetworkEnvironment()")
	}
}

func TestScanMailSpools(t *testing.T) {
	// Verify that ScanMailSpools executes safely on host without panics
	fileResults, contentResults := ScanMailSpools()
	if fileResults == nil && contentResults != nil {
		t.Errorf("unexpected nil fileResults with non-nil contentResults")
	}
}

func TestPreviewFirstLine(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Text file with leading blank lines
	txtPath := tmpDir + "/test.conf"
	content := "\n\n  DB_PASS=SuperSecret123  \nSECOND_LINE=foo\n"
	if err := os.WriteFile(txtPath, []byte(content), 0600); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	preview := previewFirstLine(txtPath)
	if preview != "DB_PASS=SuperSecret123" {
		t.Errorf("previewFirstLine(%q) = %q; want %q", txtPath, preview, "DB_PASS=SuperSecret123")
	}

	// 2. Empty file
	emptyPath := tmpDir + "/empty.conf"
	if err := os.WriteFile(emptyPath, []byte(""), 0600); err != nil {
		t.Fatalf("failed to write empty file: %v", err)
	}
	if p := previewFirstLine(emptyPath); p != "" {
		t.Errorf("expected empty preview for empty file, got %q", p)
	}

	// 3. Binary credential database suffix
	kdbxPath := tmpDir + "/passwords.kdbx"
	if err := os.WriteFile(kdbxPath, []byte("fake binary kdbx content"), 0600); err != nil {
		t.Fatalf("failed to write kdbx file: %v", err)
	}
	expectedDesc := "[Binary Credential Store / Keyring Database]"
	if p := previewFirstLine(kdbxPath); p != expectedDesc {
		t.Errorf("previewFirstLine(%q) = %q; want %q", kdbxPath, p, expectedDesc)
	}

	// 4. Non-existent file
	if p := previewFirstLine(tmpDir + "/does_not_exist.txt"); p != "" {
		t.Errorf("expected empty preview for non-existent file, got %q", p)
	}
}
