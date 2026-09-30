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
