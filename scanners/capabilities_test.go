package scanners

import (
	"os"
	"strings"
	"testing"
)

func TestFindGetcapBinary(t *testing.T) {
	// findGetcapBinary should either find a valid getcap or return empty string without error
	p := findGetcapBinary()
	if p != "" {
		info, err := os.Stat(p)
		if err != nil || info.IsDir() {
			t.Errorf("findGetcapBinary returned invalid path: %s", p)
		}
	}
}

func TestParseCapabilityLine_Dangerous(t *testing.T) {
	cases := []struct {
		line    string
		expPath string
		expCaps string
	}{
		{"/usr/bin/python3.10 cap_setuid=ep", "/usr/bin/python3.10", "cap_setuid=ep"},
		{"/usr/bin/perl = cap_sys_admin+ep", "/usr/bin/perl", "cap_sys_admin+ep"},
		{"/usr/bin/vim cap_dac_override+ep", "/usr/bin/vim", "cap_dac_override+ep"},
		{"/usr/bin/gdb cap_sys_ptrace=ep", "/usr/bin/gdb", "cap_sys_ptrace=ep"},
		{"/usr/bin/tar cap_dac_read_search+ep", "/usr/bin/tar", "cap_dac_read_search+ep"},
	}

	for _, tc := range cases {
		res := parseCapabilityLine(tc.line)
		if res == nil {
			t.Fatalf("expected result for line '%s', got nil", tc.line)
		}
		if res.Path != tc.expPath {
			t.Errorf("expected path '%s', got '%s'", tc.expPath, res.Path)
		}
		if !res.IsDangerous {
			t.Errorf("expected capability '%s' to be flagged as dangerous", tc.line)
		}
		if res.Remediation == "" {
			t.Errorf("expected remediation recommendation for dangerous capability")
		}
		if !strings.Contains(res.ComplianceTag, "CIS") {
			t.Errorf("expected CIS compliance tag, got '%s'", res.ComplianceTag)
		}
	}
}

func TestParseCapabilityLine_Benign(t *testing.T) {
	cases := []string{
		"/usr/sbin/tcpdump cap_net_raw,cap_net_admin+ep",
		"/usr/bin/ping = cap_net_raw+ep",
		"/usr/bin/auth_helper cap_audit_write+ep",
	}

	for _, line := range cases {
		res := parseCapabilityLine(line)
		if res == nil {
			t.Fatalf("expected non-nil result for benign capability line '%s'", line)
		}
		if res.IsDangerous {
			t.Errorf("expected benign capability line '%s' to NOT be flagged as dangerous", line)
		}
		if res.Remediation != "" {
			t.Errorf("expected empty remediation for benign capability, got '%s'", res.Remediation)
		}
	}
}

func TestParseCapabilityLine_Malformed(t *testing.T) {
	malformed := []string{"", "   ", "only_one_token", "\n"}
	for _, m := range malformed {
		if res := parseCapabilityLine(m); res != nil {
			t.Errorf("expected nil result for malformed line '%s', got: %+v", m, res)
		}
	}
}

func TestScanCapabilities_NegativeBoundary(t *testing.T) {
	tempDir := t.TempDir()

	results, err := ScanCapabilities(tempDir)
	if err != nil {
		t.Fatalf("unexpected error scanning clean temp directory: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 capability results on empty directory, got %d", len(results))
	}
}

func TestScanCapabilities_NonExistentPath(t *testing.T) {
	results, err := ScanCapabilities("/non/existent/path/talaria_test")
	if err != nil {
		return
	}
	if len(results) != 0 {
		t.Errorf("expected 0 capability results for non-existent path, got %d", len(results))
	}
}
