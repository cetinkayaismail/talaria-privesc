package scanners

import (
	"os"
	"testing"
)

func TestParseKernelVersion(t *testing.T) {
	tests := []struct {
		input    string
		expected [3]int
	}{
		{"5.15.0-91-generic", [3]int{5, 15, 0}},
		{"6.6.14", [3]int{6, 6, 14}},
		{"3.10.0-1160.el7.x86_64", [3]int{3, 10, 0}},
	}

	for _, tt := range tests {
		got := parseKernelVersion(tt.input)
		if got != tt.expected {
			t.Errorf("parseKernelVersion(%q) = %v; want %v", tt.input, got, tt.expected)
		}
	}
}

func TestCheckKernelRange_SmartContextMetadata(t *testing.T) {
	// Dirty Pipe range: 5.8.0 to 5.16.11
	parsed := [3]int{5, 10, 0}
	rawVer := "5.10.0-8-amd64"
	distro := DistroInfo{ID: "debian", VersionID: "11"}

	vulns := checkKernelRange(parsed, rawVer, distro)
	if len(vulns) == 0 {
		t.Fatalf("expected vulnerabilities for kernel 5.10.0, got 0")
	}

	// Verify all returned kernel CVEs have advisory demotion
	foundDirtyPipe := false
	for _, v := range vulns {
		if v.Confidence != "advisory_unverified" {
			t.Errorf("CVE %s has confidence %q; expected 'advisory_unverified'", v.CVE, v.Confidence)
		}
		if v.Severity != "INFO" {
			t.Errorf("CVE %s has severity %q; expected 'INFO'", v.CVE, v.Severity)
		}
		if v.CVE == "CVE-2022-0847" {
			foundDirtyPipe = true
		}
	}
	if !foundDirtyPipe {
		t.Errorf("expected CVE-2022-0847 (Dirty Pipe) to be found in range 5.10.0")
	}
}

func TestCheckKernelRange_ContainerAwareness(t *testing.T) {
	// Temporarily simulate CI environment
	origCI := os.Getenv("CI")
	os.Setenv("CI", "true")
	defer func() {
		if origCI == "" {
			os.Unsetenv("CI")
		} else {
			os.Setenv("CI", origCI)
		}
	}()

	parsed := [3]int{5, 10, 0}
	rawVer := "5.10.0-generic"
	distro := DistroInfo{ID: "ubuntu", VersionID: "20.04"}

	vulns := checkKernelRange(parsed, rawVer, distro)
	if len(vulns) == 0 {
		t.Fatalf("expected vulnerabilities in test kernel, got 0")
	}

	for _, v := range vulns {
		if v.ContainerNote == "" {
			t.Errorf("expected non-empty ContainerNote when CI/container is active for %s", v.CVE)
		}
	}
}

func TestCheckKernelRange_NegativeBoundary_OutOfRange(t *testing.T) {
	// Future kernel well beyond any known CVE range
	parsed := [3]int{9, 99, 99}
	rawVer := "9.99.99-custom"
	distro := DistroInfo{ID: "ubuntu", VersionID: "24.04"}

	vulns := checkKernelRange(parsed, rawVer, distro)
	if len(vulns) != 0 {
		t.Errorf("expected 0 vulnerabilities for future kernel 9.99.99, got %d", len(vulns))
	}
}
