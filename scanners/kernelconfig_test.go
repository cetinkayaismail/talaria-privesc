package scanners

import (
	"testing"
)

func TestParseKernelConfig_Dangerous(t *testing.T) {
	// Test both explicit n and typical "# CONFIG_... is not set"
	rawConfig := `
# Linux kernel configuration
# CONFIG_STRICT_DEVMEM is not set
CONFIG_DEVKMEM=y
CONFIG_LEGACY_PTYS=y
`
	results := parseKernelConfig(rawConfig)

	if len(results) != 3 {
		t.Fatalf("Expected 3 dangerous findings, got %d", len(results))
	}

	foundDevmem := false
	foundDevkmem := false
	foundPtys := false

	for _, res := range results {
		switch res.ConfigKey {
		case "CONFIG_STRICT_DEVMEM":
			foundDevmem = true
			if res.Value != "is not set" {
				t.Errorf("Expected Value 'is not set', got '%s'", res.Value)
			}
			if res.RiskLevel != "HIGH" {
				t.Errorf("Expected RiskLevel HIGH, got '%s'", res.RiskLevel)
			}
		case "CONFIG_DEVKMEM":
			foundDevkmem = true
			if res.RiskLevel != "CRITICAL" {
				t.Errorf("Expected RiskLevel CRITICAL, got '%s'", res.RiskLevel)
			}
		case "CONFIG_LEGACY_PTYS":
			foundPtys = true
			if res.RiskLevel != "MEDIUM" {
				t.Errorf("Expected RiskLevel MEDIUM, got '%s'", res.RiskLevel)
			}
		}
	}

	if !foundDevmem {
		t.Errorf("Expected to detect unset CONFIG_STRICT_DEVMEM, but was not found")
	}
	if !foundDevkmem {
		t.Errorf("Expected to detect CONFIG_DEVKMEM, but was not found")
	}
	if !foundPtys {
		t.Errorf("Expected to detect CONFIG_LEGACY_PTYS, but was not found")
	}
}

func TestParseKernelConfig_NegativeBoundary(t *testing.T) {
	// Secure defaults
	rawConfig := `
CONFIG_STRICT_DEVMEM=y
# CONFIG_DEVKMEM is not set
# CONFIG_LEGACY_PTYS is not set
CONFIG_BASH=y
`
	results := parseKernelConfig(rawConfig)

	if len(results) != 0 {
		t.Fatalf("Expected 0 findings on secure configuration, got %d: %+v", len(results), results)
	}
}
