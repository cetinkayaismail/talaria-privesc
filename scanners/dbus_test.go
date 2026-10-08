package scanners

import (
	"os"
	"testing"
)

// ── POSITIVE TESTS (must detect) ─────────────────────────────────────────────

// TestDBusWildcardAllowRule: send_destination="*" with no interface restriction
// must be flagged as a wildcard.
func TestDBusWildcardAllowRule(t *testing.T) {
	const conf = `<?xml version="1.0" encoding="UTF-8"?>
<busconfig>
  <policy context="default">
    <allow send_destination="*"/>
  </policy>
</busconfig>`
	rules, hasWildcard, consoleOnly := parseDBusAllowRules_fromContent(conf)
	if !hasWildcard {
		t.Errorf("Expected hasWildcard=true for send_destination=\"*\", got false; rules=%v", rules)
	}
	if consoleOnly {
		t.Errorf("Expected consoleOnly=false for wildcard rule without at_console")
	}
	if len(rules) == 0 {
		t.Errorf("Expected at least one rule summary, got none")
	}
}

// TestDBusOwnWildcardRule: own="*" must also be treated as a wildcard.
func TestDBusOwnWildcardRule(t *testing.T) {
	const conf = `<?xml version="1.0" encoding="UTF-8"?>
<busconfig>
  <policy context="default">
    <allow own="*"/>
  </policy>
</busconfig>`
	_, hasWildcard, _ := parseDBusAllowRules_fromContent(conf)
	if !hasWildcard {
		t.Errorf("Expected hasWildcard=true for own=\"*\", got false")
	}
}

// TestDBusConsoleOnlyRule: at_console="true" rules must set consoleOnly=true
// when all rules carry that attribute.
func TestDBusConsoleOnlyRule(t *testing.T) {
	const conf = `<?xml version="1.0" encoding="UTF-8"?>
<busconfig>
  <policy at_console="true">
    <allow send_destination="org.freedesktop.NetworkManager" at_console="true"/>
  </policy>
</busconfig>`
	rules, _, consoleOnly := parseDBusAllowRules_fromContent(conf)
	if !consoleOnly {
		t.Errorf("Expected consoleOnly=true for at_console-only rule, got false; rules=%v", rules)
	}
}

// TestDBusInterfaceRestrictedNotWildcard: a rule with send_interface specified
// must NOT be treated as a wildcard regardless of send_destination.
func TestDBusInterfaceRestrictedNotWildcard(t *testing.T) {
	const conf = `<?xml version="1.0" encoding="UTF-8"?>
<busconfig>
  <policy context="default">
    <allow send_destination="org.freedesktop.NetworkManager"
           send_interface="org.freedesktop.DBus.Properties"/>
  </policy>
</busconfig>`
	_, hasWildcard, _ := parseDBusAllowRules_fromContent(conf)
	if hasWildcard {
		t.Errorf("Expected hasWildcard=false for interface-restricted rule, got true")
	}
}

// ── BOUNDARY / NEGATIVE TESTS ────────────────────────────────────────────────

// TestDBusDenyOnlyNoResults: a file with only <deny> rules must produce no findings.
func TestDBusDenyOnlyNoResults(t *testing.T) {
	const conf = `<?xml version="1.0" encoding="UTF-8"?>
<busconfig>
  <policy context="default">
    <deny send_destination="*"/>
  </policy>
</busconfig>`
	rules, hasWildcard, _ := parseDBusAllowRules_fromContent(conf)
	if len(rules) != 0 || hasWildcard {
		t.Errorf("Expected no rules for deny-only config, got rules=%v hasWildcard=%v", rules, hasWildcard)
	}
}

// TestDBusEmptyFile: empty content must produce zero results.
func TestDBusEmptyFile(t *testing.T) {
	rules, hasWildcard, _ := parseDBusAllowRules_fromContent("")
	if len(rules) != 0 || hasWildcard {
		t.Errorf("Expected no rules for empty file, got rules=%v hasWildcard=%v", rules, hasWildcard)
	}
}

// ── DATA MAP COVERAGE ────────────────────────────────────────────────────────

// TestDBusNoisyNameSuppressed: core noisy names must be in the suppression map.
func TestDBusNoisyNameSuppressed(t *testing.T) {
	required := []string{
		"org.freedesktop.DBus",
		"org.freedesktop.PolicyKit1",
		"org.freedesktop.systemd1",
	}
	for _, name := range required {
		if !dbusNoisyNames[name] {
			t.Errorf("Expected %q in dbusNoisyNames suppression map", name)
		}
	}
}

// TestDBusHighValueNameCoverage: all expected high-value names must be present
// with non-empty exploit hints and descriptions.
func TestDBusHighValueNameCoverage(t *testing.T) {
	required := []string{
		"org.freedesktop.PackageKit",
		"org.freedesktop.Accounts",
		"com.ubuntu.USBCreator",
		"org.freedesktop.NetworkManager",
		"org.freedesktop.hostname1",
		"org.freedesktop.login1",
	}
	for _, name := range required {
		hv, ok := dbusHighValue[name]
		if !ok {
			t.Errorf("Expected %q in dbusHighValue map, not found", name)
			continue
		}
		if hv.exploitHint == "" {
			t.Errorf("Expected non-empty exploitHint for %q", name)
		}
		if hv.description == "" {
			t.Errorf("Expected non-empty description for %q", name)
		}
	}
}

// TestDBusServiceRunningNilSnapshot: must safely return false when snapshot is nil.
func TestDBusServiceRunningNilSnapshot(t *testing.T) {
	if isDBusServiceRunning(nil, "org.freedesktop.PackageKit") {
		t.Errorf("Expected false when snapshot is nil, got true")
	}
}

// TestDBusRuleSummaryContainsKeyAttributes: rule summaries must contain the
// attribute names parsed from the XML.
func TestDBusRuleSummaryContainsKeyAttributes(t *testing.T) {
	const conf = `<?xml version="1.0" encoding="UTF-8"?>
<busconfig>
  <policy context="default">
    <allow send_destination="org.freedesktop.NetworkManager"/>
  </policy>
</busconfig>`
	rules, _, _ := parseDBusAllowRules_fromContent(conf)
	if len(rules) == 0 {
		t.Fatal("Expected at least one rule summary")
	}
	found := false
	for _, r := range rules {
		if containsStr(r, "send_destination") && containsStr(r, "NetworkManager") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected rule summary to mention send_destination and NetworkManager, got: %v", rules)
	}
}

// ── HELPERS ──────────────────────────────────────────────────────────────────

// parseDBusAllowRules_fromContent writes content to a temp file and calls
// parseDBusAllowRules, avoiding direct exposure of content-based parsing.
func parseDBusAllowRules_fromContent(content string) ([]string, bool, bool) {
	f, err := os.CreateTemp("", "dbus-test-*.conf")
	if err != nil {
		return nil, false, false
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		return nil, false, false
	}
	f.Close()
	return parseDBusAllowRules(f.Name())
}

func containsStr(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
