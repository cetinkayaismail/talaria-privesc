package core

import (
	"bytes"
	"io"
	"os"
	"strings"
	"talaria/models"
	"talaria/scanners"
	"testing"
)

func captureOutput(f func()) string {
	r, w, _ := os.Pipe()
	oldStdout := os.Stdout
	os.Stdout = w

	f()

	_ = w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String()
}

func TestPrintFindingCTFMode(t *testing.T) {
	Config.Mode = ModeCTF
	Config.NoColor = true
	Config.EnableUI = false

	out := captureOutput(func() {
		PrintFinding("CRITICAL", "SUID Binary", map[string]string{
			"Path":        "/usr/local/bin/backup",
			"Remediation": "chmod u-s /usr/local/bin/backup",
			"Compliance":  "CIS-6.1.13",
		}, "/usr/local/bin/backup -exec /bin/sh \\;")
	})

	// CTF mode MUST show Exploit payload
	if !strings.Contains(out, "Exploit") || !strings.Contains(out, "-exec /bin/sh") {
		t.Errorf("Expected exploit payload in CTF mode, got:\n%s", out)
	}

	// CTF mode MUST suppress Remediation and Compliance noise
	if strings.Contains(out, "Remediation") {
		t.Errorf("Expected Remediation to be suppressed in CTF mode, got:\n%s", out)
	}
	if strings.Contains(out, "CIS-6.1.13") {
		t.Errorf("Expected Compliance tag to be suppressed in CTF mode, got:\n%s", out)
	}
}

func TestPrintFindingAuditMode(t *testing.T) {
	Config.Mode = ModeAudit
	Config.NoColor = true
	Config.EnableUI = false

	out := captureOutput(func() {
		PrintFinding("CRITICAL", "SUID Binary", map[string]string{
			"Path":        "/usr/local/bin/backup",
			"Remediation": "chmod u-s /usr/local/bin/backup",
			"Compliance":  "CIS-6.1.13",
		}, "/usr/local/bin/backup -exec /bin/sh \\;")
	})

	// Audit mode MUST show Compliance tag and Remediation command
	if !strings.Contains(out, "[CIS-6.1.13]") {
		t.Errorf("Expected compliance tag [CIS-6.1.13] in Audit mode, got:\n%s", out)
	}
	if !strings.Contains(out, "Remediation") || !strings.Contains(out, "chmod u-s") {
		t.Errorf("Expected remediation command in Audit mode, got:\n%s", out)
	}

	// Audit mode MUST suppress offensive exploit payloads
	if strings.Contains(out, "Exploit") || strings.Contains(out, "-exec /bin/sh") {
		t.Errorf("Expected Exploit payload to be suppressed in Audit mode, got:\n%s", out)
	}
}

func TestPrintSummaryModes(t *testing.T) {
	report := &models.ScanReport{
		SUID: []scanners.SUIDResult{
			{Path: "/usr/bin/vuln", IsDangerous: true},
		},
	}

	// Test CTF Summary
	Config.Mode = ModeCTF
	Config.NoColor = true
	Config.EnableUI = false
	outCTF := captureOutput(func() {
		PrintSummary(report, "12ms")
	})
	if !strings.Contains(outCTF, "CTF / OFFENSIVE") || !strings.Contains(outCTF, "1 Critical") {
		t.Errorf("Unexpected CTF summary output:\n%s", outCTF)
	}

	// Test Audit Summary
	Config.Mode = ModeAudit
	Config.NoColor = true
	Config.EnableUI = false
	outAudit := captureOutput(func() {
		PrintSummary(report, "12ms")
	})
	if !strings.Contains(outAudit, "ENTERPRISE AUDIT") || !strings.Contains(outAudit, "Non-compliant") {
		t.Errorf("Unexpected Audit summary output:\n%s", outAudit)
	}
}

func TestPrintSummaryComprehensiveCounters(t *testing.T) {
	report := &models.ScanReport{
		PAMResults: []scanners.PAMResult{
			{Path: "/etc/pam.d/su", RiskLevel: "CRITICAL", IsDangerous: true},
		},
		PolkitRules: []scanners.PolkitRuleResult{
			{FilePath: "/etc/polkit-1/rules.d/test.rules", IsDangerous: true},
		},
		Processes: []scanners.ProcessResult{
			{PID: 100, Command: "nc -l 4444", User: "root"},
		},
		PythonHijack: []scanners.PythonHijackResult{
			{Path: "/opt/script.py", RiskLevel: "HIGH", IsDangerous: true},
		},
		Wildcards: []scanners.WildcardResult{
			{Command: "tar *", RiskLevel: "MEDIUM", IsDangerous: true},
		},
	}

	Config.Mode = ModeCTF
	Config.NoColor = true
	Config.EnableUI = false

	out := captureOutput(func() {
		PrintSummary(report, "10ms")
	})

	if !strings.Contains(out, "2 Critical") || !strings.Contains(out, "1 High") || !strings.Contains(out, "1 Medium") {
		t.Errorf("Expected 2 Critical, 1 High, 1 Medium in summary, got:\n%s", out)
	}
}
