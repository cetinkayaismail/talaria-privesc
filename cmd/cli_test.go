package cmd

import (
	"testing"
)

func TestParseFlagsValid(t *testing.T) {
	cfg, err := ParseFlags([]string{"--scan", "cronjobs,sudo", "--fail-on", "CRITICAL", "--quiet"})
	if err != nil {
		t.Fatalf("ParseFlags failed: %v", err)
	}

	if cfg.ScanModules != "cronjobs,sudo" {
		t.Errorf("Expected ScanModules 'cronjobs,sudo', got %q", cfg.ScanModules)
	}
	if cfg.FailOn != "CRITICAL" {
		t.Errorf("Expected FailOn 'CRITICAL', got %q", cfg.FailOn)
	}
	if !cfg.QuietMode {
		t.Errorf("Expected QuietMode to be true")
	}
}

func TestParseFlagsFailOnCaseInsensitive(t *testing.T) {
	cfg, err := ParseFlags([]string{"--fail-on", "high"})
	if err != nil {
		t.Fatalf("ParseFlags failed: %v", err)
	}
	if cfg.FailOn != "HIGH" {
		t.Errorf("Expected FailOn normalized to 'HIGH', got %q", cfg.FailOn)
	}
}

func TestParseFlagsInvalidFailOn(t *testing.T) {
	_, err := ParseFlags([]string{"--fail-on", "INVALID"})
	if err == nil {
		t.Fatal("Expected error for invalid --fail-on value, got nil")
	}
}

func TestParseFlagsCtfAndAuditConflict(t *testing.T) {
	_, err := ParseFlags([]string{"--ctf", "--audit"})
	if err == nil {
		t.Fatal("Expected error when both --ctf and --audit are provided, got nil")
	}
}

func TestParseFlagsEncryptWithoutOutput(t *testing.T) {
	_, err := ParseFlags([]string{"--encrypt", "secretpass"})
	if err == nil {
		t.Fatal("Expected error when --encrypt is provided without -o, got nil")
	}
}

func TestParseFlagsEncryptWithOutput(t *testing.T) {
	cfg, err := ParseFlags([]string{"--encrypt", "secretpass", "-o", "/tmp/report.json"})
	if err != nil {
		t.Fatalf("Unexpected error for --encrypt with -o: %v", err)
	}
	if cfg.EncryptKey != "secretpass" || cfg.OutputFile != "/tmp/report.json" {
		t.Errorf("Expected EncryptKey 'secretpass' and OutputFile '/tmp/report.json', got %q and %q", cfg.EncryptKey, cfg.OutputFile)
	}
}

func TestParseFlagsFormatSarif(t *testing.T) {
	cfg, err := ParseFlags([]string{"--format", "sarif"})
	if err != nil {
		t.Fatalf("Unexpected error for --format sarif: %v", err)
	}
	if cfg.OutputFormat != "sarif" {
		t.Errorf("Expected OutputFormat 'sarif', got %q", cfg.OutputFormat)
	}
}

func TestParseFlagsInvalidFormat(t *testing.T) {
	_, err := ParseFlags([]string{"--format", "yaml"})
	if err == nil {
		t.Fatal("Expected error for invalid --format value 'yaml', got nil")
	}
}

func TestParseFlagsDeepELFResolution(t *testing.T) {
	// 1. Default (CTF mode) should auto-enable DeepELF
	cfgDefault, err := ParseFlags([]string{})
	if err != nil {
		t.Fatalf("unexpected error on default flags: %v", err)
	}
	if !cfgDefault.DeepELF {
		t.Errorf("expected DeepELF to be true by default in CTF mode")
	}

	// 2. Audit mode (--audit) should auto-disable DeepELF
	cfgAudit, err := ParseFlags([]string{"--audit"})
	if err != nil {
		t.Fatalf("unexpected error on --audit: %v", err)
	}
	if cfgAudit.DeepELF {
		t.Errorf("expected DeepELF to be false by default in Audit mode")
	}

	// 3. Shorthand audit (-p) should also auto-disable DeepELF
	cfgP, err := ParseFlags([]string{"-p"})
	if err != nil {
		t.Fatalf("unexpected error on -p: %v", err)
	}
	if cfgP.DeepELF {
		t.Errorf("expected DeepELF to be false by default in -p mode")
	}

	// 4. Audit mode with explicit --deep-elf should enable DeepELF
	cfgAuditExplicit, err := ParseFlags([]string{"--audit", "--deep-elf"})
	if err != nil {
		t.Fatalf("unexpected error on --audit --deep-elf: %v", err)
	}
	if !cfgAuditExplicit.DeepELF {
		t.Errorf("expected DeepELF to be true when explicitly passed with --audit")
	}

	// 5. Explicit --deep-elf=false in CTF mode should disable DeepELF
	cfgCTFDisabled, err := ParseFlags([]string{"--deep-elf=false"})
	if err != nil {
		t.Fatalf("unexpected error on --deep-elf=false: %v", err)
	}
	if cfgCTFDisabled.DeepELF {
		t.Errorf("expected DeepELF to be false when explicitly passed as false")
	}
}

