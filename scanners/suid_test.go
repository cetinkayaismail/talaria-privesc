package scanners

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

type mockFileInfo struct {
	name    string
	mode    os.FileMode
	sysStat *syscall.Stat_t
}

func (m mockFileInfo) Name() string       { return m.name }
func (m mockFileInfo) Size() int64        { return 1024 }
func (m mockFileInfo) Mode() os.FileMode  { return m.mode }
func (m mockFileInfo) ModTime() time.Time { return time.Time{} }
func (m mockFileInfo) IsDir() bool        { return false }
func (m mockFileInfo) Sys() any           { return m.sysStat }

func TestEvaluateSUIDBinary_SystemStandardFilter(t *testing.T) {
	// Standard system binaries like /usr/bin/passwd or /usr/bin/sudo must be ignored to prevent false positives
	for _, bin := range []string{"passwd", "sudo", "su", "mount", "umount", "pkexec"} {
		info := mockFileInfo{
			name: bin,
			mode: os.ModeSetuid | 0755,
			sysStat: &syscall.Stat_t{
				Uid: 0,
				Gid: 0,
			},
		}
		res, ok := evaluateSUIDBinary("/usr/bin/"+bin, info, true)
		if ok {
			t.Errorf("expected standard system SUID binary '%s' to be filtered out, got result: %+v", bin, res)
		}
	}
}

func TestEvaluateSUIDBinary_GTFOBinsTrigger(t *testing.T) {
	// GTFOBins binaries with SUID capability (e.g. bash, find, vim) must be flagged as dangerous
	info := mockFileInfo{
		name: "bash",
		mode: os.ModeSetuid | 0755,
		sysStat: &syscall.Stat_t{
			Uid: 0,
			Gid: 0,
		},
	}
	res, ok := evaluateSUIDBinary("/usr/bin/bash", info, false)
	if !ok {
		t.Fatalf("expected evaluateSUIDBinary to return ok=true for /usr/bin/bash")
	}
	if !res.IsDangerous {
		t.Errorf("expected SUID bash to be flagged as dangerous")
	}
	if res.Remediation == "" {
		t.Errorf("expected remediation recommendation for dangerous SUID binary")
	}
}

func TestEvaluateSUIDBinary_DeepELFIntegration(t *testing.T) {
	gccPath, err := exec.LookPath("gcc")
	if err != nil || gccPath == "" {
		t.Skip("gcc not found in PATH, skipping live Deep ELF SUID integration test")
	}

	tempDir := t.TempDir()
	vulnSource := filepath.Join(tempDir, "custom_service.c")
	vulnBin := filepath.Join(tempDir, "custom_service")

	src := "#include <stdlib.h>\nint main() { system(\"service apache2 restart\"); return 0; }\n"
	if err := os.WriteFile(vulnSource, []byte(src), 0600); err != nil {
		t.Fatalf("failed to write source: %v", err)
	}

	cmd := exec.Command("gcc", "-o", vulnBin, vulnSource)
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to compile: %v", err)
	}

	info := mockFileInfo{
		name: "custom_service",
		mode: os.ModeSetuid | 0755,
		sysStat: &syscall.Stat_t{
			Uid: 0,
			Gid: 0,
		},
	}

	// 1. Positive trigger: runDeepELF = true -> flags relative service call
	resPositive, ok := evaluateSUIDBinary(vulnBin, info, true)
	if !ok || !resPositive.IsDangerous {
		t.Errorf("expected custom root SUID binary calling relative command to be flagged as dangerous in CTF mode")
	}

	// 2. Negative boundary: runDeepELF = false (Audit mode) -> suppresses heuristic flagging
	resNegative, ok := evaluateSUIDBinary(vulnBin, info, false)
	if !ok || resNegative.IsDangerous {
		t.Errorf("expected custom SUID binary to NOT be flagged when runDeepELF is false (Audit mode)")
	}
}

func TestScanSUID_CleanDirectory(t *testing.T) {
	tempDir := t.TempDir()
	results, err := ScanSUID(tempDir, true)
	if err != nil {
		t.Fatalf("unexpected error scanning empty dir: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 SUID findings on clean temp directory, got %d", len(results))
	}
}

func TestScanSGID_CleanDirectory(t *testing.T) {
	tempDir := t.TempDir()
	results, err := ScanSGID(tempDir)
	if err != nil {
		t.Fatalf("unexpected error scanning empty dir: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 SGID findings on clean temp directory, got %d", len(results))
	}
}
