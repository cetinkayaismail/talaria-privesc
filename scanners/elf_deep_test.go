package scanners

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestIsCleanCommandToken(t *testing.T) {
	valid := []string{"chmod", "chown", "service", "cat", "tar", "python3", "net_tool"}
	for _, tok := range valid {
		if !isCleanCommandToken(tok) {
			t.Errorf("expected '%s' to be a clean command token", tok)
		}
	}

	invalid := []string{"", "chmod:", "cat=", "tar;rm", "/bin/sh", "tool!", "a_very_long_string_that_exceeds_thirty_two_chars_long"}
	for _, tok := range invalid {
		if isCleanCommandToken(tok) {
			t.Errorf("expected '%s' to NOT be a clean command token", tok)
		}
	}
}

func TestExtractPrintableStrings(t *testing.T) {
	raw := []byte("hello\x00world\x00/usr/bin/cat\x00service restart\x00\xff\xfe\x00")
	stringsList := extractPrintableStrings(raw, 2, 64)

	expected := map[string]bool{
		"hello":           true,
		"world":           true,
		"/usr/bin/cat":    true,
		"service restart": true,
	}

	for _, s := range stringsList {
		delete(expected, s)
	}

	if len(expected) > 0 {
		t.Errorf("missing expected strings from extraction: %v", expected)
	}
}

func TestAnalyzeDeepELF_NonELF(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "talaria_non_elf_*")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	tmpFile.WriteString("this is not an ELF binary")
	tmpFile.Close()

	match, err := AnalyzeDeepELF(tmpFile.Name())
	if err == nil && match != nil {
		t.Errorf("expected error or nil match on non-ELF file, got match: %+v", match)
	}
}

func TestAnalyzeDeepELF_WithCompiler(t *testing.T) {
	// Verify if gcc is available for live binary testing
	gccPath, err := exec.LookPath("gcc")
	if err != nil || gccPath == "" {
		t.Skip("gcc not found in PATH, skipping live ELF compiler tests")
	}

	tempDir, err := os.MkdirTemp("", "talaria_elf_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// 1. Positive test: imports system() and calls relative command "service"
	vulnSource := filepath.Join(tempDir, "vuln.c")
	vulnBin := filepath.Join(tempDir, "vuln_bin")
	err = os.WriteFile(vulnSource, []byte(`
#include <stdlib.h>
int main() {
    system("service apache2 restart");
    return 0;
}
`), 0600)
	if err != nil {
		t.Fatalf("failed to write vuln source: %v", err)
	}

	cmd := exec.Command("gcc", "-o", vulnBin, vulnSource)
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to compile vuln binary: %v", err)
	}

	match, err := AnalyzeDeepELF(vulnBin)
	if err != nil {
		t.Fatalf("AnalyzeDeepELF returned unexpected error: %v", err)
	}
	if match == nil {
		t.Fatalf("expected positive match on relative command execution, got nil")
	}
	if match.Command != "service" {
		t.Errorf("expected detected command 'service', got '%s'", match.Command)
	}

	// 2. Negative test: imports system() but calls ABSOLUTE path "/usr/sbin/service"
	safeSource := filepath.Join(tempDir, "safe_path.c")
	safeBin := filepath.Join(tempDir, "safe_path_bin")
	err = os.WriteFile(safeSource, []byte(`
#include <stdlib.h>
int main() {
    system("/usr/sbin/service apache2 restart");
    return 0;
}
`), 0600)
	if err != nil {
		t.Fatalf("failed to write safe source: %v", err)
	}

	cmd = exec.Command("gcc", "-o", safeBin, safeSource)
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to compile safe binary: %v", err)
	}

	match, err = AnalyzeDeepELF(safeBin)
	if err != nil {
		t.Fatalf("AnalyzeDeepELF returned error on safe binary: %v", err)
	}
	if match != nil {
		t.Errorf("expected no match on absolute path execution, got: %+v", match)
	}

	// 3. Negative test: contains string "service" in printf but NEVER imports execution functions
	noExecSource := filepath.Join(tempDir, "no_exec.c")
	noExecBin := filepath.Join(tempDir, "no_exec_bin")
	err = os.WriteFile(noExecSource, []byte(`
#include <stdio.h>
int main() {
    printf("service status check\n");
    return 0;
}
`), 0600)
	if err != nil {
		t.Fatalf("failed to write no_exec source: %v", err)
	}

	cmd = exec.Command("gcc", "-o", noExecBin, noExecSource)
	if err := cmd.Run(); err != nil {
		t.Fatalf("failed to compile no_exec binary: %v", err)
	}

	match, err = AnalyzeDeepELF(noExecBin)
	if err != nil {
		t.Fatalf("AnalyzeDeepELF returned error on no_exec binary: %v", err)
	}
	if match != nil {
		t.Errorf("expected no match when no execution symbol is imported, got: %+v", match)
	}
}
