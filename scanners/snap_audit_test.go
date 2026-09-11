package scanners

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanSnapAudit(t *testing.T) {
	tmpDir := t.TempDir()

	mockConfine := filepath.Join(tmpDir, "snap-confine")
	if err := os.WriteFile(mockConfine, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatalf("failed to write mock confine: %v", err)
	}

	// 1. TP: Vulnerable version 2.54.2 with checkSUID=false (testing version comparison)
	results, err := scanSnapAuditInternal([]string{mockConfine}, "2.54.2", "", filepath.Join(tmpDir, "snap"), false)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	found := false
	for _, r := range results {
		if r.CVE == "CVE-2021-44731" {
			found = true
			if r.RiskLevel != "CRITICAL" {
				t.Errorf("expected CRITICAL, got: %s", r.RiskLevel)
			}
		}
	}
	if !found {
		t.Errorf("expected CVE-2021-44731 finding for snapd 2.54.2, got none")
	}

	// 2. FP: Patched version 2.58.0
	results, err = scanSnapAuditInternal([]string{mockConfine}, "2.58.0", "", filepath.Join(tmpDir, "snap"), false)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 findings for patched snapd 2.58.0, got: %+v", results)
	}

	// 3. FP: SUID bit check enforced and mockConfine lacks SUID bit
	results, err = scanSnapAuditInternal([]string{mockConfine}, "2.54.2", "", filepath.Join(tmpDir, "snap"), true)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 findings when checkSUID=true and file lacks SUID bit, got: %+v", results)
	}

	// 4. TP: Devmode snap package
	snapDir := filepath.Join(tmpDir, "snap")
	metaDir := filepath.Join(snapDir, "testapp", "current", "meta")
	if err := os.MkdirAll(metaDir, 0755); err != nil {
		t.Fatalf("failed to mkdir: %v", err)
	}
	snapYaml := filepath.Join(metaDir, "snap.yaml")
	if err := os.WriteFile(snapYaml, []byte("name: testapp\nversion: 1.0\nconfinement: devmode\n"), 0644); err != nil {
		t.Fatalf("failed to write snap.yaml: %v", err)
	}

	results, err = scanSnapAuditInternal([]string{}, "", "", snapDir, false)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	foundDevmode := false
	for _, r := range results {
		if r.Binary == "testapp" && r.RiskLevel == "MEDIUM" {
			foundDevmode = true
		}
	}
	if !foundDevmode {
		t.Errorf("expected devmode finding for testapp, got none")
	}
}
