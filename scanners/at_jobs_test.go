package scanners

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanAtJobs(t *testing.T) {
	InitUserContext()
	tmpDir := t.TempDir()

	spoolDir := filepath.Join(tmpDir, "atjobs")
	if err := os.Mkdir(spoolDir, 0755); err != nil {
		t.Fatalf("failed to mkdir: %v", err)
	}

	atAllow := filepath.Join(tmpDir, "at.allow")
	atDeny := filepath.Join(tmpDir, "at.deny")

	// 1. FP: atd is NOT active -> must return 0 findings immediately
	res, err := scanAtJobsInternal(false, []string{spoolDir}, atAllow, atDeny)
	if err != nil || len(res) != 0 {
		t.Fatalf("expected 0 findings when atd is inactive, got %d, err: %v", len(res), err)
	}

	// 2. TP: atd is active and spool directory is writable by user
	res, err = scanAtJobsInternal(true, []string{spoolDir}, atAllow, atDeny)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	foundSpool := false
	for _, r := range res {
		if r.Path == spoolDir {
			foundSpool = true
			if r.RiskLevel != "CRITICAL" {
				t.Errorf("expected CRITICAL for writable spool dir, got: %s", r.RiskLevel)
			}
		}
	}
	if !foundSpool {
		t.Errorf("expected finding for writable spool directory, got none")
	}

	// 3. TP: Writable job file in spool
	jobFile := filepath.Join(spoolDir, "a0000101a01")
	if err := os.WriteFile(jobFile, []byte("#!/bin/sh\n"), 0666); err != nil {
		t.Fatalf("failed to write job file: %v", err)
	}
	if err := os.Chmod(jobFile, 0666); err != nil {
		t.Fatalf("failed to chmod job file: %v", err)
	}

	userCtx := GetUserContext()
	origUID := userCtx.UID
	origThresh := atJobPrivilegedThreshold
	atJobPrivilegedThreshold = origUID + 1000
	userCtx.UID = 9999
	defer func() {
		userCtx.UID = origUID
		atJobPrivilegedThreshold = origThresh
	}()

	res, err = scanAtJobsInternal(true, []string{spoolDir}, atAllow, atDeny)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	foundJob := false
	for _, r := range res {
		if r.Path == jobFile {
			foundJob = true
			if r.RiskLevel != "CRITICAL" {
				t.Errorf("expected CRITICAL for writable job file, got: %s", r.RiskLevel)
			}
		}
	}
	if !foundJob {
		t.Errorf("expected finding for writable job file %s, got none", jobFile)
	}
}
