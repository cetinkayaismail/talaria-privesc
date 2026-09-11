package scanners

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanGitHooks(t *testing.T) {
	InitUserContext()
	tmpDir := t.TempDir()

	userCtx := GetUserContext()
	origUID := userCtx.UID
	defer func() { userCtx.UID = origUID }()

	// 1. Setup repository owned by current test user
	repoDir := filepath.Join(tmpDir, "myrepo")
	hooksDir := filepath.Join(repoDir, ".git", "hooks")
	if err := os.MkdirAll(hooksDir, 0777); err != nil {
		t.Fatalf("failed to mkdir: %v", err)
	}
	_ = os.Chmod(hooksDir, 0777)

	// Put a sample file and a real hook
	sampleHook := filepath.Join(hooksDir, "pre-commit.sample")
	if err := os.WriteFile(sampleHook, []byte("#!/bin/sh\n"), 0777); err != nil {
		t.Fatalf("failed to write sample: %v", err)
	}
	realHook := filepath.Join(hooksDir, "post-merge")
	if err := os.WriteFile(realHook, []byte("#!/bin/sh\n"), 0777); err != nil {
		t.Fatalf("failed to write hook: %v", err)
	}
	if err := os.Chmod(realHook, 0777); err != nil {
		t.Fatalf("failed to chmod realHook: %v", err)
	}

	// FP: When userCtx.UID matches repo owner, scanner must SKIP (it's user's own repo!)
	results, err := scanGitHooksInternal([]string{tmpDir})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 findings for user's own repository, got: %+v", results)
	}

	// TP: When repo is owned by another user (simulate by setting userCtx.UID = 9999)
	userCtx.UID = 9999
	results, err = scanGitHooksInternal([]string{tmpDir})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	foundHook := false
	for _, r := range results {
		if r.HookPath == sampleHook {
			t.Errorf(".sample hook files must never be flagged, but got: %s", r.HookPath)
		}
		if r.HookName == "post-merge" {
			foundHook = true
			if r.RiskLevel != "CRITICAL" {
				t.Errorf("expected CRITICAL for post-merge hook, got: %s", r.RiskLevel)
			}
		}
	}
	if !foundHook {
		t.Errorf("expected finding for writable post-merge hook in cross-privilege repo, got none")
	}
}
