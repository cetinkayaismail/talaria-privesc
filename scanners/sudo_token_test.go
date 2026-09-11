package scanners

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanSudoTokensAndTTY(t *testing.T) {
	InitUserContext()

	results, err := ScanSudoTokensAndTTY()
	if err != nil {
		t.Fatalf("ScanSudoTokensAndTTY returned error: %v", err)
	}

	// Should return a valid slice without panics
	for _, r := range results {
		if r.Vector == "" {
			t.Errorf("Expected non-empty Vector name, got empty string")
		}
		if r.RiskLevel == "" {
			t.Errorf("Expected non-empty RiskLevel for vector %s", r.Vector)
		}
		if r.Reason == "" {
			t.Errorf("Expected non-empty Reason for vector %s", r.Vector)
		}
	}
}

func TestAuditTimestampTickets_Mock(t *testing.T) {
	runnerUID := os.Getuid()
	runnerGID := os.Getgid()

	// Mock context representing a DIFFERENT user (peer) on the system
	peerUserCtx := &UserContext{
		UID:      runnerUID + 10000,
		GID:      runnerGID + 10000,
		Username: "peer_tester",
		GIDs:     map[int]bool{runnerGID + 10000: true},
	}

	// 1. Positive Trigger Test:
	// A ticket owned by the runner (UID != peerUserCtx.UID) is world-writable (0666).
	// peerUserCtx MUST flag it as a dangerous writable peer sudo ticket.
	posDir := t.TempDir()
	vulnTicket := filepath.Join(posDir, "runner_ticket")
	if err := os.WriteFile(vulnTicket, []byte("ticket_data"), 0666); err != nil {
		t.Fatalf("failed to write mock vulnerable ticket: %v", err)
	}
	// Explicitly chmod 0666 to avoid umask stripping write bit
	if err := os.Chmod(vulnTicket, 0666); err != nil {
		t.Fatalf("failed to chmod 0666 mock ticket: %v", err)
	}

	posRes := auditTimestampTickets(posDir, peerUserCtx)
	if len(posRes) == 0 {
		t.Fatalf("expected positive trigger for world-writable peer ticket %s, got 0 findings", vulnTicket)
	}
	foundVuln := false
	for _, r := range posRes {
		if r.Path == vulnTicket {
			foundVuln = true
			if r.Vector != "Writable Peer Sudo Ticket" {
				t.Errorf("expected Vector 'Writable Peer Sudo Ticket', got %q", r.Vector)
			}
			if !r.IsDangerous {
				t.Errorf("expected IsDangerous = true")
			}
			if r.RiskLevel != "CRITICAL" {
				t.Errorf("expected RiskLevel 'CRITICAL', got %q", r.RiskLevel)
			}
		}
	}
	if !foundVuln {
		t.Errorf("expected ticket %s to be flagged in positive test", vulnTicket)
	}

	// 2. Negative Boundary Test — Secure Permission Gating:
	// Ticket owned by runner (UID != peerUserCtx.UID), but mode is 0600 (owner-only).
	// Must NOT be flagged because peerUserCtx has no write access.
	secDir := t.TempDir()
	secureTicket := filepath.Join(secDir, "secure_ticket")
	if err := os.WriteFile(secureTicket, []byte("ticket_data"), 0600); err != nil {
		t.Fatalf("failed to write secure ticket: %v", err)
	}
	secRes := auditTimestampTickets(secDir, peerUserCtx)
	for _, r := range secRes {
		if r.Path == secureTicket {
			t.Errorf("negative boundary failed: secure 0600 ticket was flagged: %v", r)
		}
	}

	// 3. Negative Boundary Test — Self-Owned Ticket Exclusion:
	// Ticket owned by runner and writable (0666), but inspected by runner context itself.
	// Must NOT be flagged as 'Peer' ticket because UID matches runner.
	selfUserCtx := &UserContext{
		UID:      runnerUID,
		GID:      runnerGID,
		Username: "self_tester",
		GIDs:     map[int]bool{runnerGID: true},
	}
	selfRes := auditTimestampTickets(posDir, selfUserCtx)
	for _, r := range selfRes {
		if r.Path == vulnTicket {
			t.Errorf("negative boundary failed: self-owned ticket was flagged as peer ticket: %v", r)
		}
	}

	// 4. Negative Boundary Test — Non-Existent Directory:
	nonExistentRes := auditTimestampTickets(filepath.Join(posDir, "non_existent"), peerUserCtx)
	if len(nonExistentRes) != 0 {
		t.Errorf("expected 0 results for non-existent dir, got %d", len(nonExistentRes))
	}
}
