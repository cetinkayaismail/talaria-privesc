package scanners

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseProcNetPorts(t *testing.T) {
	// Positive test: mock procfs tcp fixture with listening ports 3306 (0CEA) and 6379 (18EB) in state 0A
	// and established connection on port 8080 (1F90) in state 01
	procNetData := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 7F000001:18EB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12346 1 0000000000000000 100 0 0 10 0
   2: 7F000001:1F90 7F000001:9999 01 00000000:00000000 00:00000000 00000000     0        0 12347 1 0000000000000000 100 0 0 10 0
`
	tmpDir := t.TempDir()
	mockProcNet := filepath.Join(tmpDir, "tcp")
	if err := os.WriteFile(mockProcNet, []byte(procNetData), 0600); err != nil {
		t.Fatalf("failed to write mock proc net fixture: %v", err)
	}

	ports := make(map[int]bool)
	parseProcNetPorts(mockProcNet, ports)

	// Positive assertions
	if !ports[3306] {
		t.Errorf("expected port 3306 to be recognized as listening, got false")
	}
	if !ports[6379] {
		t.Errorf("expected port 6379 to be recognized as listening, got false")
	}

	// Negative boundary assertion: port 8080 is in state 01 (ESTABLISHED), must NOT be marked listening
	if ports[8080] {
		t.Errorf("port 8080 is in state 01 (ESTABLISHED); expected not listening, got true")
	}

	// Negative boundary test: empty or non-existent file produces 0 ports without panic
	emptyPorts := make(map[int]bool)
	parseProcNetPorts(filepath.Join(tmpDir, "non_existent"), emptyPorts)
	if len(emptyPorts) != 0 {
		t.Errorf("expected 0 ports for non-existent file, got %d", len(emptyPorts))
	}
}

func TestScanLocalServices(t *testing.T) {
	// Baseline smoke test: verifies execution does not panic or hang
	results, err := ScanLocalServices()
	if err != nil {
		t.Fatalf("ScanLocalServices returned unexpected error: %v", err)
	}

	// Results must be a valid slice (can be empty if no services listening)
	for _, res := range results {
		if res.ServiceName == "" {
			t.Errorf("found ServiceAuditResult with empty ServiceName")
		}
		if res.Port <= 0 {
			t.Errorf("found ServiceAuditResult with invalid port: %d", res.Port)
		}
	}
}

func TestAuditServicesWithPorts(t *testing.T) {
	// Positive trigger test: port 11211 triggers Memcached dangerous finding
	mockPorts := map[int]bool{
		11211: true,
	}
	results := auditServicesWithPorts(mockPorts)
	if len(results) == 0 {
		t.Fatalf("expected finding for port 11211 (Memcached), got 0")
	}
	foundMemcached := false
	for _, res := range results {
		if res.ServiceName == "Memcached" && res.Port == 11211 && res.IsDangerous {
			foundMemcached = true
			if res.ExploitHint == "" {
				t.Errorf("expected non-empty ExploitHint for Memcached finding")
			}
		}
	}
	if !foundMemcached {
		t.Errorf("expected Memcached finding in audit results")
	}

	// Negative boundary test: non-target port 8080 produces zero findings
	safePorts := map[int]bool{
		8080: true,
	}
	safeResults := auditServicesWithPorts(safePorts)
	if len(safeResults) != 0 {
		t.Errorf("expected 0 findings for safe port 8080, got %d", len(safeResults))
	}
}
