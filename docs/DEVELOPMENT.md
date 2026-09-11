# Talaria Developer & Contributor Handbook

This guide provides technical instructions for setting up a local development environment, compiling binaries, executing test suites with race detection, profiling performance, and debugging Talaria.

---

## 1. Prerequisites & Environment Setup

Talaria is built exclusively with canonical Go standard library primitives (zero third-party packages).

### Required Tooling
- **Go:** `1.21+` (Recommended: Go 1.22 or 1.23)
- **Make:** Standard GNU Make
- **Git:** 2.30+

### Verification
Ensure your Go environment is functional:
```bash
go version
# Expected: go version go1.21+ linux/amd64 (or arm64)
```

---

## 2. Building Talaria

The `Makefile` defines convenient compilation targets:

### Standard Build (Dynamically Linked)
```bash
make build
# Output: ./talaria
```

### Static Production Build (CGO Disabled)
For zero-dependency deployment on target hosts:
```bash
make build-static
# Output: ./talaria (statically linked, stripped symbols, CGO_ENABLED=0)
```

### Cross-Compilation (Multi-Architecture)
Compiles standalone binaries for `linux/amd64`, `linux/arm64`, and `linux/386` with cryptographic SHA-256 checksums:
```bash
make cross-compile
# Output: dist/talaria_linux_amd64, dist/talaria_linux_arm64, dist/talaria_linux_386, dist/checksums.sha256
```

---

## 3. Executing & Testing Locally

### Running Local Scans
```bash
# Run all modules with default terminal report
./talaria --scan all

# Run specific scanners
./talaria --scan suid,sudo,cron

# Run with compliance credential masking
./talaria --scan all -p

# Export to JSON
./talaria --scan all -o scan.json --format json
```

---

## 4. Testing & Quality Assurance

Talaria maintains a strict quality bar. Untested code or race conditions will fail CI checks.

### Running Unit Tests
```bash
# Standard test run
make test

# Mandatory race condition verification
make test-race
```

### Generating Coverage Reports
```bash
make test-coverage
# Generates coverage.out and displays percentage summary
# To inspect visually in your browser:
go tool cover -html=coverage.out
```

### Writing Dual Tests for New Scanners
Every scanner must include at least two test cases in `scanners/<name>_test.go`:

1. **Positive Vulnerability Test:** Must simulate the misconfiguration using `t.TempDir()` and verify that the scanner detects it with the correct risk score.
2. **Negative Boundary Test:** Must verify that a clean/hardened system returns **0 findings** (zero false positives).

#### Example Test Pattern:
```go
func TestScanMyModule_Positive(t *testing.T) {
    tmpDir := t.TempDir()
    vulnConfig := filepath.Join(tmpDir, "service.conf")
    os.WriteFile(vulnConfig, []byte("insecure_directive = true\n"), 0644)

    // Call scanner pointing to tmpDir...
    // Assert finding is detected with CRITICAL or HIGH risk.
}

func TestScanMyModule_Negative(t *testing.T) {
    tmpDir := t.TempDir()
    safeConfig := filepath.Join(tmpDir, "service.conf")
    os.WriteFile(safeConfig, []byte("insecure_directive = false\n"), 0644)

    // Call scanner pointing to tmpDir...
    // Assert len(findings) == 0.
}
```

---

## 5. Performance Benchmarking & Profiling

Talaria audits must run in sub-second timeframes.

### Running Benchmarks
```bash
go test -bench=. -benchmem ./scanners/...
```

### CPU & Memory Profiling
To identify memory allocations or CPU bottlenecks:
```bash
# CPU Profile
go test -bench=BenchmarkMyScanner -cpuprofile=cpu.pprof ./scanners
go tool pprof -top cpu.pprof

# Memory Profile
go test -bench=BenchmarkMyScanner -memprofile=mem.pprof ./scanners
go tool pprof -alloc_space mem.pprof
```

### Performance Rules
1. **Pre-compile Regex:** Always use package-level `regexp.MustCompile()`. Never compile regex inside loops or request paths.
2. **Streaming I/O:** Always parse large files with `bufio.Scanner`, never `os.ReadFile()` on unbounded files.
3. **Pre-allocate Slices:** Use `make([]T, 0, capacity)` whenever the upper bound is known.

---

## 6. Code Style & Pre-Commit Verification

Before submitting code, run the full verification pipeline:
```bash
make verify
```

This target runs:
1. `make fmt` (`gofmt -s`)
2. `make vet` (`go vet ./...`)
3. `make test-race` (`go test -count=1 -race ./...`)

### Architectural Constraints
- **0 Third-Party Dependencies:** Only Go standard library.
- **Max 80 Lines per Function:** Refactor longer functions into small, modular helpers.
- **Zero Disk Mutation:** Read files only (`O_RDONLY`). Never create or modify files on the target machine.
- **Context Caching:** Always pass and reuse the cached `*UserContext` (`GetUserContext()`).
