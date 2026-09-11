# Contributing to Talaria

First off, thank you for your interest in contributing to **Talaria**! Open-source contributions from security researchers, systems programmers, and DevSecOps engineers make Talaria the most reliable, zero-dependency Linux privilege escalation and auditing engine available.

This guide outlines our architectural invariants, code quality standards, scanner development workflow, and testing mandates.

---

## Table of Contents

1. [Code of Conduct](#code-of-conduct)
2. [Quickstart for Developers](#quickstart-for-developers)
3. [Architecture & Package Topology](#architecture--package-topology)
4. [Core Architectural Invariants](#core-architectural-invariants)
5. [Step-by-Step: Adding a New Scanner](#step-by-step-adding-a-new-scanner)
6. [Attack Graph & Intelligence Integration](#attack-graph--intelligence-integration)
7. [Testing & Quality Assurance Standards](#testing--quality-assurance-standards)
8. [Commit & Pull Request Workflow](#commit--pull-request-workflow)

---

## Code of Conduct

All contributors and maintainers are expected to adhere to our [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). Please treat fellow contributors with respect, empathy, and professional integrity.

---

## Quickstart for Developers

### Prerequisites
- **Go 1.21+** (Canonical toolchain, CGO disabled by default)
- **Make** (for automated targets)
- **Git**

### Setup & Local Verification
```bash
# 1. Clone the repository
git clone https://github.com/cetinkayaismail/talaria-privesc.git
cd talaria

# 2. View all available development targets
make help

# 3. Compile standard or static binary
make build
make build-static

# 4. Run tests with race detection & code verification
make test-race
make vet
make fmt

# 5. Run full pre-commit verification pipeline
make verify
```

---

## Architecture & Package Topology

Talaria enforces strict unidirectional package dependency boundaries to maintain modularity and prevent circular dependencies:

```
                  ┌──────────────┐
                  │   main.go    │
                  └──────┬───────┘
                         │
                  ┌──────▼───────┐
                  │    cmd/      │ (CLI flags, module dispatch, terminal/JSON report)
                  └──────┬───────┘
            ┌────────────┴────────────┐
            ▼                         ▼
     ┌──────────────┐          ┌──────────────┐
     │  scanners/   │          │    core/     │ (Attack graph solver, SARIF, crypto)
     └──────┬───────┘          └──────┬───────┘
            │                         │
            └────────────┬────────────┘
                         ▼
                  ┌──────────────┐
                  │   models/    │ (Shared report data structs, zero logic)
                  └──────────────┘
```

- **`cmd/`**: CLI flag parsing (`cli.go`), worker pool execution dispatch (`dispatch.go`), terminal rendering & JSON serialization (`report.go`).
- **`scanners/`**: 45+ autonomous security scanners auditing specific host domains. Each module exposes a single public entrypoint.
- **`core/`**: Intelligence engine (`intelligence.go`), weighted directed acyclic attack graph (`graph.go`), SARIF output generation (`sarif.go`), report encryption (`crypto.go`), and terminal styling (`terminal.go`).
- **`models/`**: Pure data definitions (`report.go`). **Must contain zero business logic or scanner dependencies.**
- **`internal/walkpool`**: Resource-bounded concurrent filesystem traversal engine respecting `RLIMIT_NOFILE`.

---

## Core Architectural Invariants

Every pull request is reviewed against these non-negotiable engineering standards:

### 1. Pure Standard Library Only (Zero Third-Party Dependencies)
- Talaria has **0 external dependencies** in `go.mod`.
- Never import third-party packages (no Cobra, Viper, Logrus, etc.).
- Use standard library packages: `os`, `io`, `syscall`, `bufio`, `regexp`, `context`, `crypto/aes`, `crypto/cipher`, `encoding/json`.
- *Why:* Keeps binary size minimal (<8MB), guarantees zero supply chain risk, and ensures single-binary execution on any Linux host.

### 2. Function Modularity (Max 80 Lines per Function)
- No function may exceed **80 lines of code** (excluding tests).
- Break complex parsers into small, testable helper functions.
- Keep cognitive complexity low.

### 3. Zero State Mutation & Read-Only Safety
- Talaria must **never mutate target host state**.
- Open all files with `os.O_RDONLY`. Never call `os.Create`, `os.WriteFile`, or `os.Mkdir` on the target host.
- Never write scratch files to `/tmp`, `/dev/shm`, or `/var/tmp`.
- All parsing must occur strictly in-memory.

### 4. Safe Subprocess Execution
- Subprocesses should be avoided whenever possible in favor of native `/proc`, `/sys`, or `/etc` parsing.
- If a system command must be invoked (e.g. `sudo -l -n`):
  - Must use `exec.CommandContext` with a strict deadline timeout (typically 200ms–2s).
  - Must use unprivileged context (never elevate privileges to audit).
  - Must never spawn interactive shells.

### 5. Bounded Concurrency & Traversal Ceilings
- Never use unbound filesystem walks (`filepath.Walk` on `/` is forbidden).
- Filesystem audits must use the internal `walkpool` engine with `ShouldIgnore()` directory pruning to skip `/proc`, `/sys`, `/dev`, Docker mounts, and network filesystems.
- Dynamic concurrency adapts to system `RLIMIT_NOFILE` limits (`--io-limit`).

### 6. High-Performance Primitives
- **Package-level Regex:** Pre-compile all regular expressions (`regexp.MustCompile`) at package level. Never compile regex inside loops or request paths.
- **Streaming I/O:** Parse large files (logs, history, packages) line-by-line using `bufio.Scanner` with size limits, never `os.ReadFile` on unbounded files.
- **Slice Pre-sizing:** Where the upper bound is known or estimable, pre-allocate slices with `make([]T, 0, capacity)` to eliminate reallocation overhead.

### 7. User Context Caching
- Never query user identity or groups repeatedly.
- Pass the shared cached `*UserContext` (`GetUserContext()`) containing pre-resolved UID, GID, username, and secondary group IDs.

### 8. Output Sanitization (CWE-150 Defense)
- Sanitize all strings read from untrusted files before printing to the terminal.
- Strip ANSI escape sequences to prevent terminal injection attacks.

---

## Step-by-Step: Adding a New Scanner

Follow this standardized workflow when adding a new security audit module:

### Step 1: Create Scanner Implementation in `scanners/<name>.go`

```go
package scanners

import (
	"bufio"
	"context"
	"os"
	"talaria/models"
)

// ScanMyFeature audits <target domain> for privilege escalation vectors.
// Performance target: < 5ms execution time, zero filesystem recursion.
func ScanMyFeature(ctx context.Context, uctx *UserContext) (*models.MyFeatureResult, error) {
	if uctx == nil {
		uctx = GetUserContext()
	}

	result := &models.MyFeatureResult{
		Findings: make([]models.MyFeatureFinding, 0, 4),
	}

	targetPath := "/etc/my_service.conf"
	f, err := os.Open(targetPath)
	if err != nil {
		// Target not present or unreadable — gracefully return empty result
		return result, nil
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		line := scanner.Text()
		// Perform inspection logic (modular helper <= 80 lines)...
		_ = line
	}

	return result, scanner.Err()
}
```

### Step 2: Add Data Model in `models/report.go`

Add your finding structs and update `ScanReport`:

```go
type MyFeatureFinding struct {
	Path        string `json:"path"`
	Issue       string `json:"issue"`
	RiskLevel   string `json:"risk_level"`
	Remediation string `json:"remediation,omitempty"`
}

type MyFeatureResult struct {
	Findings []MyFeatureFinding `json:"findings"`
}

// In ScanReport struct:
type ScanReport struct {
	// ... existing fields ...
	MyFeature *MyFeatureResult `json:"my_feature,omitempty"`
}
```

### Step 3: Register in CLI & Dispatch Engine

1. **`cmd/dispatch.go`:** Add the scanner module entry in `BuildModuleRegistry()`, assigning phase, execution closure, and CLI alias.
2. **`cmd/cli.go`:** Add the flag option to help text and validation lists.
3. **`cmd/report.go`:** Add terminal card formatting in `PrintSummary()` and JSON/SARIF serialization hooks.

---

## Attack Graph & Intelligence Integration

Talaria uses an **Intelligence Engine** (`core/intelligence.go`) that links individual findings into multi-stage attack chains (DAG) solving for `goal:root`:

If your scanner identifies a misconfiguration that can chain with another finding (e.g. SUID wrapper + writable subordinate script, or writable config + scheduled service restart):

1. Define an `AttackChain` struct in `core/intelligence.go`:
   ```go
   var MyFeatureChain = AttackChain{
       ID:          "CHAIN-XX",
       Name:        "My Feature Service Hijack -> ROOT PRIVILEGE",
       Confidence:  "100% CONFIRMED",
       Evaluate: func(r *models.ScanReport) []ChainResult {
           // Correlate findings across report modules...
       },
   }
   ```
2. Register the chain in `registeredChains` slice in `core/intelligence.go`.
3. Map node edges in `core/graph.go` for visual directed acyclic graph analysis.

---

## Testing & Quality Assurance Standards

Quality is our highest priority. Untested or partially tested code will not be accepted.

### Mandatory Dual-Testing Requirement
Every scanner **MUST** implement at least two test cases in `scanners/<name>_test.go`:
1. **Positive Vulnerability Trigger Test:** Simulates the vulnerable condition (e.g., world-writable file, dangerous sudoers directive) and asserts that the scanner detects it with the expected risk level and vector details.
2. **Negative Boundary Test (Zero False Positives):** Simulates a hardened or default configuration and asserts that **0 findings** are returned.

### Isolation & Cleanup
- Always use `t.TempDir()` for mock configuration files.
- Never write to real system paths during unit testing.
- Tests must execute in `<50ms` each.

### Running Test Suite
```bash
# Run all tests with standard output
make test

# Run all tests with race detector (MANDATORY before PR submission)
make test-race

# Check test coverage
make test-coverage
```

---

## Commit & Pull Request Workflow

### 1. Pre-Change Metric Report
Before implementing any significant change, ensure your work respects these 5 dimensions:
- **⚡ Speed impact:** Target execution latency (<5ms for single checks).
- **📉 FP rate change:** Precision verification, zero heuristic noise.
- **🏗️ Architecture risk:** Additive vs refactoring impact.
- **🎯 New vectors added:** Concrete LPE or audit capability.
- **🔍 Vectors that could be missed:** Documented boundaries.

### 2. Conventional Commit Messages
We adhere to the [Conventional Commits](https://www.conventionalcommits.org/) specification:
- `feat(scanners): add xinetd service hijack audit module`
- `fix(core): prevent nil pointer dereference in unprivileged proc snapshot`
- `perf(walkpool): optimize directory pruning for containerized overlayfs`
- `docs: update CONTRIBUTING.md with scanner development guide`
- `test(scanners): add positive and negative tests for sudoers dropin`

### 3. Pull Request Submission Checklist
- [ ] Code compiles cleanly (`go build ./...`)
- [ ] All unit tests pass with race detector enabled (`go test -count=1 -race ./...`)
- [ ] Code passes formatting and static analysis (`go fmt ./...` and `go vet ./...`)
- [ ] Zero external dependencies added to `go.mod`
- [ ] No functions exceed 80 lines
- [ ] Both positive and negative unit tests included for new features
- [ ] Updated documentation and references in `docs/`
