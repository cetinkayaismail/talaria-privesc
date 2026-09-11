## Summary of Changes
Provide a clear, concise overview of what this PR introduces, why it is needed, and any architectural decisions made.

Fixes #(issue)

## Type of Change
- [ ] 🎯 New Scanner / Attack Chain (adds new privilege escalation detection vector)
- [ ] 📉 False Positive Reduction / Bugfix (improves precision of existing scanner)
- [ ] ⚡ Performance Optimization (reduces execution time or memory allocations)
- [ ] 🛡️ Security / Safety Hardening (hardens file descriptor or subprocess handling)
- [ ] 📝 Documentation Update (enhances guides, references, or specifications)
- [ ] 🔧 Refactor / Tooling (improves code structure without functional changes)

## Engineering Standards Checklist
Please confirm your changes adhere to Talaria's core architectural standards:
- [ ] **Zero External Dependencies:** Built 100% with canonical Go standard library (no `go.mod` additions).
- [ ] **Function Modularity:** No function exceeds 80 lines of code.
- [ ] **Zero State Mutation:** Only reads files (`O_RDONLY`), creates no temporary files, leaves zero disk footprint.
- [ ] **Safe Subprocesses:** Any command execution is allowlisted, timeout-bounded (`exec.CommandContext`), and non-interactive.
- [ ] **Context Caching:** Reuses `GetUserContext()` instead of issuing redundant syscalls.
- [ ] **Streaming & Regex Performance:** Regexes pre-compiled at package level; file reads use buffered/streaming I/O.
- [ ] **Dual-Testing Enforced:** Includes both positive vulnerability trigger test AND negative boundary test for zero false positives.
- [ ] **Race Detector Clean:** Verified with `make verify` or `go test -count=1 -race ./...`.
- [ ] **Code Formatting & Vet:** Passes `gofmt -s` and `go vet ./...`.
