---
name: Scanner Proposal
about: Propose a new privilege escalation scanner module or detection vector
title: '[PROPOSAL] New Scanner: '
labels: enhancement, scanner
assignees: ''

---

## Scanner Overview
- **Proposed Module Name:** `scanners/<name>.go`
- **Audit Target / Domain:** (e.g. `/etc/pam.d/`, Polkit rules, environment variables)
- **MITRE ATT&CK Technique:** (e.g. T1548.003, T1053.002)

## Privilege Escalation Mechanism
Explain how an unprivileged attacker can leverage this misconfiguration to elevate privileges or execute code as root or another service user.

## Detection Strategy (Zero Mutation & High Speed)
- What files, sockets, or procfs paths need to be inspected?
- Can this be checked in `<5ms` without full filesystem recursion?
- How will false positives be filtered out?

## Proof of Concept / Minimal Trigger Environment
Provide sample commands or configurations demonstrating the vulnerable condition vs. safe baseline.

## Implementation Checklist
- [ ] Conforms to pure Go standard library (0 third-party dependencies)
- [ ] Standard signature: `Scan<Name>(ctx context.Context, uctx *UserContext) (*models.ScanResult, error)`
- [ ] Function lengths <= 80 lines
- [ ] Uses `O_RDONLY` and zero disk mutation
- [ ] Includes both positive trigger and negative boundary unit tests
