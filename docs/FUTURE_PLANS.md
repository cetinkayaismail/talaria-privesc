# Talaria — Strategic Roadmap & Future Plans

This document establishes the official master **Strategic Roadmap & Future Plans** for the **Talaria** Linux Privilege Escalation Engine. It details completed milestones, prioritized upcoming capabilities, architectural upgrades, and engineering specifications.

---

## 🧭 Executive Summary & Core Tenets

Talaria has evolved from an unprivileged scanner into a high-speed, dual-engine Linux security platform combining:
1. **Offensive CTF / Penetration Testing Engine (`--ctf` / Default):** Sub-second root pathfinding, GTFOBins exploit synthesis, and cleartext credential extraction.
2. **Enterprise Audit & Compliance Engine (`--audit` / `-p`):** CIS Linux Benchmarks, NIST SP 800-53 controls, deterministic bash remediation commands, and SARIF export for CI/CD pipelines.

### Immutable Architecture Principles
Every future capability must strictly adhere to Talaria's core tenets:
- **Zero Third-Party Dependencies:** 100% standard library Go (`net`, `os`, `syscall`, `debug/elf`, `encoding/json`).
- **Zero Host Mutation:** Pure read-only operation (`O_RDONLY` file descriptors, zero disk writes to `/tmp`).
- **Sub-Second Latency:** Full-system evaluation in `<15ms–800ms` on standard multi-core hosts.
- **Function Modularity:** Strict function length limit of `<= 80 lines` per function.
- **Mandatory Dual-Testing:** Every scanner must provide positive vulnerability triggers and negative boundary unit tests.

---

## 📊 Completed Milestones Overview (v2.0 – v2.2)

The following foundational milestones have been fully implemented, verified in Docker test laboratories, and integrated into the primary codebase:

| Milestone | Feature / Architecture Upgrade | Scope & Impact | Status |
|:---|:---|:---|:---:|
| **PHASE-1** | **Stealth Deprecation & Core Clean-up** | Removed noisy pseudo-stealth delays; centralized AES-256-GCM encryption in `core/crypto.go`. | ✅ DONE |
| **PHASE-2** | **Universal Remediation & Standards** | Integrated CIS Benchmark and NIST tags across all 45+ scanners; deterministic fix commands. | ✅ DONE |
| **PHASE-3** | **Dual-Engine Presentation Layer** | Built high-contrast `--ctf` offensive output and corporate `--audit` compliance dashboard. | ✅ DONE |
| **PHASE-4** | **CI/CD Gating & Policy Enforcement** | Added `--fail-on=CRITICAL\|HIGH\|MEDIUM` pipeline exit codes and quiet machine modes. | ✅ DONE |
| **PHASE-5** | **Enterprise Export Formats (SARIF v2.1.0)** | Implemented native GitHub Code Scanning SARIF exporter and Draft 2020-12 JSON schema. | ✅ DONE |
| **OPT-01..05** | **Architecture Decomposition & Walkpool** | Monolith decomposed into `cmd/`, table-driven dispatch, unified `/proc` snapshot, worker pool. | ✅ DONE |
| **VEC-01..08** | **8 High-Priority Privilege Vectors** | Sudoers.d drop-ins, shell RC poisoning, at jobs, fstab user mounts, snap helpers, git hooks. | ✅ DONE |
| **CHAIN-50** | **50 Autonomous Attack Chains** | SubUID/Sysctl chaining, password reuse heuristics, wildcard injection, token extraction. | ✅ DONE |

---

## 🗺️ Master Future Roadmap (v2.3 – v3.0)

```
┌───────────────────────────────────────────────────────────────────────────────────┐
│                           TALARIA FUTURE ROADMAP                                  │
├──────────────┬──────────────────────────────────────────┬─────────────────────────┤
│ Milestone    │ Focus Area                               │ Target Deliverables     │
├──────────────┼──────────────────────────────────────────┼─────────────────────────┤
│ Release v2.3 │ Deep Inspection & Capability Expansion   │ • Deep ELF Analysis     │
│              │                                          │ • D-Bus Policy Auditor  │
│              │                                          │ • Linux Capabilities v2 │
│              │                                          │ • Mail/Log Secret Hunt  │
├──────────────┼──────────────────────────────────────────┼─────────────────────────┤
│ Release v2.4 │ Container Breakout & Kernel Diagnostics  │ • Cgroup Escape Vectors │
│              │                                          │ • eBPF Audit & Tracing  │
│              │                                          │ • Distro Patch Tracker  │
│              │                                          │ • WSL Interop Auditor   │
├──────────────┼──────────────────────────────────────────┼─────────────────────────┤
│ Release v2.5 │ Multi-Goal Graph & Probabilistic Engine  │ • Multi-Goal Dijkstra   │
│              │                                          │ • Probabilistic Scoring │
│              │                                          │ • Attack Graph Live SVG │
├──────────────┼──────────────────────────────────────────┼─────────────────────────┤
│ Release v2.6 │ Enterprise Automation & DevSecOps Suite  │ • Baseline Delta Audits │
│              │                                          │ • Auto-Remediation Gen  │
│              │                                          │ • SIEM Webhook Dispatch │
│              │                                          │ • Interactive TUI Mode  │
└──────────────┴──────────────────────────────────────────┴─────────────────────────┘
```

---

## 🔬 Detailed Technical Specifications for Upcoming Features

### Milestone v2.3: Deep Inspection & Capability Expansion

#### 1. B2 — Deep ELF String & Disassembly Analysis (`--deep-elf`)
- **Objective:** Detect custom in-house root SUID/SGID binaries (common in CTFs, proprietary server appliances, and internal pentests) that call external binaries via relative paths (`system("service status")` instead of `/usr/sbin/service`).
- **Technical Design:**
  - Parse ELF binaries using standard library `debug/elf`.
  - Extract `.rodata` string tables and scan for candidate shell commands.
  - Cross-reference extracted command tokens against user-writable directories in `$PATH`.
  - Gate behind `--deep-elf` flag to preserve sub-second default speed and zero false positives during routine audits.
- **Evaluation:**
  - ⚡ Speed: ~1ms per non-standard SUID binary (<50ms total).
  - 📉 FP Risk: Controlled via strict heuristic filtering (no absolute paths, no shell syntax, max 20 chars).
  - 🎯 New Vectors: Unlocks detection of custom/compiled privilege escalation vulnerabilities.

#### 2. SCN-01 — D-Bus System Bus Policy & Method Auditor (`scanners/dbus.go`)
- **Objective:** Audit system D-Bus service configurations for unauthorized method invocations.
- **Technical Design:**
  - Inspect XML configuration policies in `/etc/dbus-1/system.d/` and `/usr/share/dbus-1/system.d/`.
  - Flag policies granting unauthenticated users `send_destination="*"` or root service method access without `auth_admin` Polkit restrictions.
  - Detect writable D-Bus policy files allowing persistent privilege elevation.
- **Evaluation:**
  - ⚡ Speed: <5ms (streaming XML parsing of small configuration files).
  - 📉 FP Risk: Very Low (flags explicit configuration weaknesses).
  - 🎯 New Vectors: Inter-Process Communication (IPC) privilege escalation.

#### 3. SCN-02 — Expanded Linux File Capability Matrix (`scanners/capabilities.go`)
- **Objective:** Broaden capability evaluation beyond `CAP_SETUID`/`CAP_SETGID`.
- **Technical Design:**
  - Audit `CAP_DAC_OVERRIDE` & `CAP_DAC_READ_SEARCH` (bypasses all UNIX file permission boundaries).
  - Audit `CAP_SYS_PTRACE` (arbitrary memory inspection and process code injection).
  - Audit `CAP_SYS_ADMIN` (container namespace breakout, arbitrary filesystem mount).
  - Audit `CAP_NET_RAW` & `CAP_NET_ADMIN` (raw socket sniffing and interface manipulation).
  - Provide tailored remediation and exploitation payloads for each capability.

#### 4. SCN-03 — Mail Spool & System Log Secret Harvester (`scanners/log_mail.go`)
- **Objective:** Inspect unprivileged-readable system log files and mailbox spools for leaked credentials.
- **Technical Design:**
  - Stream `/var/mail/`, `/var/spool/mail/`, and user-readable `/var/log/` entries using `bufio.Scanner` with a 64KB bounded buffer.
  - Identify automated cron delivery errors containing database passwords, API tokens, or reset credentials.
  - Implement strict line limits to prevent high I/O on heavily saturated production logs.

---

### Milestone v2.4: Container Breakout & Kernel Diagnostics

#### 5. SCN-04 — Container Breakout & Namespace Escape Engine (`scanners/container_escape.go`)
- **Objective:** Detect modern container escape misconfigurations when Talaria runs inside Docker, Podman, or Kubernetes pods.
- **Technical Design:**
  - Check cgroup v1 `release_agent` writability and notify-on-release flags.
  - Detect accessible container engine sockets (`/var/run/docker.sock`, `/run/containerd/containerd.sock`, `/run/crio/crio.sock`).
  - Audit exposed kernel devices (`/dev/mem`, `/dev/kmem`, `/dev/kmsg`) and missing Seccomp / AppArmor container profiles.
  - Validate Kubernetes ServiceAccount token permissions (`/var/run/secrets/kubernetes.io/serviceaccount/token`).

#### 6. SCN-05 — eBPF & Kernel Tracing Security Auditor (`scanners/ebpf.go`)
- **Objective:** Detect eBPF privileges that allow unprivileged kernel code injection or privilege escalation.
- **Technical Design:**
  - Check `/proc/sys/kernel/unprivileged_bpf_disabled`.
  - Inspect `/sys/kernel/debug/tracing` permissions and active kprobes/uprobes.
  - Cross-reference with `CAP_BPF` or `CAP_SYS_ADMIN`.

#### 7. B6 — Distro-Specific Kernel CVE Backport Resolver (`--distro-cve`)
- **Objective:** Eliminate false positive kernel CVE alerts on enterprise distributions (Ubuntu LTS, Debian, RHEL) where fixes are backported without incrementing the upstream kernel version.
- **Technical Design:**
  - Compile an embedded distribution backport version map (`distro_cves.json`).
  - When scanning Ubuntu `5.15.0-91-generic` or RHEL `kernel-4.18.0-372.el8`, cross-reference vendor security advisories before raising HIGH/CRITICAL CVE flags.
  - Label backported kernels as `RESOLVED (VENDOR BACKPORT)` instead of falsely alerting.

---

### Milestone v2.5: Multi-Goal Graph & Probabilistic Engine

#### 8. INT-01 — Configurable Multi-Goal Attack Graph Traversal
- **Objective:** Extend Dijkstra pathfinding beyond single `goal:root` to support user-selected target objectives.
- **Supported Objectives:**
  - `--goal=root` (default): Maximum privilege escalation.
  - `--goal=breakout`: Escape from container or chroot environment to host OS.
  - `--goal=credentials`: Harvest highest volume of cloud/database authentication keys.
  - `--goal=persistence`: Identify writable services, crontabs, or systemd drop-ins for survival.

#### 9. INT-02 — Dynamic Probabilistic Edge Weighting
- **Objective:** Refine attack path calculation by incorporating host-specific exploit reliability factors:
  - Presence of kernel ASLR (`kernel.randomize_va_space`).
  - Active LSM confinement (SELinux enforcing, AppArmor profiles).
  - Unprivileged user namespace restrictions (`kernel.unprivileged_userns_clone`).
  - Read-only root filesystem mounts.

---

### Milestone v2.6: DevSecOps Automation & Enterprise Ecosystem

#### 10. OPS-01 — Baseline Delta Auditing (`--baseline=approved.json`)
- **Objective:** Enable CI/CD pipelines and DevSecOps teams to enforce a "no new security regressions" gate.
- **Behavior:**
  - Ingest an existing signed scan baseline.
  - Compute a deterministic semantic diff between old and current findings.
  - Emit exit code 1 only if **new** misconfigurations have been introduced, suppressing pre-existing accepted technical debt.

#### 11. OPS-02 — Automated Bash Remediation Script Generator (`--generate-fix`)
- **Objective:** Automatically produce an idempotent, dry-run-capable bash script that executes all recommended hardening commands.
- **Behavior:**
  - Assembles all scanner `Remediation` commands into an executable script.
  - Includes `--dry-run` flag support, file permission backups (`cp -a`), and pre-execution state verification.

#### 12. OPS-03 — Interactive Terminal UI Dashboard (`--interactive`)
- **Objective:** Provide a low-overhead, curses-style terminal navigation interface for interactive pentesting and incident response.
- **Behavior:**
  - Interactive attack graph navigation using arrow keys.
  - Instant copying of GTFOBins exploit one-liners to the system clipboard or OSC-52 terminal buffer.
  - Real-time search and filter across all scanned categories.

---

## ⚖️ Strategic Optimization & Feasibility Matrix

Every proposed roadmap item is evaluated against five standardized axes (1 = lowest/worst, 5 = highest/best):

| ID | Initiative Name | Speed (1–5) | FP Safety (1–5) | Vector Impact (1–5) | Arch Stability (1–5) | Implementation Ease (1–5) | Overall Score | Priority |
|:---|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **B2** | Deep ELF String Analysis (`--deep-elf`) | 4/5 | 4/5 | 5/5 | 4/5 | 4/5 | **21 / 25** | **P1 (v2.3)** |
| **SCN-01** | D-Bus System Policy Auditor | 5/5 | 5/5 | 4/5 | 5/5 | 4/5 | **23 / 25** | **P1 (v2.3)** |
| **SCN-02** | Expanded Linux Capability Matrix | 5/5 | 5/5 | 5/5 | 5/5 | 4/5 | **24 / 25** | **P1 (v2.3)** |
| **SCN-03** | Mail Spool & Log Secret Harvester | 4/5 | 3/5 | 4/5 | 4/5 | 3/5 | **18 / 25** | **P2 (v2.3)** |
| **SCN-04** | Container Escape Engine | 5/5 | 5/5 | 5/5 | 5/5 | 4/5 | **24 / 25** | **P1 (v2.4)** |
| **SCN-05** | eBPF & Kernel Tracing Auditor | 5/5 | 5/5 | 4/5 | 5/5 | 4/5 | **23 / 25** | **P2 (v2.4)** |
| **B6** | Distro Kernel CVE Backport Resolver | 5/5 | 5/5 | 4/5 | 4/5 | 3/5 | **21 / 25** | **P2 (v2.4)** |
| **INT-01** | Configurable Multi-Goal DAG | 5/5 | 5/5 | 4/5 | 4/5 | 4/5 | **22 / 25** | **P2 (v2.5)** |
| **INT-02** | Dynamic Probabilistic Weighting | 5/5 | 5/5 | 4/5 | 4/5 | 3/5 | **21 / 25** | **P3 (v2.5)** |
| **OPS-01** | Baseline Delta Auditing | 5/5 | 5/5 | 4/5 | 4/5 | 4/5 | **22 / 25** | **P2 (v2.6)** |
| **OPS-02** | Automated Remediation Script Generator | 5/5 | 5/5 | 4/5 | 5/5 | 4/5 | **23 / 25** | **P2 (v2.6)** |
| **OPS-03** | Interactive TUI Dashboard | 4/5 | 5/5 | 3/5 | 3/5 | 2/5 | **17 / 25** | **P3 (v2.6)** |

---

## 🤝 Community Feedback & Roadmap Proposing

We encourage the open-source security community to propose new privilege escalation vectors and architectural improvements:
1. Review existing scanners in [`docs/SCANNERS.md`](SCANNERS.md) and attack chains in [`docs/ARCHITECTURE.md`](ARCHITECTURE.md).
2. Ensure your proposed vector meets the **Zero Third-Party Dependency** and **Zero Host Mutation** constraints.
3. Open a GitHub Issue using the **Feature / Scanner Proposal** template, including the 5 standard evaluation metrics.
