# Talaria Documentation Directory

Welcome to the **Talaria** technical documentation library. This directory contains detailed specifications, architectural blueprints, integration guides, and operational runbooks for Talaria.

---

## Documentation Map

```
docs/
├── README.md                           # Documentation directory index (this file)
├── ARCHITECTURE.md                     # Enterprise architecture & formal STRIDE threat model
├── SCANNERS.md                         # Detailed catalog of all 45+ security audit scanners
├── RULES_CATALOG.md                    # CIS Benchmarks, NIST SP 800-53, DISA STIG, & MITRE ATT&CK mapping
├── INTEGRATION_GUIDE.md                # SIEM integration (Splunk, Elastic, Datadog), JSON Schema, SARIF
├── OPERATIONS_RUNBOOK.md               # SRE deployment guide (Kubernetes CronJobs, systemd, air-gap)
├── DEVELOPMENT.md                      # Developer environment, benchmarking, testing, and debugging
└── STANDARDS_AND_REMEDIATION_MATRIX.md # In-depth remediation matrix and risk classifications
```

---

## Overview of Key Specifications

### 🏛️ [Architecture Specification & Threat Model](ARCHITECTURE.md)
Detailed architectural overview of Talaria:
- Component topology and unidirectional dependency boundaries (`cmd/` -> `scanners/`/`core/` -> `models/`).
- Formal STRIDE threat analysis and mathematical Zero-Mutation proof (`O_RDONLY` file descriptors).
- Graph-based Attack Chain Engine (weighted Directed Acyclic Graph solving for `goal:root`).
- Memory and concurrency architecture (`RLIMIT_NOFILE` dynamic sizing).

### 🎯 [Scanner Reference Catalog](SCANNERS.md)
Exhaustive reference for every scanner module in `scanners/`:
- Description of the privilege escalation vector.
- Audited system paths, environment variables, or procfs structures.
- Risk scoring criteria (CRITICAL, HIGH, MEDIUM, LOW, INFO).
- False-positive elimination strategies.

### 🛡️ [Security Rules & Remediation Catalog](RULES_CATALOG.md)
Compliance and mitigation mappings:
- Exact CIS Linux Benchmark v2.0.0 recommendations.
- NIST SP 800-53 Rev. 5 controls.
- DISA STIG rule IDs.
- Deterministic bash remediation commands for systems administrators.

### 📊 [SIEM & Telemetry Integration Guide](INTEGRATION_GUIDE.md)
Enterprise ingestion pipelines:
- Draft 2020-12 compliant JSON Schema for automated validation.
- Splunk Cloud/Enterprise blueprints and field extractions.
- Elastic SIEM Logstash pipelines and index mappings.
- Datadog agent configuration.
- SARIF export integration with GitHub Code Scanning.

### 🚀 [Operations & SRE Runbook](OPERATIONS_RUNBOOK.md)
Production deployment patterns:
- Kubernetes CronJob manifests with restricted SecurityContext.
- CIS-hardened systemd service and timer templates.
- Air-gapped banking enclave deployment checklist.
- Failure Mode & Effects Analysis (FMEA) table.

### 💻 [Developer Guide](DEVELOPMENT.md)
Everything needed to develop and extend Talaria:
- Local Go toolchain prerequisites.
- Building standard and static binaries.
- Running unit tests with race detection.
- Profiling CPU and memory allocations with `pprof`.

---

## Contributing to Documentation

We welcome improvements and additions to our documentation. If you are adding a new scanner or updating operational guidance:
1. Ensure documentation follows the same concise, accurate tone.
2. Link new documents in this `docs/README.md` and the root `README.md`.
3. Submit your pull request following the guidelines in [`CONTRIBUTING.md`](../CONTRIBUTING.md).
