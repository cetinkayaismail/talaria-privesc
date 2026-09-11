# Security Policy

## Supported Versions

Security updates and patches are actively applied to the latest release line:

| Version | Supported          | Security Baseline |
| :--- | :---: | :--- |
| `v2.x` (current) | :white_check_mark: | Active support & continuous CVE mitigation |
| `v1.x` | :white_check_mark: | Critical vulnerability patches only |
| `< v1.0` | :x: | End-of-life |

## Safe Architecture Guarantee

Talaria is engineered as a **purely read-only** security assessment engine:
- **Zero Disk Mutation:** File descriptors are opened with `O_RDONLY` and zero temporary files are written to disk.
- **Zero Third-Party Dependencies:** The codebase utilizes 100% canonical Go standard library primitives, eliminating software supply chain attacks (zero npm/go modules/cgo exploits).
- **Process Isolation:** Command executions are strictly bounded by context deadlines (`exec.CommandContext`) and do not execute interactive shells.

## Reporting a Security Vulnerability

If you discover a potential vulnerability, please **do not create a public issue**. Instead, follow responsible disclosure:

1. **GitHub Private Vulnerability Reporting:** Submit a report via the **[Security Advisories](https://github.com/cetinkayaismail/talaria-privesc/security/advisories/new)** tab.
2. **Direct Maintainer Contact:** If Private Reporting is unavailable, reach out to the project maintainers via the email listed on the repository owner's GitHub profile.

### Information to Include in Your Report
- Detailed summary of the potential security risk or host-state issue.
- Step-by-step reproduction instructions or a minimal test case.
- Impact assessment (e.g., memory exhaustion, improper privilege assumption, uncontrolled file descriptor leak).
- Suggested remediation or patch if available.

### Response SLA & Remediation Process
- **Initial Acknowledgment:** Within 48 hours.
- **Severity Assessment & Triage:** Within 5 business days.
- **Coordinated Fix & Release:** Critical security patches will be published with a CVE identifier and explicit changelog credits upon validation.
