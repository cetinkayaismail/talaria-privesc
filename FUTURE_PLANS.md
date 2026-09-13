# Talaria — Strategic Roadmap & Future Plans

The master strategic roadmap and future engineering plans for Talaria are maintained in the documentation library:

👉 **[docs/FUTURE_PLANS.md](docs/FUTURE_PLANS.md)**

---

## 🗺️ Quick Summary of Upcoming Releases

- **v2.3 (Deep Inspection & Capability Expansion):**
  - Deep ELF string and disassembly analysis (`--deep-elf`) for custom root SUID binaries.
  - D-Bus system bus policy and method auditor (`scanners/dbus.go`).
  - Expanded Linux capability evaluation (`CAP_DAC_OVERRIDE`, `CAP_SYS_PTRACE`, `CAP_SYS_ADMIN`).
  - Memory-safe mail spool and system log secret harvester (`scanners/log_mail.go`).

- **v2.4 (Container Breakout & Kernel Diagnostics):**
  - Cgroup v1/v2 release agent escape engine & container socket auditing.
  - eBPF and kernel tracing security auditor.
  - Distro-specific kernel CVE backport resolver (`--distro-cve`).

- **v2.5 (Multi-Goal Graph & Probabilistic Engine):**
  - Configurable multi-goal attack graph pathfinding (`--goal=root|breakout|credentials|persistence`).
  - Dynamic probabilistic edge weighting factoring ASLR, SELinux, and AppArmor confinement.

- **v2.6 (DevSecOps Automation & Enterprise Suite):**
  - CI/CD baseline delta auditing (`--baseline=prev.json`).
  - Automated bash remediation script generation (`--generate-fix`).
  - Interactive terminal UI dashboard (`--interactive`).
  - SIEM and messaging webhook dispatchers.

For full technical specifications, evaluation scorecards, and implementation priorities, see **[docs/FUTURE_PLANS.md](docs/FUTURE_PLANS.md)**.
