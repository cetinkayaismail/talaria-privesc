# Talaria Future Plans & Architecture Upgrades

This document outlines planned features, logic upgrades, and architectural changes for the Talaria Intelligence Engine. Features are sorted from the **hardest/most complex to implement** to the **easiest**.

Features that have already been successfully integrated into our project (Intelligence Engine Modularization, Systemd-Machined CVE-2026-40224 vulnerability, AppArmor Risk Downgrading, Udev Rules Injection, MOTD & Profile.d Hijacking, Process-Based Secret Scanning, etc.) have been removed from this list.

## Feature Analysis & Scoring

Each upcoming feature is analyzed and scored based on 4 criteria:
- **FP Rate (False Positives):** How will it affect the system's rate of generating unnecessary alarms?
- **Speed Impact:** What is the impact on the overall scan speed (in seconds/milliseconds)?
- **Vector Missing (FN - False Negatives):** Will it cause us to hide or overlook a real vulnerability?
- **Arch Risk (Long-Term Architecture Risk):** Will it complicate future maintenance of the codebase or break the currently working system?

---

### 1. Parallel Directory Walking Worker Pool Architecture (`parallel_walking_worker_pool`)
- **Description:** Implement a parallel directory walking architecture (worker pool) using Go channels to distribute scan tasks concurrently, replacing the slow sequential `filepath.WalkDir`.
- **FP Rate:** *Low.* Does not change finding logic.
- **Speed Impact:** *Extremely High.* Drastically cuts down scan times on massive filesystems, particularly on low-speed drives or NFS.
- **Vector Missing (FN):** *Zero.*
- **Arch Risk:** *High.* Requires replacing sequential walkers with concurrent ones and managing race conditions and goroutine limits.

### 2. Embedded GTFOBins JSON Database
- **Description:** Transitioning from a static hardcoded map of dangerous binaries to an embedded JSON database. Allows for hundreds of more binaries to be tracked with zero performance penalty.
- **FP Rate:** *Low.*
- **Speed Impact:** *Zero.* (Embedded at compile-time).
- **Vector Missing (FN):** *Extremely Low.* Covers much more ground than static lists.
- **Arch Risk:** *Medium.* Requires maintaining a collection of JSON definitions.

### 3. Advanced Intelligence Chains (Cross-Reference Upgrades)
- **Description:** Adding new "Attack Chains" to the Intelligence Engine using existing data:
    - **Capability Chain:** Linking `CAP_DAC_READ_SEARCH` or `CAP_SYS_ADMIN` directly to exploitation paths.
    - **NFS no_root_squash:** Identifying writable NFS shares that allow SUID binary injection.
    - **Password Reuse:** Automating the cross-referencing of found secrets with other local user accounts.
- **FP Rate:** *Low.*
- **Speed Impact:** *Negligible.* (Uses already scanned data).
- **Vector Missing (FN):** *Low.*
- **Arch Risk:** *Low.* Clean additions to `core/intelligence.go`.

### 4. Shell Script Wildcard Expansion (`wildcard_exploit`)
- **Description:** Auditing cronjobs, writable shell scripts, and systemd service scripts for dangerous wildcard usages (like `tar *`, `chown *`, `chmod *`, or `rsync *`) in paths where a regular user can write or plant files.
- **FP Rate:** *Low.* Only flags wildcards used in conjunction with vulnerable executables inside writable directories.
- **Speed Impact:** *Medium.* Requires reading and regex-parsing discovered shell scripts.
- **Vector Missing (FN):** *Medium.* Obfuscated shell scripts or complex commands might hide the wildcards.
- **Arch Risk:** *Medium.* Can be integrated into existing `scanners/writeable.go` or a new `scanners/wildcards.go` module.

### 5. Python Library Hijacking (`python_hijack`)
- **Description:** Checking if system-wide root-owned Python scripts are writable, or if their source directories or standard libraries (e.g. in `site-packages` or `dist-packages`) are writable, allowing library hijacking via path lookup priority.
- **FP Rate:** *Low.* Directly verifies write access on importable paths and script directories.
- **Speed Impact:** *High.* Requires traversing python paths and analyzing imports of root-owned scripts.
- **Vector Missing (FN):** *Medium.* Python paths can be dynamically modified at runtime.
- **Arch Risk:** *Medium.* Requires parsing python script dependencies and mapping system-wide module directories.

### 6. Garbage Collection and Memory Optimization with Pool Buffers (`gc_mem_pool_buffers`)
- **Description:** Implement a `sync.Pool` based slice allocation mechanism for byte buffer pools in I/O intensive scanners (like `fileperms_exploit.go` and `secrets.go`) to prevent heavy GC overhead during scans.
- **FP Rate:** *Zero.*
- **Speed Impact:** *High.* Reduces CPU cycles wasted on memory allocations and garbage collection sweeps.
- **Vector Missing (FN):** *Zero.*
- **Arch Risk:** *Low-Medium.* Requires careful memory-pool recycling to avoid dirty data leakage.

### 7. Deep Mailbox & System Log Auditing (`log_mailbox_audit`)
- **Description:** Auditing system log files (like `/var/log/auth.log`, `/var/log/syslog`, `/var/log/secure`) and user mail spools (under `/var/mail/` and `/var/spool/mail/`) for sensitive information leaks, system notifications, or credentials left in plain-text logs or notification emails.
- **FP Rate:** *High.* Requires robust regex to distinguish actual leaked secrets from normal log structures or operational system emails.
- **Speed Impact:** *High.* Parsing massive syslog files (which can span hundreds of megabytes) introduces substantial I/O load.
- **Vector Missing (FN):** *Medium.* Logs rotate frequently, meaning older secrets might be missing.
- **Arch Risk:** *Medium.* Requires memory-safe buffered streaming of large log files to prevent memory exhaustion (OOM) under 32-bit constraints.
