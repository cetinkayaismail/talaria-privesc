# Talaria — Enterprise Operations & CLI User Guide

Talaria is a modular, zero-dependency, zero-mutation Linux Privilege Escalation and Security Audit Scanner. It can execute comprehensive system-wide audits or selectively target discrete audit domains.

---

## 1. Core Invocation Patterns

### Comprehensive Full-System Audit (Default Mode: Audit & Compliance)
Execute all 51 audit modules across the root filesystem. By default, Talaria runs in **Enterprise Audit Mode** (`--audit=true`), providing credential sanitization, CIS/NIST framework mapping, and remediation commands:
```bash
./talaria --scan all
```

### Visual Summary Dashboard (`--ui`)
Enable the visual terminal card dashboard displaying finding counts, audit status, and top attack paths:
```bash
./talaria --scan all --ui
```

### CTF & Rapid Exploitation Mode (`--ctf`)
Activate offensive assessment mode for CTF competitions and rapid penetration testing. This mode prioritizes instant root escalation, cleartext credentials, GTFOBins one-liners, and automatically enables deep ELF analysis (`--deep-elf`):
```bash
./talaria --scan all --ctf
```

### Targeted Module Execution
Target specific audit domains (e.g. SUID executables, Linux capabilities, and sudo privileges):
```bash
./talaria --scan suid,capabilities,sudo
```

### Scoped Filesystem Traversal
Constrain filesystem audits to a designated path (e.g. `/var/www` or `/opt`):
```bash
./talaria --scan writeable,secrets --path /var/www
```

### Excluding High-Volume Modules
Bypass specific modules to optimize execution speed or focus scope:
```bash
./talaria --scan all --exclude network,vulnerabilities
```

### CI/CD Pipeline Mode with Severity Gate (`--fail-on` & `--quiet`)
Integrate into automated DevSecOps pipelines. Exit with status code 1 if findings meet or exceed severity threshold, and suppress decorative banners:
```bash
./talaria --scan all --fail-on=CRITICAL --quiet
```

### Structured Telemetry Export (JSON & SARIF)
Generate machine-readable reports for SIEM ingestion (Splunk, Elastic, Datadog) or GitHub Code Scanning:
```bash
./talaria --scan all -o audit_report.json --format json
./talaria --scan all -o audit_report.sarif --format sarif
```

### Cryptographic Report Archival (AES-256-GCM)
Encrypt the exported audit report at rest using authenticated AES-256-GCM:
```bash
./talaria --scan all -o /dev/shm/audit.enc --encrypt "YourSecureInstitutionalPassphrase"
```

### Explicit Sudo Credential Auditing
Provide sudo authentication non-interactively to audit `sudo -l` authorization rules:
```bash
./talaria --scan sudo --pass 'UserAuthToken123!'
```

---

## 2. Command Line Flag Reference

### Core Execution Flags

| Flag | Default | Type | Description |
|---|---|---|---|
| `--scan`, `--module`, `--modules` | `all` | string | Comma-separated list of audit modules to execute, or `all`. |
| `--exclude` | `""` | string | Comma-separated list of audit modules to bypass during execution. |
| `--path` | `/` | string | Root directory path for filesystem traversal modules. |
| `-o` | `""` | string | Output file path to persist the generated report (requires `--format` or `--encrypt`). |
| `--format` | `text` | string | Report format: `text` (human-readable), `json` (Draft 2020-12 schema), or `sarif`. |
| `--pass` | `""` | string | Optional sudo password for non-interactive `sudo -l` authorization inspection. |
| `--io-limit` | `0` | int | Maximum concurrent I/O scanning goroutines (default `0`: auto-calculated from `RLIMIT_NOFILE`). |
| `--encrypt` | `""` | string | AES-256-GCM encryption passphrase applied to output report (requires `-o`). |

### Operational Modes (Dual-Engine)

| Flag | Default | Type | Description |
|---|---|---|---|
| `--audit` | `true` | bool | **Default mode**: Blue team compliance audit with remediation commands, masked secrets, and CIS/NIST tags. |
| `--professional`, `-p` | `true` | bool | Alias for `--audit`. |
| `--ctf` | `false` | bool | CTF / offensive mode: rapid root escalation, GTFOBins exploit 1-liners, cleartext credentials. Mutually exclusive with `--audit`. |
| `--deep-elf` | `auto` | bool | Deep ELF string analysis & PATH hijack auditing on custom SUID binaries (`true` in CTF, `false` in Audit). |

### CI/CD & Automation Flags (Phase 4)

| Flag | Default | Type | Description |
|---|---|---|---|
| `--fail-on=SEVERITY` | `""` | string | Exit code 1 if findings meet or exceed threshold (`CRITICAL`, `HIGH`, `MEDIUM`). |
| `--quiet`, `-q` | `false` | bool | CI/CD pipeline mode: suppress ASCII banner and decorative headers. |

### Presentation & Formatting Flags

| Flag | Default | Type | Description |
|---|---|---|---|
| `--ui` | `false` | bool | Enable visual summary dashboard card. |
| `--no-color` | `false` | bool | Disable ANSI colors (also respects `NO_COLOR` environment variable or non-TTY). |

---

## 3. Complete 51 Audit Module Catalog

Talaria provides 51 deterministic audit modules categorized by subsystem:

| Module Identifier | Subsystem | Description |
|---|---|---|
| `secrets` | Credentials & Storage | Sensitive configuration files, credential dumps, database connection strings, cloud keys |
| `suid` | Privileged Binaries | SUID executables cross-referenced against GTFOBins and custom binaries |
| `sgid` | Privileged Binaries | SGID executables with privileged group ownership (shadow, disk, staff) |
| `sudo` | Access Control | Sudoers rules analysis (`NOPASSWD`, `SETENV`, `!authenticate`, `env_keep`) |
| `capabilities` | Execution Controls | Extended Linux file capabilities (`CAP_SETUID`, `CAP_SYS_ADMIN`, `CAP_DAC_OVERRIDE`) |
| `cronjobs` | Automation | System and user crontabs, anacron, systemd timers, and scheduled tasks |
| `processes` | Process Subsystem | Active process arguments with plaintext credentials and process boundaries |
| `ptrace` | Process Subsystem | Kernel `ptrace_scope` and cross-process memory inspection vulnerabilities |
| `nfs` | Filesystem & Storage | Network File System exports auditing (`no_root_squash` and insecure mount options) |
| `network` | Network Infrastructure | Active listening TCP/UDP sockets, loopback services, and perimeter exposure |
| `writeable` | Filesystem Integrity | World-writable and group-writable system binaries, scripts, and configuration files |
| `initscripts` | Service Management | Writable SysV init scripts in `/etc/init.d/` and runlevel service directories |
| `logrotate` | Automation | Writable `postrotate` scripts and insecure configuration files in `/etc/logrotate.d/` |
| `environmentfile` | Service Management | Systemd service `EnvironmentFile=` directive writability and injection vectors |
| `sockets` | IPC & Sockets | Privileged Unix domain sockets (Docker daemon socket, system service sockets) |
| `filepermissions` | Filesystem Integrity | Critical system file permission drift (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`) |
| `filepermsexploit` | Execution Hijack | SUID/SGID scripts invoking relative binary paths susceptible to PATH hijacking |
| `groups` | Access Control | Privileged supplemental group memberships (docker, lxd, disk, shadow, adm) |
| `services` | Service Management | Local daemon auditing (unauthenticated Redis, blank password MySQL, Memcached) |
| `packages` | Package Management | Package manager execution hooks (`apt`, `dpkg`), drop-in directories, and repository writability |
| `pathhijack` | Execution Hijack | Writable directory entries or relative paths (`.`) within system and user `$PATH` |
| `sshkeys` | Credentials & Storage | User `authorized_keys` writability, private key exposure, and active agent sockets |
| `vulnerabilities` | Vulnerability Intel | Deterministic kernel and installed software version CVE mapping (Dirty COW, PwnKit) |
| `container` | Virtualization | Container breakout primitives (privileged mode, mounted docker sockets, sensitive host mounts) |
| `dbus` | IPC & Sockets | System D-Bus configuration policies and unprotected remote procedure calls |
| `sessions` | Session Subsystem | Active tmux and GNU screen Unix domain socket hijacking vectors and `.Xauthority` session cookies |
| `kernelconfig` | Kernel Hardening | Leaked kernel configuration options (`CONFIG_STRICT_DEVMEM`, uncompressed kconfig) |
| `polkit` | Access Control | PolicyKit JavaScript rules logic auditing and pkexec authorization rules |
| `history` | Credentials & Storage | Sensitive secrets, database passwords, and API tokens in shell history files |
| `pam` | Access Control | Pluggable Authentication Modules configuration, pam_exec scripts, and custom modules |
| `sysctl` | Kernel Hardening | Kernel sysctl runtime baseline inspection (symlink protection, eBPF unprivileged) |
| `systemdoverrides`| Service Management | Systemd service drop-in directories (`*.service.d/*.conf`) write permissions |
| `subuid` | Virtualization | Unprivileged user namespace cloning and SubUID/SubGID allocation ranges |
| `mounts` | Filesystem Integrity | Shared memory and temporary storage mount flags (`noexec`, `nosuid` on `/dev/shm`) |
| `udev` | Hardware & Devices | Udev rule definitions (`/etc/udev/rules.d`) and event execution target writability |
| `crondirs` | Automation | System task drop-in directory permission drift (`/etc/cron.d`, `/var/spool/cron`) |
| `ldnss` | Execution Hijack | Dynamic linker search paths (`/etc/ld.so.conf.d`) and NSS switch configuration |
| `modprobe` | Kernel Hardening | Kernel module blacklists and modprobe execution install targets (`/etc/modprobe.d`) |
| `cloudmeta` | Cloud & Enclaves | In-cluster Kubernetes ServiceAccount tokens and Cloud IMDSv1/v2 endpoints |
| `venvwrap` | Execution Hijack | Python virtual environment site-packages writability and execution wrapper scripts |
| `python_hijack` | Execution Hijack | Python module hijacking via writable directories present in `sys.path` |
| `elfrpath` | Execution Hijack | Dynamic ELF `DT_RPATH` / `DT_RUNPATH` search header analysis on privileged binaries |
| `auditd` | Audit & Logging | System audit daemons (`auditd`, `rsyslog`, `journald`) status and rule coverage |
| `procenv` | Process Subsystem | Process environment secret and token harvesting from `/proc/[pid]/environ` |
| `sudoers_dropin` | Access Control | Writable `/etc/sudoers.d/` drop-in configuration directory and custom rule files |
| `shell_rc` | Persistence & Hijack | Writable root shell startup scripts (`/root/.bashrc`, `/etc/environment`, `/etc/profile`) |
| `at_jobs` | Automation | Writable `at` daemon spool directories and queued scheduled job files |
| `fstab` | Filesystem Integrity | Insecure mount flags (`user`, `exec`) in `/etc/fstab` enabling unprivileged code execution |
| `snap_audit` | Execution Controls | Snap package confinement analysis (`classic`, `devmode`) and writable snap paths |
| `git_hooks` | Execution Hijack | Writable Git hooks in shared or production repositories executed by privileged users |
| `xinetd` | Service Management | Insecure `xinetd` service configurations and writable server executables |

---

## 4. Decrypting Encrypted Reports

Reports encrypted with `--encrypt` utilize AES-256-GCM. Decrypt them using the Talaria programmatic API or standard OpenSSL tools:

### Using Talaria Core Decryption
```go
decryptedBytes, err := core.DecryptReport(encryptedBase64Bytes, "YourSecureInstitutionalPassphrase")
```

### Verification
All scans produce zero persistent side-effects or temporary files on disk when executed without `-o`.
