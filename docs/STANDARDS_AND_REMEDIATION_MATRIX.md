# Talaria — Comprehensive Security Standards & Universal Remediation Matrix

This document provides the authoritative, multi-framework compliance mapping and deterministic remediation matrix for all **30+ security audit domains** in Talaria. 

Every scanner finding is mapped directly to established industry standards:
- **CIS Benchmarks:** CIS Distribution-Independent Linux Benchmark v2.0.0 & Ubuntu/RHEL Benchmarks
- **NIST SP 800-53 Rev. 5:** Security and Privacy Controls for Information Systems (Federal Baseline)
- **DISA STIG:** DoD Security Technical Implementation Guides for Red Hat Enterprise Linux & Ubuntu
- **MITRE ATT&CK:** Enterprise Matrix for Linux (Privilege Escalation, Persistence, Credential Access)

---

## Table of Contents
1. [Domain 1: Privileged Binaries & Execution Controls](#domain-1-privileged-binaries--execution-controls)
2. [Domain 2: Access Control & Authorization Subsystems](#domain-2-access-control--authorization-subsystems)
3. [Domain 3: Scheduled Tasks & Automated Execution Triggers](#domain-3-scheduled-tasks--automated-execution-triggers)
4. [Domain 4: Kernel, Memory & Device Security](#domain-4-kernel-memory--device-security)
5. [Domain 5: Filesystem & Mount Point Hardening](#domain-5-filesystem--mount-point-hardening)
6. [Domain 6: Credentials, Tokens & In-Memory Secrets](#domain-6-credentials-tokens--in-memory-secrets)
7. [Domain 7: Package Management, Namespaces & Kernel CVEs](#domain-7-package-management-namespaces--kernel-cves)
8. [Domain 8: Container, Cloud & Perimeter Infrastructure](#domain-8-container-cloud--perimeter-infrastructure)

---

## Domain 1: Privileged Binaries & Execution Controls

### 1.1 SUID / SGID Binaries & GTFOBins Escalation (`scanners/suid.go`, `scanners/gtfobins.go`)
* **Framework Mappings:**
  * **CIS Benchmark:** `CIS 6.1.13` (Audit SUID executables), `CIS 6.1.14` (Audit SGID executables)
  * **NIST SP 800-53:** `AC-6(1)` (Authorize Access to Security Functions), `CM-6` (Configuration Settings)
  * **DISA STIG:** `V-230530` (Non-essential SUID/SGID files must be removed)
  * **MITRE ATT&CK:** `T1548.001` (Abuse Elevation Control Mechanism: Setuid and Setgid)
* **Risk Severity:** **CRITICAL** (if GTFOBins-capable or custom binary) / **HIGH**
* **Vulnerability Condition:** Executable with SUID (`04000`) or SGID (`02000`) bit set allows shell escapes or arbitrary root file manipulation.
* **Authoritative Remediation:**
  ```bash
  # Remove SUID/SGID bit from non-essential or dangerous binary
  chmod u-s,g-s /path/to/binary
  # Or restrict execution to authorized administrative group only
  chown root:root /path/to/binary && chmod 0750 /path/to/binary
  ```
* **Verification Command:**
  ```bash
  find /path/to/binary -perm /6000
  ```

---

### 1.2 Linux File Capabilities (`scanners/capabilities.go`)
* **Framework Mappings:**
  * **CIS Benchmark:** `CIS 6.1.15` (Audit Linux file capabilities)
  * **NIST SP 800-53:** `AC-6(1)` (Least Privilege), `CM-6` (Configuration Settings)
  * **DISA STIG:** `V-230531` (System executables must not possess unauthorized file capabilities)
  * **MITRE ATT&CK:** `T1548.001` (Setuid and Setgid / Capability Abuse)
* **Risk Severity:** **CRITICAL** (`CAP_SETUID`, `CAP_SETGID`, `CAP_DAC_OVERRIDE`, `CAP_SYS_PTRACE`, `CAP_SYS_ADMIN`)
* **Vulnerability Condition:** Extended attribute file capabilities allow unprivileged processes to bypass kernel DAC or gain effective UID 0.
* **Authoritative Remediation:**
  ```bash
  # Strip extended file capabilities from the target binary
  setcap -r /path/to/binary
  ```
* **Verification Command:**
  ```bash
  getcap /path/to/binary
  ```

---

### 1.3 Dynamic Linker Search Paths & SUID ELF RPATH (`scanners/ld_nss.go`, `scanners/elf_rpath.go`)
* **Framework Mappings:**
  * **CIS Benchmark:** `CIS 5.4.2` (Ensure dynamic library search paths are root-owned and not world-writable)
  * **NIST SP 800-53:** `SI-7` (Software Integrity), `CM-6` (Configuration Settings)
  * **DISA STIG:** `V-230500` (Dynamic library configurations must be protected)
  * **MITRE ATT&CK:** `T1574.001` (Hijack Execution Flow: Dynamic Linker Hijacking), `T1574.006` (Dynamic Linker Search Paths)
* **Risk Severity:** **CRITICAL**
* **Vulnerability Condition:** User write access on `/etc/ld.so.conf`, `/etc/ld.so.conf.d/*.conf`, `/etc/nsswitch.conf`, or directory listed in library paths (e.g. `/usr/local/lib`); or SUID binary with relative `DT_RPATH` / `DT_RUNPATH` (e.g. `.` or `$ORIGIN`).
* **Authoritative Remediation:**
  ```bash
  # Fix ownership and permissions on LD configuration and library directories
  chown -R root:root /etc/ld.so.conf /etc/ld.so.conf.d /etc/nsswitch.conf
  chmod 0644 /etc/ld.so.conf /etc/ld.so.conf.d/*.conf /etc/nsswitch.conf
  chmod -R 0755 /usr/local/lib /opt/lib
  # Update dynamic linker cache
  ldconfig
  ```
* **Verification Command:**
  ```bash
  ls -la /etc/ld.so.conf.d/ && ldconfig -v 2>/dev/null | grep -i writable
  ```

---

## Domain 2: Access Control & Authorization Subsystems

### 2.1 Sudoers Delegation & Unrestricted Commands (`scanners/sudo.go`)
* **Framework Mappings:**
  * **CIS Benchmark:** `CIS 5.3.4` (Ensure sudo commands require password authentication), `CIS 5.3.7` (Ensure sudoers file integrity)
  * **NIST SP 800-53:** `AC-6(5)` (Privileged Accounts), `IA-5(1)` (Password Authentication)
  * **DISA STIG:** `V-230534` (Sudo configuration must prohibit NOPASSWD and environment inheritance)
  * **MITRE ATT&CK:** `T1548.003` (Abuse Elevation Control Mechanism: Sudo and Sudo Caching)
* **Risk Severity:** **CRITICAL** (`NOPASSWD`, `SETENV`, `env_keep+=LD_PRELOAD`, `ALL`)
* **Vulnerability Condition:** Sudo rule permits non-root user to execute binaries with `NOPASSWD`, `SETENV`, or dangerous wildcard patterns without password verification.
* **Authoritative Remediation:**
  ```bash
  # Remove NOPASSWD or dangerous directives; enforce full password re-authentication
  visudo -f /etc/sudoers.d/custom_rules
  # Ensure safe defaults are set in /etc/sudoers:
  # Defaults env_reset, timestamp_timeout=5
  # username ALL=(ALL:ALL) ALL
  chmod 0440 /etc/sudoers /etc/sudoers.d/*
  ```
* **Verification Command:**
  ```bash
  visudo -c
  ```

---

### 2.2 PolicyKit Custom JavaScript Authorization (`scanners/polkit.go`)
* **Framework Mappings:**
  * **CIS Benchmark:** `CIS 5.3.5` (Ensure polkit rules require root authentication for privileged actions)
  * **NIST SP 800-53:** `AC-3` (Access Enforcement), `AC-6` (Least Privilege)
  * **DISA STIG:** `V-230365` (Polkit rules must enforce administrative authorization)
  * **MITRE ATT&CK:** `T1548.001` (Abuse Elevation Control Mechanism)
* **Risk Severity:** **CRITICAL** (Custom JS rule returning `polkit.Result.YES` for non-root users)
* **Vulnerability Condition:** Rule file in `/etc/polkit-1/rules.d/` grants authorization without authentication or is writable by unprivileged users.
* **Authoritative Remediation:**
  ```bash
  # Enforce root ownership, restrictive permissions, and verify rule logic
  chown -R root:root /etc/polkit-1/rules.d/ /usr/share/polkit-1/rules.d/
  chmod 0750 /etc/polkit-1/rules.d/
  chmod 0644 /etc/polkit-1/rules.d/*.rules
  # Replace polkit.Result.YES with polkit.Result.AUTH_ADMIN in custom rules
  ```
* **Verification Command:**
  ```bash
  ls -ld /etc/polkit-1/rules.d/ && ls -la /etc/polkit-1/rules.d/
  ```

---

### 2.3 PAM Security Configurations & pam_exec Hooks (`scanners/pam.go`)
* **Framework Mappings:**
  * **CIS Benchmark:** `CIS 5.3.1` (Ensure PAM password policy is configured), `CIS 5.3.3` (Ensure PAM configuration files are root-owned and mode 0644)
  * **NIST SP 800-53:** `IA-2` (Identification and Authentication), `IA-5` (Authenticator Management)
  * **DISA STIG:** `V-230360` (PAM configuration files must be protected)
  * **MITRE ATT&CK:** `T1556.002` (Modify Authentication Process: Pluggable Authentication Modules)
* **Risk Severity:** **CRITICAL** (Writable `pam.d` file, writable `pam_exec` script, or custom `.so` module)
* **Vulnerability Condition:** PAM stack executes unprivileged script via `pam_exec.so` on authentication events, or `/etc/pam.d/` files are writable.
* **Authoritative Remediation:**
  ```bash
  # Fix ownership and permissions on all PAM stack configuration files
  chown -R root:root /etc/pam.d/ /etc/security/
  chmod 0755 /etc/pam.d/
  chmod 0644 /etc/pam.d/* /etc/security/*.conf
  # Ensure all pam_exec scripts are root-owned and read-only
  chown root:root /path/to/pam_script.sh && chmod 0700 /path/to/pam_script.sh
  ```
* **Verification Command:**
  ```bash
  ls -la /etc/pam.d/
  ```

---

### 2.4 Privileged Group Membership (`scanners/groups.go`)
* **Framework Mappings:**
  * **CIS Benchmark:** `CIS 5.4.1` (Ensure user accounts belong only to authorized functional groups)
  * **NIST SP 800-53:** `AC-6(2)` (Non-Privileged Access for Nonsecurity Functions)
  * **DISA STIG:** `V-230535` (Users must not possess unauthorized administrative group memberships)
  * **MITRE ATT&CK:** `T1078.003` (Valid Accounts: Local Accounts)
* **Risk Severity:** **CRITICAL** (`docker`, `lxd`, `disk`, `shadow`, `sudo`, `wheel`)
* **Vulnerability Condition:** Standard user is assigned to privileged secondary groups granting raw socket or disk block access.
* **Authoritative Remediation:**
  ```bash
  # Remove standard user from privileged group
  gpasswd -d <username> docker
  gpasswd -d <username> lxd
  gpasswd -d <username> disk
  gpasswd -d <username> shadow
  ```
* **Verification Command:**
  ```bash
  id <username>
  ```

---

## Domain 3: Scheduled Tasks & Automated Execution Triggers

### 3.1 System Task Drop-in Permissions & Cron Tables (`scanners/cronjobs.go`, `scanners/cron_dirs.go`)
* **Framework Mappings:**
  * **CIS Benchmark:** `CIS 5.1.1` (Ensure cron daemon is enabled), `CIS 5.1.2`-`5.1.7` (Ensure permissions on `/etc/crontab`, `/etc/cron.hourly`, `/etc/cron.daily`, `/etc/cron.weekly`, `/etc/cron.monthly`, `/etc/cron.d` are mode 0700/0600)
  * **NIST SP 800-53:** `CM-6` (Configuration Settings), `SI-4` (Information System Monitoring)
  * **DISA STIG:** `V-230380` through `V-230386` (Cron directories and files must be mode 0700/0600 root-owned)
  * **MITRE ATT&CK:** `T1053.003` (Scheduled Task/Job: Cron)
* **Risk Severity:** **CRITICAL**
* **Vulnerability Condition:** Writable cron table, writable script called by root cron, or permission drift on cron drop-in directory (`chmod 777 /etc/cron.d`).
* **Authoritative Remediation:**
  ```bash
  # Enforce strict ownership and mode 0700/0600 on cron drop-in directories and files
  chown -R root:root /etc/crontab /etc/cron.* /var/spool/cron/crontabs
  chmod 0600 /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/* 2>/dev/null || true
  chmod 0700 /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /var/spool/cron
  ```
* **Verification Command:**
  ```bash
  stat -c "%a %U:%G %n" /etc/crontab /etc/cron.d /etc/cron.*
  ```

---

### 3.2 Systemd Unit Overrides, Timers & Environment Files (`scanners/systemd_overrides.go`, `scanners/env_file.go`)
* **Framework Mappings:**
  * **CIS Benchmark:** `CIS 5.1.9` (Ensure systemd service files and overrides are protected)
  * **NIST SP 800-53:** `CM-6` (Configuration Settings), `SI-7` (Software Integrity)
  * **DISA STIG:** `V-230390` (Systemd unit configuration files must be root-owned and read-only)
  * **MITRE ATT&CK:** `T1543.002` (Create or Modify System Process: Systemd Service)
* **Risk Severity:** **CRITICAL**
* **Vulnerability Condition:** Drop-in directory `/etc/systemd/system/*.service.d/override.conf`, service unit binary target, or `EnvironmentFile=` source file is writable by unprivileged user.
* **Authoritative Remediation:**
  ```bash
  # Fix ownership and permissions on Systemd units, drop-in directories, and environment files
  chown -R root:root /etc/systemd/system/ /lib/systemd/system/ /usr/lib/systemd/system/ /etc/default/ /etc/sysconfig/
  chmod 0755 /etc/systemd/system/
  find /etc/systemd/system/ -type f -exec chmod 0644 {} +
  chmod 0644 /etc/default/* /etc/sysconfig/* 2>/dev/null || true
  # Reload systemd manager configuration
  systemctl daemon-reload
  ```
* **Verification Command:**
  ```bash
  systemctl list-unit-files --state=enabled && systemd-delta
  ```

---

### 3.3 Logrotate Writable Postrotate Hooks (`scanners/logrotate.go`)
* **Framework Mappings:**
  * **CIS Benchmark:** `CIS 4.2.1` (Ensure logrotate configuration files are protected)
  * **NIST SP 800-53:** `AU-9` (Protection of Audit Information), `CM-6` (Configuration Settings)
  * **MITRE ATT&CK:** `T1053` (Scheduled Task/Job)
* **Risk Severity:** **CRITICAL**
* **Vulnerability Condition:** Configuration in `/etc/logrotate.d/` executes postrotate script that is owned or writable by unprivileged users.
* **Authoritative Remediation:**
  ```bash
  # Enforce root ownership and read-only permissions on logrotate configs and scripts
  chown -R root:root /etc/logrotate.conf /etc/logrotate.d/
  chmod 0644 /etc/logrotate.conf /etc/logrotate.d/*
  chown root:root /path/to/postrotate_script && chmod 0755 /path/to/postrotate_script
  ```
* **Verification Command:**
  ```bash
  ls -la /etc/logrotate.d/
  ```

---

## Domain 4: Kernel, Memory & Device Security

### 4.1 Kernel Sysctl Hardening Baselines (`scanners/sysctl.go`, `scanners/kernelconfig.go`)
* **Framework Mappings:**
  * **CIS Benchmark:** `CIS 1.5.1` (Ensure ASLR is enabled), `CIS 1.5.2` (Ensure ptrace_scope is restricted), `CIS 1.5.3` (Ensure kptr_restrict is enabled), `CIS 1.5.4` (Ensure unprivileged eBPF is disabled)
  * **NIST SP 800-53:** `SC-7` (Boundary Protection), `SI-16` (Memory Protection)
  * **DISA STIG:** `V-230370` through `V-230378` (Kernel security parameters must be hardened)
  * **MITRE ATT&CK:** `T1068` (Exploitation for Privilege Escalation)
* **Risk Severity:** **CRITICAL** / **HIGH**
* **Vulnerability Condition:** Weak runtime sysctl parameters exposing kernel pointers, allowing cross-process memory injection, or permitting unprivileged eBPF loading.
* **Authoritative Remediation:**
  ```bash
  # Create persistent kernel hardening configuration
  cat << 'EOF' > /etc/sysctl.d/99-talaria-hardening.conf
  # Talaria Baseline Hardening Configuration
  kernel.kptr_restrict = 2
  kernel.yama.ptrace_scope = 2
  kernel.dmesg_restrict = 1
  kernel.unprivileged_bpf_disabled = 1
  net.core.bpf_jit_harden = 2
  fs.protected_symlinks = 1
  fs.protected_hardlinks = 1
  fs.protected_fifos = 2
  fs.protected_regular = 2
  vm.mmap_min_addr = 65536
  kernel.randomize_va_space = 2
  EOF
  # Apply configuration immediately
  sysctl -p /etc/sysctl.d/99-talaria-hardening.conf
  ```
* **Verification Command:**
  ```bash
  sysctl kernel.kptr_restrict kernel.yama.ptrace_scope kernel.unprivileged_bpf_disabled
  ```

---

### 4.2 Raw Physical & Kernel Memory Device Nodes (`scanners/sysctl.go`)
* **Framework Mappings:**
  * **CIS Benchmark:** `CIS 1.5.3` (Protect kernel memory access)
  * **NIST SP 800-53:** `SI-16` (Memory Protection), `AC-3` (Access Enforcement)
  * **DISA STIG:** `V-230375` (Direct memory device access must be prohibited)
  * **MITRE ATT&CK:** `T1055` (Process Injection / Direct Memory Manipulation)
* **Risk Severity:** **CRITICAL**
* **Vulnerability Condition:** `/dev/mem`, `/dev/kmem`, or `/proc/kcore` is readable or writable by non-root users.
* **Authoritative Remediation:**
  ```bash
  # Enforce strict root-only permissions on raw memory character devices
  chmod 0600 /dev/mem /dev/kmem 2>/dev/null || true
  chmod 0400 /proc/kcore 2>/dev/null || true
  # Ensure CONFIG_STRICT_DEVMEM=y and CONFIG_IO_STRICT_DEVMEM=y in kernel boot args
  ```
* **Verification Command:**
  ```bash
  ls -la /dev/mem /dev/kmem /proc/kcore 2>/dev/null
  ```

---

### 4.3 Modprobe Kernel Module Execution Hooks (`scanners/modprobe.go`)
* **Framework Mappings:**
  * **CIS Benchmark:** `CIS 1.1.1.1`-`1.1.1.8` (Ensure unused filesystem/network kernel modules are disabled and configuration files are root-owned)
  * **NIST SP 800-53:** `CM-7` (Least Functionality), `SI-7` (Software Integrity)
  * **DISA STIG:** `V-230240` (Modprobe configuration must be root-owned and read-only)
  * **MITRE ATT&CK:** `T1547.006` (Boot or Logon Autostart Execution: Kernel Modules and Extensions)
* **Risk Severity:** **CRITICAL**
* **Vulnerability Condition:** Rule files under `/etc/modprobe.d/` or `/lib/modprobe.d/` are writable, or an `install <module> <target>` hook points to an unprivileged writable executable.
* **Authoritative Remediation:**
  ```bash
  # Enforce root ownership and read-only permissions on modprobe rule directories
  chown -R root:root /etc/modprobe.d/ /lib/modprobe.d/
  chmod 0755 /etc/modprobe.d/
  chmod 0644 /etc/modprobe.d/*.conf /lib/modprobe.d/*.conf 2>/dev/null || true
  # Ensure all install hook target binaries are root-owned and non-writable
  ```
* **Verification Command:**
  ```bash
  ls -la /etc/modprobe.d/
  ```

---

### 4.4 Udev Event Rules & Execution Targets (`scanners/udev.go`)
* **Framework Mappings:**
  * **CIS Benchmark:** `CIS 1.1.23` (Ensure udev configuration is root-owned and mode 0644)
  * **NIST SP 800-53:** `CM-6` (Configuration Settings), `SI-4` (System Monitoring)
  * **MITRE ATT&CK:** `T1546.004` (Event Triggered Execution: Unix Shell Configuration / Udev Event Execution)
* **Risk Severity:** **CRITICAL**
* **Vulnerability Condition:** Rule file in `/etc/udev/rules.d/` is writable or executes `RUN+=` or `PROGRAM=` scripts owned/writable by unprivileged users.
* **Authoritative Remediation:**
  ```bash
  # Enforce root ownership and read-only permissions on udev rules and scripts
  chown -R root:root /etc/udev/rules.d/ /lib/udev/rules.d/
  chmod 0755 /etc/udev/rules.d/
  chmod 0644 /etc/udev/rules.d/*.rules
  # Reload udev rules
  udevadm control --reload-rules && udevadm trigger
  ```
* **Verification Command:**
  ```bash
  ls -la /etc/udev/rules.d/
  ```

---

## Domain 5: Filesystem & Mount Point Hardening

### 5.1 Critical System File Permissions (`scanners/filepermissions.go`, `scanners/writeable.go`)
* **Framework Mappings:**
  * **CIS Benchmark:** `CIS 6.2.1` (`/etc/passwd`), `CIS 6.2.2` (`/etc/shadow`), `CIS 6.2.3` (`/etc/group`), `CIS 6.2.4` (`/etc/gshadow`), `CIS 6.2.5` (`/etc/shadow-`), `CIS 6.2.6` (`/etc/gshadow-`), `CIS 6.2.11` (Ensure no world-writable files exist)
  * **NIST SP 800-53:** `AC-6` (Least Privilege), `CM-6` (Configuration Settings)
  * **DISA STIG:** `V-230280` through `V-230288` (System authentication files must be root:root/root:shadow and mode 0644/0600/0640)
  * **MITRE ATT&CK:** `T1565` (Data Manipulation), `T1078` (Valid Accounts)
* **Risk Severity:** **CRITICAL**
* **Vulnerability Condition:** World-writable system binaries (`/bin`, `/sbin`, `/usr/bin`), or writable `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`.
* **Authoritative Remediation:**
  ```bash
  # Standardize core identity file permissions
  chmod 0644 /etc/passwd /etc/group
  chown root:root /etc/passwd /etc/group
  chmod 0640 /etc/shadow /etc/gshadow
  chown root:shadow /etc/shadow /etc/gshadow 2>/dev/null || chown root:root /etc/shadow /etc/gshadow
  chmod 0440 /etc/sudoers /etc/sudoers.d/* 2>/dev/null || true
  chown -R root:root /etc/sudoers /etc/sudoers.d/
  # Remove world-write bits from system binaries
  chmod -R o-w /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin
  ```
* **Verification Command:**
  ```bash
  stat -c "%a %U:%G %n" /etc/passwd /etc/shadow /etc/group /etc/gshadow
  ```

---

### 5.2 Shared Memory & Temporary Mount Flags (`scanners/mounts.go`)
* **Framework Mappings:**
  * **CIS Benchmark:** `CIS 1.1.2` (`/tmp` nodev), `CIS 1.1.3` (`/tmp` nosuid), `CIS 1.1.4` (`/tmp` noexec), `CIS 1.1.5` (`/dev/shm` nodev), `CIS 1.1.6` (`/dev/shm` nosuid), `CIS 1.1.7` (`/dev/shm` noexec)
  * **NIST SP 800-53:** `CM-6` (Configuration Settings), `MP-2` (Media Access)
  * **DISA STIG:** `V-230230` through `V-230238` (Temporary partitions must enforce nodev, nosuid, noexec)
  * **MITRE ATT&CK:** `T1055` (Process Injection / Execution from Temp Directories)
* **Risk Severity:** **HIGH** / **MEDIUM**
* **Vulnerability Condition:** `/dev/shm`, `/tmp`, or `/var/tmp` mounted without `noexec`, `nosuid`, or `nodev` options, allowing direct binary staging and execution.
* **Authoritative Remediation:**
  ```bash
  # Update /etc/fstab to enforce nodev, nosuid, noexec on temporary partitions
  # /dev/shm:
  mount -o remount,nodev,nosuid,noexec /dev/shm
  # Update /etc/fstab entry:
  # tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0
  ```
* **Verification Command:**
  ```bash
  mount | grep -E '(/tmp|/dev/shm|/var/tmp)'
  ```

---

### 5.3 System / User PATH Variable Hijacking (`scanners/path_hijack.go`)
* **Framework Mappings:**
  * **CIS Benchmark:** `CIS 5.4.4` (Ensure root PATH integrity and no '.' or world-writable directories exist)
  * **NIST SP 800-53:** `CM-6` (Configuration Settings)
  * **DISA STIG:** `V-230520` (System PATH must not contain relative or world-writable paths)
  * **MITRE ATT&CK:** `T1574.007` (Hijack Execution Flow: Path Interception by PATH Environment Variable)
* **Risk Severity:** **HIGH** / **CRITICAL**
* **Vulnerability Condition:** Current or root `$PATH` contains relative directories (`.` or empty entry) or world-writable directories (e.g. `/tmp`).
* **Authoritative Remediation:**
  ```bash
  # Audit and sanitize /etc/profile, /etc/environment, /etc/bash.bashrc, /root/.bashrc
  # Ensure standard clean path:
  export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
  # Enforce root ownership and mode 0755 on all directories in system PATH
  ```
* **Verification Command:**
  ```bash
  echo "$PATH" | tr ':' '\n' | while read d; do [ -d "$d" ] && stat -c "%a %U %n" "$d"; done
  ```

---

### 5.4 Network File System (NFS) Root Squashing (`scanners/nfs.go`)
* **Framework Mappings:**
  * **CIS Benchmark:** `CIS 2.2.7` (Ensure NFS exports enforce root_squash)
  * **NIST SP 800-53:** `AC-6` (Least Privilege), `SC-8` (Transmission Confidentiality and Integrity)
  * **DISA STIG:** `V-230300` (NFS exports must enforce root_squash)
  * **MITRE ATT&CK:** `T1134` (Access Token Manipulation)
* **Risk Severity:** **CRITICAL**
* **Vulnerability Condition:** `/etc/exports` defines shares with `no_root_squash`, allowing remote root clients to create SUID binaries on the exported filesystem.
* **Authoritative Remediation:**
  ```bash
  # Replace no_root_squash with root_squash in /etc/exports
  sed -i 's/no_root_squash/root_squash/g' /etc/exports
  exportfs -ra
  ```
* **Verification Command:**
  ```bash
  showmount -e 127.0.0.1 2>/dev/null || cat /etc/exports
  ```

---

## Domain 6: Credentials, Tokens & In-Memory Secrets

### 6.1 Exposed Configuration Passwords & Cloud Tokens (`scanners/secrets.go`)
* **Framework Mappings:**
  * **CIS Benchmark:** `CIS 5.4.3` (Ensure credentials and sensitive files are not stored unencrypted)
  * **NIST SP 800-53:** `IA-5(1)` (Password-Based Authentication), `SC-28` (Protection of Information at Rest)
  * **DISA STIG:** `V-230410` (Unencrypted passwords must not be stored in clear text)
  * **MITRE ATT&CK:** `T1552.001` (Unsecured Credentials: Credentials In Files)
* **Risk Severity:** **CRITICAL** / **HIGH**
* **Vulnerability Condition:** Plaintext API keys, AWS credentials, database passwords, or private keys found in readable config files (`/etc`, `/var/www`, `/opt`, `/home`).
* **Authoritative Remediation:**
  ```bash
  # Restrict permissions on sensitive configuration files to owner only
  chmod 0600 /path/to/credentials.conf /home/user/.aws/credentials
  # Migrate hardcoded credentials to a secure secret store (e.g. HashiCorp Vault, AWS Secrets Manager)
  ```
* **Verification Command:**
  ```bash
  stat -c "%a %U:%G %n" /path/to/credentials.conf
  ```

---

### 6.2 Process Environment Table Credential Leakage (`scanners/proc_env.go`, `scanners/processes.go`)
* **Framework Mappings:**
  * **NIST SP 800-53:** `IA-5` (Authenticator Management), `SC-28` (Protection of Information at Rest)
  * **DISA STIG:** `V-230420` (Process environment variables must not expose authentication secrets)
  * **MITRE ATT&CK:** `T1552.003` (Unsecured Credentials: Bash History / Process Memory)
* **Risk Severity:** **HIGH** / **CRITICAL**
* **Vulnerability Condition:** High-privilege processes expose database passwords (`PGPASSWORD`, `MYSQL_PWD`) or cloud tokens in `/proc/[pid]/environ`.
* **Authoritative Remediation:**
  ```bash
  # Restrict /proc access with hidepid mount option
  mount -o remount,rw,hidepid=2 /proc
  # Update /etc/fstab entry:
  # proc /proc proc defaults,hidepid=2,gid=proc 0 0
  # Configure services to use systemd LoadCredential= or file-based secret passing
  ```
* **Verification Command:**
  ```bash
  mount | grep hidepid
  ```

---

### 6.3 SSH Authorized Keys & Private Key Permissions (`scanners/ssh_keys.go`)
* **Framework Mappings:**
  * **CIS Benchmark:** `CIS 5.2.1`-`5.2.20` (SSH Server Configuration), `CIS 6.2.7`-`6.2.10` (Ensure user .ssh directory and file permissions are mode 0700/0600)
  * **NIST SP 800-53:** `AC-17` (Remote Access), `IA-5` (Authenticator Management)
  * **DISA STIG:** `V-230400` (SSH private keys and authorized_keys permissions must be restricted)
  * **MITRE ATT&CK:** `T1098.004` (Account Manipulation: SSH Authorized Keys), `T1552.004` (Private Keys)
* **Risk Severity:** **CRITICAL**
* **Vulnerability Condition:** `authorized_keys` file is writable by unprivileged users, or private SSH keys (`id_rsa`, `id_ed25519`) are world/group-readable.
* **Authoritative Remediation:**
  ```bash
  # Enforce strict user ownership and permissions on SSH configurations
  chown -R <username>:<username> /home/<username>/.ssh
  chmod 0700 /home/<username>/.ssh
  chmod 0600 /home/<username>/.ssh/authorized_keys /home/<username>/.ssh/id_*
  chmod 0644 /home/<username>/.ssh/*.pub 2>/dev/null || true
  ```
* **Verification Command:**
  ```bash
  stat -c "%a %U:%G %n" ~/.ssh ~/.ssh/authorized_keys ~/.ssh/id_* 2>/dev/null
  ```

---

## Domain 7: Package Management, Namespaces & Kernel CVEs

### 7.1 Package Manager Hook Drop-in Security (`scanners/packages.go`)
* **Framework Mappings:**
  * **CIS Benchmark:** `CIS 1.2.1`-`1.2.5` (Ensure package manager repositories and GPG keys are configured and verified)
  * **NIST SP 800-53:** `SI-2` (Flaw Remediation), `SI-7` (Software Integrity)
  * **DISA STIG:** `V-230260` (Package manager configuration and hook directories must be root-owned and read-only)
  * **MITRE ATT&CK:** `T1072` (Software Deployment Tools)
* **Risk Severity:** **CRITICAL**
* **Vulnerability Condition:** APT drop-in `/etc/apt/apt.conf.d/`, DNF/YUM plugin `/etc/dnf/plugins/`, or Pacman hook `/etc/pacman.d/hooks/` is writable by unprivileged user.
* **Authoritative Remediation:**
  ```bash
  # Enforce root ownership and read-only permissions on package manager configuration directories
  chown -R root:root /etc/apt/ /etc/dpkg/ /etc/yum.repos.d/ /etc/dnf/ /etc/pacman.d/
  chmod -R 0755 /etc/apt/apt.conf.d/ /etc/dpkg/dpkg.cfg.d/ /etc/dnf/plugins/ /etc/pacman.d/hooks/ 2>/dev/null || true
  find /etc/apt/ /etc/yum.repos.d/ -type f -exec chmod 0644 {} +
  ```
* **Verification Command:**
  ```bash
  ls -ld /etc/apt/apt.conf.d/ /etc/dpkg/dpkg.cfg.d/
  ```

---

### 7.2 Unprivileged User Namespaces & SubUID Allocations (`scanners/subuid.go`)
* **Framework Mappings:**
  * **CIS Benchmark:** `CIS 1.5.3` (Restrict unprivileged user namespaces)
  * **NIST SP 800-53:** `AC-6` (Least Privilege), `SC-7` (Boundary Protection)
  * **MITRE ATT&CK:** `T1068` (Exploitation for Privilege Escalation)
* **Risk Severity:** **HIGH**
* **Vulnerability Condition:** Kernel allows unprivileged user namespaces (`kernel.unprivileged_userns_clone = 1`), enabling unprivileged users to create isolated network/user namespaces to exploit kernel subsystem flaws (e.g. `act_pedit`, `netfilter`, `overlayfs`).
* **Authoritative Remediation:**
  ```bash
  # Restrict unprivileged user namespace creation if container isolation is not required
  echo "kernel.unprivileged_userns_clone = 0" > /etc/sysctl.d/99-userns.conf
  sysctl -p /etc/sysctl.d/99-userns.conf 2>/dev/null || true
  # Or on modern kernels using user.max_user_namespaces:
  # sysctl -w user.max_user_namespaces=0
  ```
* **Verification Command:**
  ```bash
  sysctl kernel.unprivileged_userns_clone user.max_user_namespaces 2>/dev/null
  ```

---

### 7.3 Kernel & Software Known Vulnerabilities (`scanners/vulnerabilities.go`)
* **Framework Mappings:**
  * **CIS Benchmark:** `CIS 1.2.2` (Ensure updates, patches, and additional security software are installed)
  * **NIST SP 800-53:** `SI-2` (Flaw Remediation)
  * **DISA STIG:** `V-230250` (The operating system must be maintained at a supported release level)
  * **MITRE ATT&CK:** `T1068` (Exploitation for Privilege Escalation)
* **Risk Severity:** **CRITICAL** (Dirty COW, PwnKit, Dirty Pipe, CVE-2024-1086, etc.)
* **Vulnerability Condition:** Kernel or critical setuid utility version matches an unpatched local privilege escalation CVE range.
* **Authoritative Remediation:**
  ```bash
  # Apply all vendor security updates and reboot system to load patched kernel
  # On Debian/Ubuntu:
  apt-get update && apt-get dist-upgrade -y
  # On RHEL/Rocky/Fedora:
  dnf upgrade --security -y
  ```
* **Verification Command:**
  ```bash
  uname -r
  ```

---

## Domain 8: Container, Cloud & Perimeter Infrastructure

### 8.1 Container Escapes & Exposed Docker Sockets (`scanners/container.go`)
* **Framework Mappings:**
  * **CIS Docker Benchmark:** `CIS 2.1` (Restrict network access to Docker daemon), `CIS 5.4` (Do not run privileged containers)
  * **CIS Kubernetes Benchmark:** `CIS 5.2.1` (Minimize admission of privileged containers)
  * **NIST SP 800-53:** `AC-6` (Least Privilege), `SC-7` (Boundary Protection)
  * **MITRE ATT&CK:** `T1611` (Escape to Host)
* **Risk Severity:** **CRITICAL**
* **Vulnerability Condition:** Container is running in `--privileged` mode, has dangerous capabilities (`CAP_SYS_ADMIN`), or has `/var/run/docker.sock` mounted inside.
* **Authoritative Remediation:**
  ```bash
  # Remove Docker socket mounts from container specs
  # Disallow privileged container mode in Kubernetes PodSecurityStandards:
  # securityContext:
  #   privileged: false
  #   allowPrivilegeEscalation: false
  #   capabilities:
  #     drop: ["ALL"]
  ```
* **Verification Command:**
  ```bash
  capsh --print 2>/dev/null || cat /proc/1/status | grep CapEff
  ```

---

### 8.2 Kubernetes In-Cluster Tokens & Cloud IMDS (`scanners/cloud_meta.go`)
* **Framework Mappings:**
  * **CIS Kubernetes Benchmark:** `CIS 5.1.6` (Ensure ServiceAccount tokens are only mounted where necessary)
  * **NIST SP 800-53:** `AC-6` (Least Privilege), `SC-28` (Protection of Information at Rest)
  * **MITRE ATT&CK:** `T1552.005` (Unsecured Credentials: Cloud Instance Metadata API)
* **Risk Severity:** **CRITICAL**
* **Vulnerability Condition:** Default ServiceAccount token mounted with administrative cluster roles, or Cloud IMDSv1 reachable without hop-limit / session token constraints.
* **Authoritative Remediation:**
  ```bash
  # Disable automatic ServiceAccount token mounting in Kubernetes:
  # automountServiceAccountToken: false
  # Enforce AWS IMDSv2 (Session token required) and hop limit = 1:
  # aws ec2 modify-instance-metadata-options --instance-id <id> --http-tokens required --http-put-response-hop-limit 1
  ```
* **Verification Command:**
  ```bash
  curl -s -m 1 http://169.254.169.254/latest/meta-data/
  ```

---

### 8.3 System Audit Daemons & Logging Subsystems (`scanners/auditd.go`)
* **Framework Mappings:**
  * **CIS Benchmark:** `CIS 4.1.1` (Ensure auditd service is enabled and active), `CIS 4.1.3`-`4.1.17` (Audit rule baselines)
  * **NIST SP 800-53:** `AU-2` (Event Logging), `AU-12` (Audit Generation)
  * **DISA STIG:** `V-230320` through `V-230355` (The system must generate audit records for privileged activities)
  * **MITRE ATT&CK:** `T1562.001` (Impair Defenses: Disable or Modify Tools)
* **Risk Severity:** **HIGH** (if auditd disabled or 0 rules loaded)
* **Vulnerability Condition:** `auditd` daemon is stopped or active without security audit rules monitoring privileged syscalls (`execve`, `chmod`, `setuid`).
* **Authoritative Remediation:**
  ```bash
  # Enable and start audit daemon
  systemctl enable --now auditd
  # Load standard CIS audit rules
  augenrules --load
  ```
* **Verification Command:**
  ```bash
  auditctl -s && auditctl -l | head -n 10
  ```

---

## Master Remediation Code Implementation Reference

When implementing the **Remediation Engine (`core/remediation.go`)** in Phase 2, the following mapping dictionary will be used:

```
┌───────────────────────────┬──────────────────────────────────────────┬─────────────────────────────┐
│ Scanner Identifier        │ Default CIS Benchmark ID                 │ Primary Remediation Action  │
├───────────────────────────┼──────────────────────────────────────────┼─────────────────────────────┤
│ suid                      │ CIS-Linux-6.1.13                         │ chmod u-s <path>            │
│ sgid                      │ CIS-Linux-6.1.14                         │ chmod g-s <path>            │
│ capabilities              │ CIS-Linux-6.1.15                         │ setcap -r <path>            │
│ sudo                      │ CIS-Linux-5.3.4                          │ visudo -f /etc/sudoers      │
│ polkit                    │ CIS-Linux-5.3.5                          │ chmod 0644 <rule>           │
│ pam                       │ CIS-Linux-5.3.3                          │ chmod 0644 /etc/pam.d/*     │
│ cronjobs                  │ CIS-Linux-5.1.2                          │ chmod 0600 /etc/crontab     │
│ crondirs                  │ CIS-Linux-5.1.7                          │ chmod 0700 /etc/cron.d      │
│ systemd_overrides         │ CIS-Linux-5.1.9                          │ chmod 0644 <override.conf>  │
│ env_file                  │ CIS-Linux-5.1.9                          │ chmod 0640 <env_file>       │
│ ld_nss                    │ CIS-Linux-5.4.2                          │ chmod 0755 <lib_dir>        │
│ elfrpath                  │ CIS-Linux-5.4.2                          │ chrpath -d <binary>         │
│ modprobe                  │ CIS-Linux-1.1.1                          │ chmod 0644 /etc/modprobe.d/ │
│ udev                      │ CIS-Linux-1.1.23                         │ chmod 0644 /etc/udev/rules/ │
│ filepermissions           │ CIS-Linux-6.2.1                          │ chmod 0644 /etc/passwd      │
│ writeable                 │ CIS-Linux-6.2.11                         │ chmod o-w <file>            │
│ mounts                    │ CIS-Linux-1.1.5                          │ mount -o remount,nodev,nosuid,noexec /dev/shm │
│ path_hijack               │ CIS-Linux-5.4.4                          │ export PATH=/usr/bin:/bin   │
│ nfs                       │ CIS-Linux-2.2.7                          │ sed -i s/no_root_squash/root_squash/ /etc/exports │
│ sysctl                    │ CIS-Linux-1.5.2                          │ sysctl -w <key>=<val>       │
│ secrets                   │ CIS-Linux-5.4.3                          │ chmod 0600 <secret_file>    │
│ proc_env                  │ NIST-SC-28                               │ mount -o remount,hidepid=2 /proc │
│ ssh_keys                  │ CIS-Linux-5.2.20                         │ chmod 0600 ~/.ssh/auth_keys │
│ packages                  │ CIS-Linux-1.2.1                          │ chmod 0755 /etc/apt/apt.conf.d/ │
│ subuid                    │ CIS-Linux-1.5.3                          │ sysctl -w kernel.unprivileged_userns_clone=0 │
│ container                 │ CIS-Docker-5.4                           │ securityContext.privileged: false │
│ cloud_meta                │ CIS-K8s-5.1.6                            │ automountServiceAccountToken: false │
│ auditd                    │ CIS-Linux-4.1.1                          │ systemctl enable --now auditd │
└───────────────────────────┴──────────────────────────────────────────┴─────────────────────────────┘
```

---
*Standards verification source date: August 2026.*
