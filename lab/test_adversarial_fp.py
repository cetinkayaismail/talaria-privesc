#!/usr/bin/env python3
"""
Talaria — Adversarial False-Positive (FP) Stress Test Suite
Deploys 15 deceptive, benign, and edge-case scenarios specifically designed
to bait heuristic scanners into reporting false vulnerabilities.

A test PASSES if Talaria correctly ignores the deception or classifies it as safe.
A test FAILS (FP DETECTED) if Talaria flags the benign condition as dangerous/exploitable.
"""

import json
import subprocess
import sys
import time

BINARY_HOST_PATH = "/home/ismail/Desktop/go_projects/talaria/bin/talaria"
DOCKER_IMAGE = "talaria-lab:latest"

ADVERSARIAL_CASES = [
    {
        "id": "FP-01",
        "name": "Deceptive CSS Asset Matching Substring ('box-shadow.css')",
        "category": "secrets",
        "setup": "mkdir -p /home/tester/assets && echo 'body { box-shadow: 0 4px 8px #000; }' > /home/tester/assets/box-shadow.css && chmod 644 /home/tester/assets/box-shadow.css && chown -R tester:tester /home/tester/assets",
        "assert_no_fp": lambda r: not any("box-shadow.css" in s.get("path", "") for s in r.get("secrets", []))
    },
    {
        "id": "FP-02",
        "name": "Public Key File ('id_rsa.pub') Should Not Flag as Private Key",
        "category": "secrets",
        "setup": "mkdir -p /home/tester/.ssh && echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC... tester@lab' > /home/tester/.ssh/id_rsa.pub && chmod 644 /home/tester/.ssh/id_rsa.pub && chown -R tester:tester /home/tester/.ssh",
        "assert_no_fp": lambda r: not any("id_rsa.pub" in s.get("path", "") and s.get("type", "") != "Public Key" for s in r.get("secrets", []))
    },
    {
        "id": "FP-03",
        "name": "Current User's Own Tmux Session (Cannot Hijack Yourself)",
        "category": "sessions",
        "setup": "mkdir -p /tmp/tmux-1000 && touch /tmp/tmux-1000/default && chown -R tester:tester /tmp/tmux-1000 && chmod 777 /tmp/tmux-1000/default",
        "assert_no_fp": lambda r: not any("tmux-1000" in s.get("path", "") and s.get("is_dangerous") for s in r.get("session_hijack", []))
    },
    {
        "id": "FP-04",
        "name": "Symlinked Masked Service to /dev/null",
        "category": "cronjobs",
        "setup": "mkdir -p /etc/systemd/system && ln -sf /dev/null /etc/systemd/system/masked.service",
        "assert_no_fp": lambda r: not any("masked.service" in t.get("path", "") and t.get("is_dangerous") for t in r.get("systemd_timers", []))
    },
    {
        "id": "FP-05",
        "name": "Symlink with 0777 Perms Pointing to Root Read-Only Script",
        "category": "cronjobs",
        "setup": "mkdir -p /opt/lab /etc/cron.d && echo '#!/bin/bash\\nexit 0' > /opt/lab/ro_script.sh && chmod 555 /opt/lab/ro_script.sh && chown root:root /opt/lab/ro_script.sh && ln -sf /opt/lab/ro_script.sh /etc/cron.d/symlink_cron",
        "assert_no_fp": lambda r: not any("symlink_cron" in c.get("command", "") and c.get("is_dangerous") for c in r.get("cron_jobs", []))
    },
    {
        "id": "FP-06",
        "name": "Commented-Out Vulnerable Cron Line (# * * * * * root /tmp/evil.sh)",
        "category": "cronjobs",
        "setup": "mkdir -p /etc/cron.d && echo '# * * * * * root /tmp/evil.sh' > /etc/cron.d/commented_cron",
        "assert_no_fp": lambda r: not any("/tmp/evil.sh" in c.get("command", "") for c in r.get("cron_jobs", []))
    },
    {
        "id": "FP-07",
        "name": "Standard Secure /etc/passwd Perms (0644 World-Readable)",
        "category": "filepermissions",
        "setup": "chmod 644 /etc/passwd",
        "assert_no_fp": lambda r: not any(f.get("path") == "/etc/passwd" and f.get("is_dangerous") for f in r.get("file_permissions", []))
    },
    {
        "id": "FP-08",
        "name": "Standard Secure /etc/shadow Perms (0600 Root-Only Unreadable)",
        "category": "filepermissions",
        "setup": "chmod 600 /etc/shadow && chown root:root /etc/shadow",
        "assert_no_fp": lambda r: not any(f.get("path") == "/etc/shadow" and f.get("can_write") for f in r.get("file_permissions", [])) and not any("/etc/shadow" in s.get("path", "") for s in r.get("secrets", []))
    },
    {
        "id": "FP-09",
        "name": "Commented-Out Library Path in /etc/ld.so.conf.d (# /tmp/libs)",
        "category": "ldnss",
        "setup": "mkdir -p /etc/ld.so.conf.d /tmp/fake_libs && chmod 777 /tmp/fake_libs && echo '# /tmp/fake_libs' > /etc/ld.so.conf.d/commented.conf",
        "assert_no_fp": lambda r: not any("/tmp/fake_libs" in l.get("path", "") for l in r.get("ld_nss_results", []))
    },
    {
        "id": "FP-10",
        "name": "Secure Root Sudo Timestamp Directory (/var/run/sudo/ts 0700)",
        "category": "sudo",
        "setup": "mkdir -p /var/run/sudo/ts && chmod 700 /var/run/sudo/ts && chown root:root /var/run/sudo/ts",
        "assert_no_fp": lambda r: not any(t.get("vector") == "Writable Sudo Timestamp Directory" for t in r.get("sudo_tokens", []))
    },
    {
        "id": "FP-11",
        "name": "Standard Read-Only Drop-in /etc/sudoers.d/README (0440 Root)",
        "category": "sudo",
        "setup": "mkdir -p /etc/sudoers.d && echo '# Sudoers Drop-in' > /etc/sudoers.d/README && chmod 440 /etc/sudoers.d/README && chown root:root /etc/sudoers.d/README",
        "assert_no_fp": lambda r: not any(t.get("vector") == "Writable /etc/sudoers.d Directory" for t in r.get("sudo_tokens", []))
    },
    {
        "id": "FP-12",
        "name": "Standard Benign System Unix Sockets (syslog, systemd-notify)",
        "category": "sockets",
        "setup": "python3 -c \"import socket; s=socket.socket(socket.AF_UNIX); s.bind('/var/run/dev-log')\" 2>/dev/null || true",
        "assert_no_fp": lambda r: not any(s.get("path") == "/var/run/dev-log" and s.get("is_dangerous") for s in r.get("sockets", []))
    },
    {
        "id": "FP-13",
        "name": "Standard Cron Environment Declarations (SHELL, PATH)",
        "category": "cronjobs",
        "setup": "mkdir -p /etc/cron.d && printf 'SHELL=/bin/bash\\nPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin\\n' > /etc/cron.d/env_cron",
        "assert_no_fp": lambda r: not any(c.get("is_dangerous") for c in r.get("cron_jobs", []) if "SHELL=" in c.get("command", ""))
    },
    {
        "id": "FP-14",
        "name": "Deceptive Documentation Config File (/usr/share/doc/sample-shadow.conf)",
        "category": "secrets",
        "setup": "mkdir -p /usr/share/doc/sample && echo 'shadow_file=/etc/shadow' > /usr/share/doc/sample/sample-shadow.conf && chmod 644 /usr/share/doc/sample/sample-shadow.conf",
        "assert_no_fp": lambda r: not any("sample-shadow.conf" in s.get("path", "") for s in r.get("secrets", []))
    },
    {
        "id": "FP-15",
        "name": "Benign Public API Environment Variable (REACT_APP_PUBLIC_KEY)",
        "category": "procenv",
        "setup": "su tester -c 'export REACT_APP_PUBLIC_KEY=\"public_live_1234567890\" && (sleep 30 &)'",
        "assert_no_fp": lambda r: not any(p.get("key") == "REACT_APP_PUBLIC_KEY" for p in r.get("proc_env_results", []))
    }
]

def run_single_adversarial_test(test):
    t0 = time.time()
    setup_cmd = test["setup"]
    
    cmd = [
        "docker", "run", "--rm",
        "-t",
        "--user", "root",
        "-v", f"{BINARY_HOST_PATH}:/usr/local/bin/talaria:ro",
        DOCKER_IMAGE,
        "bash", "-c",
        f"{setup_cmd} && su tester -c '/usr/local/bin/talaria -o /tmp/rep.json --format json >/dev/null 2>&1' && cat /tmp/rep.json"
    ]
    
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=25)
        duration_ms = int((time.time() - t0) * 1000)
        
        if proc.returncode != 0:
            return {
                "id": test["id"],
                "name": test["name"],
                "category": test["category"],
                "status": "ERROR",
                "reason": f"Container exit code {proc.returncode}: {proc.stderr[:100]}",
                "duration_ms": duration_ms
            }
            
        raw_stdout = proc.stdout.replace("\r\n", "\n").replace("\r", "")
        json_start = raw_stdout.find("{")
        json_end = raw_stdout.rfind("}")
        if json_start == -1 or json_end == -1:
            return {
                "id": test["id"],
                "name": test["name"],
                "category": test["category"],
                "status": "ERROR",
                "reason": "No JSON output found",
                "duration_ms": duration_ms
            }
            
        report = json.loads(raw_stdout[json_start:json_end+1])
        no_fp = test["assert_no_fp"](report)
        
        return {
            "id": test["id"],
            "name": test["name"],
            "category": test["category"],
            "status": "PASS (NO FP)" if no_fp else "FAIL (FP TRIGGERED)",
            "reason": "Correctly ignored deception" if no_fp else "Talaria fell for the deception and reported a False Positive!",
            "duration_ms": duration_ms
        }
    except Exception as e:
        return {
            "id": test["id"],
            "name": test["name"],
            "category": test["category"],
            "status": "ERROR",
            "reason": str(e)[:100],
            "duration_ms": int((time.time() - t0) * 1000)
        }

def main():
    print(f"[+] Starting Talaria Adversarial False-Positive (FP) Stress Suite ({len(ADVERSARIAL_CASES)} cases)...")
    results = []
    
    for i, test in enumerate(ADVERSARIAL_CASES, 1):
        sys.stdout.write(f"  [{i:02d}/{len(ADVERSARIAL_CASES):02d}] Stress Testing {test['id']}: {test['name']} ... ")
        sys.stdout.flush()
        res = run_single_adversarial_test(test)
        results.append(res)
        if "PASS" in res["status"]:
            print(f"🛡️ {res['status']} ({res['duration_ms']}ms)")
        else:
            print(f"⚠️ {res['status']} ({res['duration_ms']}ms) - {res['reason']}")
            
    clean = sum(1 for r in results if "PASS" in r["status"])
    fps = sum(1 for r in results if "FAIL" in r["status"])
    total = len(results)
    
    print("\n" + "="*80)
    print(f"ADVERSARIAL FP RESILIENCE: {clean}/{total} CLEAN ({(clean/total)*100:.1f}%) | False Positives Triggered: {fps}")
    print("="*80)
    
    with open("lab/adversarial_fp_results.json", "w") as f:
        json.dump(results, f, indent=2)
    print("[+] Results saved to lab/adversarial_fp_results.json")

if __name__ == "__main__":
    main()
