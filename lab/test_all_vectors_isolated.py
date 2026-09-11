#!/usr/bin/env python3
"""
Talaria — Comprehensive Isolated Multi-Vector Test Suite
Runs each privilege escalation vector individually inside an isolated Docker container,
validates that Talaria detects it, and compiles a comprehensive test report.
"""

import json
import subprocess
import sys
import time

BINARY_HOST_PATH = "/home/ismail/Desktop/go_projects/talaria/bin/talaria"
DOCKER_IMAGE = "talaria-lab:latest"

VECTORS = [
    {
        "id": "VEC-01",
        "name": "SUID Binary Exploitation (GTFOBins)",
        "module": "suid",
        "setup": "cp /usr/bin/find /tmp/find && chmod 4755 /tmp/find",
        "verify": lambda r: any(s.get("path") == "/tmp/find" and s.get("is_dangerous") for s in r.get("suid", []))
    },
    {
        "id": "VEC-02",
        "name": "SGID Binary Exploitation (Group Escalation)",
        "module": "sgid",
        "setup": "groupadd -f shadow_test && cp /usr/bin/find /usr/local/bin/find_sgid && chown root:shadow_test /usr/local/bin/find_sgid && chmod 2755 /usr/local/bin/find_sgid",
        "verify": lambda r: any(s.get("path") == "/usr/local/bin/find_sgid" for s in r.get("sgid", []))
    },
    {
        "id": "VEC-03",
        "name": "Linux Capabilities (cap_setuid+ep)",
        "module": "capabilities",
        "setup": "cp /usr/bin/python3 /usr/local/bin/python_cap && setcap cap_setuid+ep /usr/local/bin/python_cap",
        "verify": lambda r: any("python_cap" in c.get("path", "") and c.get("is_dangerous") for c in r.get("capabilities", []))
    },
    {
        "id": "VEC-04",
        "name": "Sudo NOPASSWD Rule",
        "module": "sudo",
        "setup": "echo 'tester ALL=(ALL) NOPASSWD: /usr/bin/find' >> /etc/sudoers",
        "verify": lambda r: any(s.get("no_password") and "/usr/bin/find" in s.get("command", "") for s in r.get("sudo_privileges", []))
    },
    {
        "id": "VEC-05",
        "name": "Sudo LD_PRELOAD env_keep Injection",
        "module": "sudo",
        "setup": "echo 'Defaults env_keep += \"LD_PRELOAD\"' >> /etc/sudoers && echo 'tester ALL=(ALL) NOPASSWD: /bin/true' >> /etc/sudoers",
        "verify": lambda r: any(s.get("has_ld_preload") for s in r.get("sudo_privileges", []))
    },
    {
        "id": "VEC-06",
        "name": "Active Sudo Timestamp Token Reuse",
        "module": "sudo",
        "setup": "echo 'tester ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers",
        "verify": lambda r: any(t.get("vector") == "Active Sudo Session Token" and t.get("is_dangerous") for t in r.get("sudo_tokens", []))
    },
    {
        "id": "VEC-07",
        "name": "Writable Sudo Timestamp Directory (/var/run/sudo/ts)",
        "module": "sudo",
        "setup": "mkdir -p /var/run/sudo/ts && chmod 777 /var/run/sudo/ts",
        "verify": lambda r: any(t.get("vector") == "Writable Sudo Timestamp Directory" for t in r.get("sudo_tokens", []))
    },
    {
        "id": "VEC-08",
        "name": "Writable /etc/sudoers.d/ Directory",
        "module": "sudo",
        "setup": "chmod 777 /etc/sudoers.d",
        "verify": lambda r: any(t.get("vector") == "Writable /etc/sudoers.d Directory" for t in r.get("sudo_tokens", []))
    },
    {
        "id": "VEC-09",
        "name": "TIOCSTI Terminal Command Injection (/dev/pts)",
        "module": "sudo",
        "setup": "chmod 666 /dev/pts/0",
        "verify": lambda r: any("TIOCSTI" in t.get("vector", "") for t in r.get("sudo_tokens", []))
    },
    {
        "id": "VEC-10",
        "name": "Cronjob Executing Writable Script",
        "module": "cronjobs",
        "setup": "mkdir -p /opt/lab && echo '#!/bin/bash' > /opt/lab/cron.sh && chmod 777 /opt/lab/cron.sh && echo '* * * * * root /opt/lab/cron.sh' > /etc/cron.d/lab_cron",
        "verify": lambda r: any("/opt/lab/cron.sh" in c.get("command", "") and c.get("is_dangerous") for c in r.get("cron_jobs", []))
    },
    {
        "id": "VEC-11",
        "name": "Cron Drop-in Directory Permission Drift (/etc/cron.d)",
        "module": "crondirs",
        "setup": "chmod 777 /etc/cron.d",
        "verify": lambda r: any(c.get("path") == "/etc/cron.d" and c.get("is_dangerous") for c in r.get("cron_dir_results", []))
    },
    {
        "id": "VEC-12",
        "name": "Systemd Timer Executing Writable Script",
        "module": "cronjobs",
        "setup": "mkdir -p /opt/lab /etc/systemd/system && echo '#!/bin/bash' > /opt/lab/timer_exec.sh && chmod 777 /opt/lab/timer_exec.sh && printf '[Service]\\nExecStart=/opt/lab/timer_exec.sh\\n' > /etc/systemd/system/lab_timer.service && printf '[Timer]\\nOnCalendar=minutely\\n' > /etc/systemd/system/lab_timer.timer",
        "verify": lambda r: any(t.get("is_dangerous") and "timer_exec.sh" in t.get("reason", "") for t in r.get("systemd_timers", []))
    },
    {
        "id": "VEC-13",
        "name": "Systemd Unit Drop-in Override Writable",
        "module": "systemdoverrides",
        "setup": "mkdir -p /etc/systemd/system/dummy.service.d && printf '[Service]\\nExecStart=/bin/true\\n' > /etc/systemd/system/dummy.service.d/override.conf && chmod 666 /etc/systemd/system/dummy.service.d/override.conf",
        "verify": lambda r: any("override.conf" in o.get("path", "") and o.get("is_dangerous") for o in r.get("systemd_overrides", []))
    },
    {
        "id": "VEC-14",
        "name": "Systemd Service EnvironmentFile Writable",
        "module": "environmentfile",
        "setup": "mkdir -p /etc/default /etc/systemd/system && touch /etc/default/app_env && chmod 666 /etc/default/app_env && printf '[Service]\\nEnvironmentFile=/etc/default/app_env\\nExecStart=/bin/true\\n' > /etc/systemd/system/app.service",
        "verify": lambda r: any("app_env" in e.get("env_file_path", "") and e.get("is_writable") for e in r.get("env_file_results", []))
    },
    {
        "id": "VEC-15",
        "name": "PATH Hijacking (Writable Directory in PATH)",
        "module": "pathhijack",
        "setup": "mkdir -p /opt/lab/bin && chmod 777 /opt/lab/bin",
        "run_cmd": "su tester -c 'PATH=/opt/lab/bin:$PATH /usr/local/bin/talaria -o /tmp/rep.json --format json >/dev/null 2>&1' && cat /tmp/rep.json",
        "verify": lambda r: any("/opt/lab/bin" in p.get("directory", "") and p.get("is_writeable") for p in r.get("path_hijack", []))
    },
    {
        "id": "VEC-16",
        "name": "Sensitive File Exposure: OpenSSH Private Key",
        "module": "secrets",
        "setup": "mkdir -p /home/tester/.ssh && echo '-----BEGIN OPENSSH PRIVATE KEY-----' > /home/tester/.ssh/id_rsa && echo 'b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW' >> /home/tester/.ssh/id_rsa && echo '-----END OPENSSH PRIVATE KEY-----' >> /home/tester/.ssh/id_rsa && chmod 600 /home/tester/.ssh/id_rsa && chown -R tester:tester /home/tester/.ssh",
        "verify": lambda r: any("id_rsa" in s.get("path", "") for s in r.get("secrets", [])) or any("id_rsa" in k.get("path", "") for k in r.get("ssh_keys", []))
    },
    {
        "id": "VEC-17",
        "name": "Sensitive File Exposure: AWS Credentials",
        "module": "secrets",
        "setup": "mkdir -p /home/tester/.aws && echo '[default]' > /home/tester/.aws/credentials && echo 'aws_access_key_id=AKIAIOSFODNN7EXAMPLE' >> /home/tester/.aws/credentials && echo 'aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' >> /home/tester/.aws/credentials && chmod 644 /home/tester/.aws/credentials && chown -R tester:tester /home/tester/.aws",
        "verify": lambda r: any(".aws/credentials" in s.get("path", "") for s in r.get("secrets", []))
    },
    {
        "id": "VEC-18",
        "name": "Sensitive File Exposure: Plaintext Password in Config",
        "module": "secrets",
        "setup": "mkdir -p /etc/lab && echo 'DB_USER=admin' > /etc/lab/database.conf && echo 'DB_PASSWORD=SuperSecretAdminPass2026!' >> /etc/lab/database.conf && chmod 644 /etc/lab/database.conf",
        "verify": lambda r: any("database.conf" in s.get("path", "") for s in r.get("secrets", [])) or any("database.conf" in s.get("path", "") for s in r.get("secret_content", []))
    },
    {
        "id": "VEC-19",
        "name": "Shell History Secrets Scraping",
        "module": "history_secrets",
        "setup": "echo 'mysql -u root -p\"AdminDBPassword2026!\"' > /home/tester/.bash_history && echo 'sshpass -p \"SecretSSHKey!\" ssh user@10.0.0.1' >> /home/tester/.bash_history && chown tester:tester /home/tester/.bash_history",
        "verify": lambda r: any("AdminDBPassword2026!" in h.get("command", "") or h.get("risk_level") == "HIGH" for h in r.get("history_secrets", []))
    },
    {
        "id": "VEC-20",
        "name": "Dynamic Linker Writable Search Path (/etc/ld.so.conf.d)",
        "module": "ldnss",
        "setup": "mkdir -p /etc/ld.so.conf.d /opt/lab/libs && echo '/opt/lab/libs' > /etc/ld.so.conf.d/evil.conf && chmod 644 /etc/ld.so.conf.d/evil.conf && chmod 777 /opt/lab/libs",
        "verify": lambda r: any("/opt/lab/libs" in l.get("path", "") and l.get("is_dangerous") for l in r.get("ld_nss_results", []))
    },
    {
        "id": "VEC-21",
        "name": "Logrotate Writable Configuration File",
        "module": "logrotate",
        "setup": "mkdir -p /etc/logrotate.d && printf '/var/log/test.log {\\n daily\\n rotate 3\\n}\\n' > /etc/logrotate.d/test_log && chmod 666 /etc/logrotate.d/test_log",
        "verify": lambda r: any("test_log" in l.get("config_path", "") and l.get("is_writable") for l in r.get("logrotate", []))
    },
    {
        "id": "VEC-22",
        "name": "Logrotate Writable Postrotate Script",
        "module": "logrotate",
        "setup": "mkdir -p /etc/logrotate.d /opt/lab && echo '#!/bin/bash' > /opt/lab/postrotate.sh && chmod 777 /opt/lab/postrotate.sh && printf '/var/log/test.log {\\n postrotate\\n /opt/lab/postrotate.sh\\n endscript\\n}\\n' > /etc/logrotate.d/test_post && chmod 644 /etc/logrotate.d/test_post",
        "verify": lambda r: any("test_post" in l.get("config_path", "") and "/opt/lab/postrotate.sh" in str(l.get("postrotate_paths", [])) for l in r.get("logrotate", []))
    },
    {
        "id": "VEC-23",
        "name": "PAM Policy Writable Configuration",
        "module": "pam",
        "setup": "mkdir -p /etc/pam.d && echo 'auth required pam_permit.so' > /etc/pam.d/lab_auth && chmod 666 /etc/pam.d/lab_auth",
        "verify": lambda r: any("lab_auth" in p.get("path", "") and p.get("is_dangerous") for p in r.get("pam_results", []))
    },
    {
        "id": "VEC-24",
        "name": "PAM Exec Module Writable Script",
        "module": "pam",
        "setup": "mkdir -p /etc/pam.d /opt/lab && echo '#!/bin/bash' > /opt/lab/pam_hook.sh && chmod 777 /opt/lab/pam_hook.sh && echo 'auth required pam_exec.so /opt/lab/pam_hook.sh' > /etc/pam.d/lab_pam_exec && chmod 644 /etc/pam.d/lab_pam_exec",
        "verify": lambda r: any("pam_hook.sh" in p.get("path", "") and p.get("is_dangerous") for p in r.get("pam_results", []))
    },
    {
        "id": "VEC-25",
        "name": "Polkit Permissive Custom JavaScript Rule",
        "module": "polkit",
        "setup": "mkdir -p /etc/polkit-1/rules.d && printf 'polkit.addRule(function(action, subject) {\\n if (action.id == \"org.freedesktop.policykit.exec\") return polkit.Result.YES;\\n});\\n' > /etc/polkit-1/rules.d/99-test.rules && chmod 644 /etc/polkit-1/rules.d/99-test.rules",
        "verify": lambda r: any(p.get("is_dangerous") and "exec" in p.get("action", "") for p in r.get("polkit_rules", []))
    },
    {
        "id": "VEC-26",
        "name": "Exposed Writable Docker Daemon Socket",
        "module": "sockets",
        "setup": "python3 -c \"import socket; s=socket.socket(socket.AF_UNIX); s.bind('/var/run/docker.sock')\" && chmod 666 /var/run/docker.sock",
        "verify": lambda r: any("docker.sock" in s.get("path", "") and s.get("is_dangerous") for s in r.get("sockets", []))
    },
    {
        "id": "VEC-27",
        "name": "Exposed Writable Podman Daemon Socket",
        "module": "sockets",
        "setup": "python3 -c \"import socket; s=socket.socket(socket.AF_UNIX); s.bind('/var/run/podman.sock')\" && chmod 666 /var/run/podman.sock",
        "verify": lambda r: any("podman.sock" in s.get("path", "") and s.get("is_dangerous") for s in r.get("sockets", []))
    },
    {
        "id": "VEC-28",
        "name": "Modprobe Writable Install Hook Target",
        "module": "modprobe",
        "setup": "mkdir -p /etc/modprobe.d /opt/lab && echo '#!/bin/bash' > /opt/lab/modprobe_exec.sh && chmod 777 /opt/lab/modprobe_exec.sh && echo 'install lab_dummy /opt/lab/modprobe_exec.sh' > /etc/modprobe.d/lab.conf && chmod 644 /etc/modprobe.d/lab.conf",
        "verify": lambda r: any("modprobe_exec.sh" in m.get("path", "") and m.get("is_dangerous") for m in r.get("modprobe_results", []))
    },
    {
        "id": "VEC-29",
        "name": "Kubernetes ServiceAccount Token Leak",
        "module": "cloudmeta",
        "setup": "mkdir -p /var/run/secrets/kubernetes.io/serviceaccount && echo 'eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3QifQ.eyJzdWIiOiJzYSJ9.sig' > /var/run/secrets/kubernetes.io/serviceaccount/token && chmod 644 /var/run/secrets/kubernetes.io/serviceaccount/token",
        "verify": lambda r: any("serviceaccount/token" in c.get("path", "") and c.get("is_dangerous") for c in r.get("cloud_meta_results", []))
    },
    {
        "id": "VEC-30",
        "name": "Python VirtualEnv Writable Activate Script",
        "module": "venvwrap",
        "setup": "mkdir -p /opt/venv/bin && touch /opt/venv/bin/activate && chmod 777 /opt/venv/bin/activate",
        "verify": lambda r: any("activate" in v.get("path", "") and v.get("is_dangerous") for v in r.get("venv_wrap_results", []))
    },
    {
        "id": "VEC-31",
        "name": "Tmux / Screen Session Hijacking Socket",
        "module": "sessions",
        "setup": "mkdir -p /tmp/tmux-0 && touch /tmp/tmux-0/default && chown -R root:root /tmp/tmux-0 && chmod 777 /tmp/tmux-0/default",
        "verify": lambda r: any("tmux-0/default" in s.get("path", "") and s.get("is_dangerous") for s in r.get("session_hijack", []))
    },
    {
        "id": "VEC-32",
        "name": "X11 Authority Cookie Hijack (.Xauthority)",
        "module": "xauthority",
        "setup": "mkdir -p /tmp/.X11-unix /root && chmod 755 /root && touch /root/.Xauthority && chmod 644 /root/.Xauthority",
        "verify": lambda r: any(".Xauthority" in x.get("path", "") and x.get("is_dangerous") for x in r.get("xauthority", []))
    },
    {
        "id": "VEC-33",
        "name": "Critical System File Permissions (/etc/passwd Writable)",
        "module": "filepermissions",
        "setup": "chmod 666 /etc/passwd",
        "verify": lambda r: any(f.get("path") == "/etc/passwd" and f.get("is_dangerous") for f in r.get("file_permissions", []))
    },
    {
        "id": "VEC-34",
        "name": "Cron Line Interpreter Argument Analysis (python3 script.py)",
        "module": "cronjobs",
        "setup": "mkdir -p /opt/lab && echo 'print(1)' > /opt/lab/task.py && chmod 777 /opt/lab/task.py && echo '* * * * * root python3 /opt/lab/task.py' > /etc/cron.d/python_cron",
        "verify": lambda r: any("task.py" in c.get("command", "") and c.get("is_dangerous") for c in r.get("cron_jobs", []))
    },
    {
        "id": "VEC-35",
        "name": "Process Environment Secret Token Harvesting",
        "module": "procenv",
        "run_cmd": 'su tester -c "export AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE && sleep 60 & sleep 0.2 && /usr/local/bin/talaria -o /tmp/rep.json --format json >/dev/null 2>&1" && cat /tmp/rep.json',
        "verify": lambda r: any(p.get("key") == "AWS_SECRET_ACCESS_KEY" for p in r.get("proc_env_results", []))
    }
]

def run_single_test(vec):
    t0 = time.time()
    setup_cmd = vec.get("setup", "")
    
    if "run_cmd" in vec:
        inner_cmd = f"{setup_cmd} && {vec['run_cmd']}" if setup_cmd else vec["run_cmd"]
    else:
        inner_cmd = f"{setup_cmd} && su tester -c '/usr/local/bin/talaria -o /tmp/rep.json --format json >/dev/null 2>&1' && cat /tmp/rep.json"
        
    cmd = [
        "docker", "run", "--rm",
        "-t",
        "--user", "root",
        "-v", f"{BINARY_HOST_PATH}:/usr/local/bin/talaria:ro",
        DOCKER_IMAGE,
        "bash", "-c", inner_cmd
    ]
    
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=25)
        duration_ms = int((time.time() - t0) * 1000)
        
        if proc.returncode != 0:
            return {
                "id": vec["id"],
                "name": vec["name"],
                "module": vec["module"],
                "status": "FAIL",
                "reason": f"Container exit code {proc.returncode}: {proc.stderr[:100]}",
                "duration_ms": duration_ms
            }
        
        # Clean stdout of carriage returns from -t
        raw_stdout = proc.stdout.replace("\r\n", "\n").replace("\r", "")
        # Extract JSON part (from '{' to '}')
        json_start = raw_stdout.find("{")
        json_end = raw_stdout.rfind("}")
        if json_start == -1 or json_end == -1:
            return {
                "id": vec["id"],
                "name": vec["name"],
                "module": vec["module"],
                "status": "FAIL",
                "reason": f"No JSON object found in output: {raw_stdout[:100]}",
                "duration_ms": duration_ms
            }
            
        json_str = raw_stdout[json_start:json_end+1]
        try:
            report = json.loads(json_str)
        except Exception as e:
            return {
                "id": vec["id"],
                "name": vec["name"],
                "module": vec["module"],
                "status": "FAIL",
                "reason": f"Failed to parse JSON output: {str(e)[:100]}",
                "duration_ms": duration_ms
            }
        
        is_caught = vec["verify"](report)
        return {
            "id": vec["id"],
            "name": vec["name"],
            "module": vec["module"],
            "status": "CAUGHT" if is_caught else "MISSED",
            "reason": "Successfully detected" if is_caught else "Vector not present in scanner findings",
            "duration_ms": duration_ms
        }
    except subprocess.TimeoutExpired:
        return {
            "id": vec["id"],
            "name": vec["name"],
            "module": vec["module"],
            "status": "TIMEOUT",
            "reason": "Test exceeded 25s timeout",
            "duration_ms": int((time.time() - t0) * 1000)
        }
    except Exception as e:
        return {
            "id": vec["id"],
            "name": vec["name"],
            "module": vec["module"],
            "status": "ERROR",
            "reason": str(e)[:100],
            "duration_ms": int((time.time() - t0) * 1000)
        }

def main():
    print(f"[+] Starting Talaria Isolated Vector Verification Suite ({len(VECTORS)} vectors)...")
    results = []
    
    for i, vec in enumerate(VECTORS, 1):
        sys.stdout.write(f"  [{i:02d}/{len(VECTORS):02d}] Testing {vec['id']}: {vec['name']} ... ")
        sys.stdout.flush()
        res = run_single_test(vec)
        results.append(res)
        if res["status"] == "CAUGHT":
            print(f"✅ CAUGHT ({res['duration_ms']}ms)")
        else:
            print(f"❌ {res['status']} ({res['duration_ms']}ms) - {res['reason']}")
            
    # Summary
    caught = sum(1 for r in results if r["status"] == "CAUGHT")
    missed = sum(1 for r in results if r["status"] != "CAUGHT")
    total = len(results)
    
    print("\n" + "="*80)
    print(f"TALARIA TEST SUITE SUMMARY: {caught}/{total} CAUGHT ({(caught/total)*100:.1f}%)")
    print("="*80)
    
    # Save output to JSON
    with open("lab/test_results.json", "w") as f:
        json.dump(results, f, indent=2)
    print("[+] Detailed results saved to lab/test_results.json")

if __name__ == "__main__":
    main()
