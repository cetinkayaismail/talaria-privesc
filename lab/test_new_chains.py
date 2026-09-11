#!/usr/bin/env python3
"""
Talaria — Lab Verification Suite for Attack Chains 46–50 & Trigger/MITRE Mapping
Runs end-to-end tests inside the Docker lab environment (talaria-lab:latest)
to validate ground-truth attack chain triggering, trigger categorization, and MITRE mapping.
"""

import subprocess
import sys
import time
import json
import os

DOCKER_IMAGE = "talaria-lab:latest"
BINARY_PATH = "/home/ismail/Desktop/go_projects/talaria/bin/talaria"

def run_container_cmd(cmd_str, privileged=False):
    """Executes a command inside the testbed container."""
    cmd = [
        "docker", "run", "--rm",
        "-t",
    ]
    if privileged:
        cmd.append("--privileged")
    cmd.extend([
        "--user", "root",
        "-v", f"{BINARY_PATH}:/usr/local/bin/talaria:ro",
        DOCKER_IMAGE,
        "bash", "-c", cmd_str
    ])
    return subprocess.run(cmd, capture_output=True, text=True, timeout=30)

def test_chain_46_sudo_token():
    """Chain 46: SudoTokenTTYChain (Active Sudo Token Reuse & TTY Injection)"""
    sys.stdout.write("  [1/5] Testing Chain 46 (SudoTokenTTYChain) ... ")
    sys.stdout.flush()
    setup = (
        "echo 'tester ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers && "
        "su tester -c '/usr/local/bin/talaria --audit -o /tmp/rep.json --format json > /tmp/out.txt 2>&1' && "
        "cat /tmp/out.txt"
    )
    res = run_container_cmd(setup)
    output = res.stdout
    
    has_finding = "Active Sudo Session Token" in output
    has_trigger = "Trigger : ⚡ INSTANT" in output
    has_mitre = "MITRE ATT&CK: T1548.003" in output
    
    if has_finding and has_trigger and has_mitre:
        print("✅ PASSED (Trigger: ⚡ INSTANT, MITRE: T1548.003)")
        return True
    else:
        print(f"❌ FAILED (finding={has_finding}, trigger={has_trigger}, mitre={has_mitre})")
        return False

def test_chain_48_subuid_namespace():
    """Chain 48: SubUIDNamespaceChain (SubUID/SubGID User Namespace Mapping)"""
    sys.stdout.write("  [2/5] Testing Chain 48 (SubUIDNamespaceChain) ... ")
    sys.stdout.flush()
    setup = (
        "su tester -c '/usr/local/bin/talaria --audit -o /tmp/rep.json --format json > /tmp/out.txt 2>&1' && "
        "cat /tmp/out.txt"
    )
    res = run_container_cmd(setup)
    output = res.stdout
    
    has_finding = ("SubUID/SubGID User Namespace Mapping" in output or 
                   "Unprivileged User Namespace Clone Enabled" in output)
    has_trigger = "Trigger : ⚡ INSTANT" in output
    has_mitre = "MITRE ATT&CK: T1068" in output
    
    if has_finding and has_trigger and has_mitre:
        print("✅ PASSED (Trigger: ⚡ INSTANT, MITRE: T1068)")
        return True
    else:
        print(f"❌ FAILED (finding={has_finding}, trigger={has_trigger}, mitre={has_mitre})")
        return False

def test_chain_49_nfs_local_mount():
    """Chain 49: NfsLocalMountChain (NFS no_root_squash Local Mount Correlation)"""
    sys.stdout.write("  [3/5] Testing Chain 49 (NfsLocalMountChain) ... ")
    sys.stdout.flush()
    setup = (
        "mkdir -p /shared /mnt/nfs && "
        "echo '/shared *(rw,no_root_squash)' >> /etc/exports && "
        "echo '127.0.0.1:/shared /mnt/nfs nfs defaults 0 0' >> /etc/fstab && "
        "su tester -c '/usr/local/bin/talaria --audit -o /tmp/rep.json --format json > /tmp/out.txt 2>&1' && "
        "cat /tmp/out.txt"
    )
    res = run_container_cmd(setup)
    output = res.stdout
    
    has_finding = "NFS no_root_squash Export Locally Mounted: /shared -> /mnt/nfs" in output
    has_trigger = "Trigger : ⚡ INSTANT" in output
    has_mitre = "MITRE ATT&CK: T1136.001" in output
    
    if has_finding and has_trigger and has_mitre:
        print("✅ PASSED (Trigger: ⚡ INSTANT, MITRE: T1136.001)")
        return True
    else:
        print(f"❌ FAILED (finding={has_finding}, trigger={has_trigger}, mitre={has_mitre})")
        return False

def test_chain_50_shm_suid_delivery():
    """Chain 50: ShmSuidDeliveryChain (Insecure /dev/shm Partition Lacking nosuid)"""
    sys.stdout.write("  [4/5] Testing Chain 50 (ShmSuidDeliveryChain) ... ")
    sys.stdout.flush()
    setup = (
        "mount -o remount,suid /dev/shm && "
        "su tester -c '/usr/local/bin/talaria --audit -o /tmp/rep.json --format json > /tmp/out.txt 2>&1' && "
        "cat /tmp/out.txt"
    )
    res = run_container_cmd(setup, privileged=True)
    output = res.stdout
    
    has_finding = "Insecure Shared Memory Partition Allows SUID Execution: /dev/shm" in output
    has_trigger = "Trigger : ⚡ INSTANT" in output
    has_mitre = "MITRE ATT&CK: T1548.001" in output
    
    if has_finding and has_trigger and has_mitre:
        print("✅ PASSED (Trigger: ⚡ INSTANT, MITRE: T1548.001)")
        return True
    else:
        print(f"❌ FAILED (finding={has_finding}, trigger={has_trigger}, mitre={has_mitre})")
        return False

def test_chain_47_kernel_exploit():
    """Chain 47: SysctlKernelExploitChain (Verified via Unit Test Suite)"""
    sys.stdout.write("  [5/5] Testing Chain 47 (SysctlKernelExploitChain) ... ")
    sys.stdout.flush()
    # Run the unit test for Chain 47 to verify deterministic correlation logic
    cmd = ["/usr/local/go/bin/go", "test", "-v", "-run", "TestAttackChains46To50/Chain47", "./core"]
    proc = subprocess.run(cmd, cwd="/home/ismail/Desktop/go_projects/talaria", capture_output=True, text=True)
    if proc.returncode == 0 and "PASS" in proc.stdout:
        print("✅ PASSED (Trigger: ⚡ INSTANT, MITRE: T1068)")
        return True
    else:
        print(f"❌ FAILED: {proc.stderr}")
        return False

def test_ctf_mode_suppression():
    """Verify that in --ctf mode, MITRE ATT&CK tags are suppressed while triggers remain"""
    sys.stdout.write("  [+] Verifying CTF Mode Cleanliness (--ctf) ... ")
    sys.stdout.flush()
    setup = (
        "echo 'tester ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers && "
        "su tester -c '/usr/local/bin/talaria --ctf > /tmp/out.txt 2>&1' && "
        "cat /tmp/out.txt"
    )
    res = run_container_cmd(setup)
    output = res.stdout
    
    has_mitre = "MITRE ATT&CK" in output
    has_trigger = "Trigger :" in output
    
    if not has_mitre and has_trigger:
        print("✅ PASSED (Triggers displayed, MITRE tags suppressed)")
        return True
    else:
        print(f"❌ FAILED (has_mitre={has_mitre}, has_trigger={has_trigger})")
        return False

def main():
    print("=" * 80)
    print("TALARIA LAB — ATTACK CHAINS 46–50 & TRIGGER/MITRE VERIFICATION")
    print("=" * 80)
    
    tests = [
        test_chain_46_sudo_token,
        test_chain_48_subuid_namespace,
        test_chain_49_nfs_local_mount,
        test_chain_50_shm_suid_delivery,
        test_chain_47_kernel_exploit,
        test_ctf_mode_suppression,
    ]
    
    passed = 0
    for test in tests:
        if test():
            passed += 1
            
    print("\n" + "=" * 80)
    print(f"SUMMARY: {passed}/{len(tests)} Tests Passed ({(passed/len(tests))*100:.1f}%)")
    print("=" * 80)
    
    if passed == len(tests):
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()
