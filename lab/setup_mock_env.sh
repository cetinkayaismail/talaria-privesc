#!/bin/bash
# ==============================================================================
# Talaria Lab — Comprehensive Multi-Vector Testbed Setup Script
# ==============================================================================
# Populates safe, controlled mock misconfigurations for all scanner modules.

set -e

echo "[+] Setting up comprehensive Talaria testbed environment..."

# 1. Writable Scheduled Execution (CronJob)
mkdir -p /opt/lab
cat << 'EOF' > /opt/lab/backup.sh
#!/bin/bash
# Root backup script mock
echo "Running system backup..."
EOF
chmod 777 /opt/lab/backup.sh

cat << 'EOF' > /etc/cron.d/lab_cron
* * * * * root /opt/lab/backup.sh
EOF
chmod 644 /etc/cron.d/lab_cron

# 2. Writable PAM Policy & Exec Script
cat << 'EOF' > /etc/pam.d/lab_test_auth
# Test PAM Policy
auth required pam_exec.so /opt/lab/pam_helper.sh
EOF
chmod 666 /etc/pam.d/lab_test_auth

cat << 'EOF' > /opt/lab/pam_helper.sh
#!/bin/bash
exit 0
EOF
chmod 777 /opt/lab/pam_helper.sh

# 3. Systemd EnvironmentFile & Unit Override
mkdir -p /etc/default /etc/systemd/system/lab-dummy.service.d
cat << 'EOF' > /etc/default/lab_service
# Mock Service Environment File
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin
EOF
chmod 666 /etc/default/lab_service

cat << 'EOF' > /etc/systemd/system/lab-dummy.service
[Unit]
Description=Lab Dummy Service
[Service]
EnvironmentFile=/etc/default/lab_service
ExecStart=/bin/true
EOF
chmod 644 /etc/systemd/system/lab-dummy.service

cat << 'EOF' > /etc/systemd/system/lab-dummy.service.d/override.conf
[Service]
ExecStartPre=/opt/lab/backup.sh
EOF
chmod 666 /etc/systemd/system/lab-dummy.service.d/override.conf

# 4. Capabilities (Linux File Capabilities)
cp /usr/bin/python3 /usr/local/bin/python_cap 2>/dev/null || cp /bin/bash /usr/local/bin/bash_cap
setcap cap_setuid+ep /usr/local/bin/python_cap 2>/dev/null || setcap cap_setuid+ep /usr/local/bin/bash_cap 2>/dev/null || true

# 5. SUID / SGID GTFOBins Mock Binaries
cp /usr/bin/find /usr/local/bin/find_suid
chmod 4755 /usr/local/bin/find_suid

cp /usr/bin/wall /usr/local/bin/wall_sgid
groupadd -f shadow_test
chown root:shadow_test /usr/local/bin/wall_sgid 2>/dev/null || true
chmod 2755 /usr/local/bin/wall_sgid

# 6. Logrotate Writable Postrotate Script
mkdir -p /etc/logrotate.d
cat << 'EOF' > /etc/logrotate.d/lab_app
/var/log/lab.log {
    daily
    rotate 7
    postrotate
        /opt/lab/postrotate_hook.sh
    endscript
}
EOF
chmod 644 /etc/logrotate.d/lab_app

cat << 'EOF' > /opt/lab/postrotate_hook.sh
#!/bin/bash
echo "Rotate complete"
EOF
chmod 777 /opt/lab/postrotate_hook.sh

# 7. Writable Directory in PATH (PATH Hijacking)
mkdir -p /opt/lab/bin
chmod 777 /opt/lab/bin

# 8. User Secret Files & History Credentials
mkdir -p /home/tester/.ssh /home/tester/.aws /home/tester/.config
cat << 'EOF' > /home/tester/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACD1234567890123456789012345678901234567890123AAAACBAAAA
-----END OPENSSH PRIVATE KEY-----
EOF
chmod 600 /home/tester/.ssh/id_rsa

cat << 'EOF' > /home/tester/.aws/credentials
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
EOF
chmod 644 /home/tester/.aws/credentials

cat << 'EOF' > /home/tester/.bash_history
cd /var/www/html
mysql -u dbuser -p'SecretP@ssw0rd2026!' -h 127.0.0.1
ssh -i ~/.ssh/id_rsa root@10.0.0.15
EOF
chmod 644 /home/tester/.bash_history

# 9. Config Comment Password Disclosure
mkdir -p /etc/lab_config
cat << 'EOF' > /etc/lab_config/app.conf
# App configuration file
# Database credential user:admin & pass:SuperSecret2026!
DB_HOST=127.0.0.1
DB_PORT=3306
EOF
chmod 644 /etc/lab_config/app.conf

# 10. Polkit Custom Rule File
mkdir -p /etc/polkit-1/rules.d
cat << 'EOF' > /etc/polkit-1/rules.d/50-lab.rules
polkit.addRule(function(action, subject) {
    if (action.id == "org.freedesktop.policykit.exec") {
        return polkit.Result.YES;
    }
});
EOF
chmod 644 /etc/polkit-1/rules.d/50-lab.rules

# 11. Package Manager Writable Hook Configuration Drop-in
mkdir -p /etc/apt/apt.conf.d
cat << 'EOF' > /etc/apt/apt.conf.d/99lab-update
// Lab APT Hook Configuration Mock
APT::Update::Post-Invoke-Success {"/bin/true";};
EOF
chmod 666 /etc/apt/apt.conf.d/99lab-update

# 12. Dynamic Linker Writable Search Directory
mkdir -p /etc/ld.so.conf.d /opt/lab/libs
echo "/opt/lab/libs" > /etc/ld.so.conf.d/lab_custom.conf
chmod 644 /etc/ld.so.conf.d/lab_custom.conf
chmod 777 /opt/lab/libs

# 13. Modprobe Writable Install Hook Target
mkdir -p /etc/modprobe.d
cat << 'EOF' > /etc/modprobe.d/lab_hook.conf
# Lab Modprobe Rule Mock
install dummy_net /opt/lab/mod_hook.sh
EOF
chmod 644 /etc/modprobe.d/lab_hook.conf
cat << 'EOF' > /opt/lab/mod_hook.sh
#!/bin/bash
exit 0
EOF
chmod 777 /opt/lab/mod_hook.sh

# 14. Kubernetes In-Cluster ServiceAccount Token Mock
mkdir -p /var/run/secrets/kubernetes.io/serviceaccount
echo "eyJhbGciOiJSUzI1NiIsImtpZCI6Ik1vY2tLZXlJZCJ9.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50In0.mockSignature" > /var/run/secrets/kubernetes.io/serviceaccount/token
echo "default" > /var/run/secrets/kubernetes.io/serviceaccount/namespace
chmod 644 /var/run/secrets/kubernetes.io/serviceaccount/token

# 15. Python VirtualEnv Site-Packages Writable Mock
mkdir -p /opt/lab/venv/bin /opt/lab/venv/lib/python3.11/site-packages
touch /opt/lab/venv/bin/activate
chmod 777 /opt/lab/venv/bin/activate
chmod 777 /opt/lab/venv/lib/python3.11/site-packages

# 16. Sudoers.d Writable Drop-In Mock
mkdir -p /etc/sudoers.d
grep -q "includedir /etc/sudoers.d" /etc/sudoers 2>/dev/null || echo "#includedir /etc/sudoers.d" >> /etc/sudoers
chmod 777 /etc/sudoers.d

# 17. Shell Startup Environment Writable Mock
mkdir -p /etc
touch /etc/environment
chmod 666 /etc/environment

# 18. At Daemon Spool Directory Mock
mkdir -p /var/spool/cron/atjobs
chmod 777 /var/spool/cron/atjobs
cat << 'EOF' > /var/spool/cron/atjobs/a0000101
#!/bin/sh
echo "Scheduled job"
EOF
chmod 666 /var/spool/cron/atjobs/a0000101

# 19. Persistent Fstab User-Mount Mock
echo "/dev/sdb1 /mnt/lab_usb ext4 user,exec 0 0" >> /etc/fstab

# 20. Snap Confinement Devmode Mock
mkdir -p /snap/mockapp/current/meta
cat << 'EOF' > /snap/mockapp/current/meta/snap.yaml
name: mockapp
version: 1.0.0
confinement: devmode
EOF

# 21. Shared Git Hooks Writable Mock
mkdir -p /opt/deploy_repo/.git/hooks
cat << 'EOF' > /opt/deploy_repo/.git/hooks/post-merge
#!/bin/sh
exit 0
EOF
chown -R root:root /opt/deploy_repo
chmod 777 /opt/deploy_repo/.git/hooks
chmod 777 /opt/deploy_repo/.git/hooks/post-merge

# 22. Xinetd Service Configuration Mock
mkdir -p /etc/xinetd.d /opt/lab/bin
touch /opt/lab/bin/xinetd_server
chmod 777 /opt/lab/bin/xinetd_server
cat << 'EOF' > /etc/xinetd.d/lab_svc
service lab_svc
{
    disable = no
    server = /opt/lab/bin/xinetd_server
}
EOF
chmod 666 /etc/xinetd.d/lab_svc

# 23. Writable MOTD Script Mock
mkdir -p /etc/update-motd.d
cat << 'EOF' > /etc/update-motd.d/00-header
#!/bin/sh
echo "Welcome to Talaria Lab"
EOF
chmod 777 /etc/update-motd.d/00-header

# 24. Multi-User Accounts & Groups (Lateral Movement & Stress Testing)
echo "[+] Provisioning multi-user accounts and group structures..."
groupadd -f devteam
for u in developer devops dba webadmin backup_svc alice bob; do
    useradd -m -s /bin/bash "$u" 2>/dev/null || true
    echo "$u:${u}pass123" | chpasswd
done
usermod -aG devteam tester 2>/dev/null || true
usermod -aG devteam bob 2>/dev/null || true
usermod -aG devteam developer 2>/dev/null || true

# 25. Lateral Privilege Escalation Vectors (Horizontal Pivoting)
echo "[+] Planting lateral movement vectors..."

# 25a. Cross-User SSH Key Leak (tester can read alice's private key)
mkdir -p /home/alice/.ssh /tmp/.backups
cat << 'EOF' > /home/alice/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACD1234567890123456789012345678901234567890123AAAACBAAAA
-----END OPENSSH PRIVATE KEY-----
EOF
chmod 644 /home/alice/.ssh/id_rsa
chown -R alice:alice /home/alice/.ssh
cp /home/alice/.ssh/id_rsa /tmp/.backups/alice_id_rsa
chmod 644 /tmp/.backups/alice_id_rsa

# 25b. Non-Root Scheduled Execution (devops runs a writable cronjob script)
mkdir -p /opt/devops
cat << 'EOF' > /opt/devops/sync.sh
#!/bin/bash
# DevOps sync daemon
echo "Automated repo sync running..."
EOF
chmod 777 /opt/devops/sync.sh
chown devops:devops /opt/devops/sync.sh
cat << 'EOF' > /etc/cron.d/devops_sync
* * * * * devops /opt/devops/sync.sh
EOF
chmod 644 /etc/cron.d/devops_sync

# 25c. Horizontal Sudo RunAs (tester can run script as developer without password)
mkdir -p /opt/developer
cat << 'EOF' > /opt/developer/build.sh
#!/bin/bash
echo "Building project artifacts..."
EOF
chmod 755 /opt/developer/build.sh
chown developer:developer /opt/developer/build.sh
cat << 'EOF' > /etc/sudoers.d/developer_nopasswd
tester ALL=(developer) NOPASSWD: /opt/developer/build.sh
EOF
chmod 440 /etc/sudoers.d/developer_nopasswd

# 25d. Terminal Session Hijacking Socket (webadmin tmux socket)
mkdir -p /tmp/tmux-1004
touch /tmp/tmux-1004/default
chmod 777 /tmp/tmux-1004 /tmp/tmux-1004/default
chown -R webadmin:webadmin /tmp/tmux-1004

# 25e. Shared Group Executable Hijack (devteam group script executed by bob)
mkdir -p /opt/projects
cat << 'EOF' > /opt/projects/app_launcher.sh
#!/bin/bash
# Team application launcher
echo "Launching microservice..."
EOF
chown bob:devteam /opt/projects/app_launcher.sh
chmod 775 /opt/projects/app_launcher.sh

# 25f. Multi-Hop Vertical Chain: Once developer is compromised, developer has sudo rights to root
cat << 'EOF' > /etc/sudoers.d/developer_root
developer ALL=(root) NOPASSWD: /usr/bin/find
EOF
chmod 440 /etc/sudoers.d/developer_root

# 26. High-Density Filesystem Stress Generation (~20,000+ files to benchmark WalkDir and I/O)
echo "[+] Generating ~20,000 filesystem stress assets across multiple directories..."
python3 -c "
import os
base_dirs = [
    ('/var/www/html/app', 'www-data'),
    ('/opt/projects/repo', 'developer'),
    ('/home/developer/workspace', 'developer'),
    ('/home/devops/infrastructure', 'devops'),
    ('/srv/data/storage', 'backup_svc')
]
count = 0
for base, owner in base_dirs:
    for m in range(20):
        target_dir = f'{base}/module_{m}/sub_{m%5}'
        os.makedirs(target_dir, exist_ok=True)
        for f_idx in range(200):
            file_path = f'{target_dir}/component_{f_idx}.py'
            with open(file_path, 'w') as f:
                f.write(f'# Stress benchmark mock file {m}_{f_idx}\nVALUE={f_idx}\n')
            count += 1
print(f'[+] Created {count} mock benchmark files successfully.')
"

# Fix home permissions
chown -R tester:tester /home/tester 2>/dev/null || true
chown -R developer:developer /home/developer 2>/dev/null || true
chown -R devops:devops /home/devops 2>/dev/null || true
chown -R dba:dba /home/dba 2>/dev/null || true
chown -R webadmin:webadmin /home/webadmin 2>/dev/null || true
chown -R backup_svc:backup_svc /home/backup_svc 2>/dev/null || true
chown -R alice:alice /home/alice 2>/dev/null || true
chown -R bob:bob /home/bob 2>/dev/null || true

echo "[+] Comprehensive lab setup complete."


