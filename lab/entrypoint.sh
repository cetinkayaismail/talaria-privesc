#!/bin/bash
# ==============================================================================
# Talaria Lab — Container Entrypoint & Background Service Launcher
# ==============================================================================
# Starts realistic background daemons under multiple user contexts with exposed
# process environment secrets and command-line arguments to test live discovery.

set -e

echo "[*] Initializing Talaria Multi-User Lab environment..."

# 1. Start DBA background daemon with exposed environment credentials
if id -u dba >/dev/null 2>&1; then
    runuser -u dba -- env DB_PASSWORD='SuperSecretDatabasePass2026!' MYSQL_PWD='db_master_pass_99' DATABASE_URL='postgres://dba:ClusterSecret2026@127.0.0.1:5432/production' python3 -c 'import time; time.sleep(86400)' >/dev/null 2>&1 &
fi

# 1b. Start Tester background daemon with exposed environment credentials
if id -u tester >/dev/null 2>&1; then
    runuser -u tester -- env DB_PASSWORD='TesterInternalDatabasePass!' GITHUB_TOKEN='ghp_testertoken1234567890' VAULT_TOKEN='s.mockvaulttoken999' python3 -c 'import time; time.sleep(86400)' >/dev/null 2>&1 &
fi

# 2. Start Developer background dev-server with API tokens
if id -u developer >/dev/null 2>&1; then
    runuser -u developer -- env GITHUB_TOKEN='ghp_mocktoken1234567890abcdef' AWS_SECRET_ACCESS_KEY='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' VAULT_TOKEN='s.mockvaulttoken999' python3 -c 'import time; time.sleep(86400)' >/dev/null 2>&1 &
fi

# 3. Start Root background service with exposed command-line credentials
python3 -c 'import time; time.sleep(86400)' --admin-key=MasterRootKey2026! --token=tok_live_privesc999 --database=mysql://root:RootPassWord2026@localhost/sys >/dev/null 2>&1 &

# 4. Start active Tmux session for webadmin
if id -u webadmin >/dev/null 2>&1; then
    runuser -u webadmin -- tmux new-session -d -s web_prod "bash" 2>/dev/null || true
    chmod -R 777 /tmp/tmux-* 2>/dev/null || true
fi

# 5. Start cron daemon
cron 2>/dev/null || true

echo "[+] Multi-user background services initialized."

# Execute command as unprivileged user 'tester'
if [ $# -eq 0 ]; then
    exec runuser -u tester -- /usr/local/bin/talaria
elif [ "$1" = "/bin/bash" ] || [ "$1" = "bash" ]; then
    exec runuser -u tester -- /bin/bash
else
    exec runuser -u tester -- "$@"
fi
