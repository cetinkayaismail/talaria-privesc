package core

import (
	"talaria/models"
	"talaria/scanners"
	"testing"
)

func TestEnrichTriggerAndMitre(t *testing.T) {
	tests := []struct {
		name        string
		chainRes    ChainResult
		wantTrigger string
		wantMitre   string
	}{
		{
			name: "Cron scheduled task",
			chainRes: ChainResult{
				Name:        "Writable file executed by root CronJob",
				Description: "Command: /etc/cron.d/job.sh",
			},
			wantTrigger: "⏰ SCHEDULED",
			wantMitre:   "T1053.003",
		},
		{
			name: "Sudo instant privilege",
			chainRes: ChainResult{
				Name:        "Writable file can be run via Sudo",
				Description: "NOPASSWD /usr/bin/python3",
			},
			wantTrigger: "⚡ INSTANT",
			wantMitre:   "T1548.003",
		},
		{
			name: "PAM login trigger",
			chainRes: ChainResult{
				Name:        "PAM Module Misconfiguration",
				Description: "pam_exec.so executed on user login",
			},
			wantTrigger: "🔑 ON-LOGIN",
			wantMitre:   "T1556.004",
		},
		{
			name: "MOTD profile login trigger",
			chainRes: ChainResult{
				Name:        "Writable MOTD Script Execution on Login: 99-pwn",
				Description: "Executed on SSH login",
			},
			wantTrigger: "🔑 ON-LOGIN",
			wantMitre:   "T1546.004",
		},
		{
			name: "Explicit trigger preserved",
			chainRes: ChainResult{
				Name:        "Custom Chain",
				TriggerType: "⚡ INSTANT",
				MitreID:     "T1234.567",
			},
			wantTrigger: "⚡ INSTANT",
			wantMitre:   "T1234.567",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := tt.chainRes
			enrichTriggerAndMitre(&res)
			if res.TriggerType != tt.wantTrigger {
				t.Errorf("got TriggerType %q, want %q", res.TriggerType, tt.wantTrigger)
			}
			if res.MitreID != tt.wantMitre {
				t.Errorf("got MitreID %q, want %q", res.MitreID, tt.wantMitre)
			}
		})
	}
}

func TestAttackChains46To50(t *testing.T) {
	// Chain 46: SudoTokenTTYChain
	t.Run("Chain46_SudoTokenTTY", func(t *testing.T) {
		chain := &SudoTokenTTYChain{}
		report := &models.ScanReport{
			SudoTokens: []scanners.SudoTokenResult{
				{
					Vector:      "Active Sudo Session Token",
					Path:        "/run/sudo/ts/root",
					IsDangerous: true,
					Reason:      "Cached sudo credential exists",
					ExploitHint: "sudo -i",
				},
			},
		}
		results := chain.Evaluate(report)
		if len(results) != 1 {
			t.Fatalf("expected 1 result, got %d", len(results))
		}
		if results[0].TriggerType != "⚡ INSTANT" {
			t.Errorf("expected ⚡ INSTANT, got %s", results[0].TriggerType)
		}
		if results[0].MitreID != "T1548.003" {
			t.Errorf("expected T1548.003, got %s", results[0].MitreID)
		}
	})

	// Chain 47: SysctlKernelExploitChain
	t.Run("Chain47_SysctlKernelExploit", func(t *testing.T) {
		chain := &SysctlKernelExploitChain{}
		report := &models.ScanReport{
			SysctlResults: []scanners.SysctlResult{
				{
					Key:          "kernel.unprivileged_userns_clone",
					CurrentValue: "1",
					IsDangerous:  true,
				},
			},
			Vulnerabilities: []scanners.VersionInfo{
				{
					Software:    "linux",
					IsDangerous: true,
					Vulnerabilities: []scanners.KernelVulnerability{
						{
							CVE:         "CVE-2022-25636",
							Name:        "Netfilter user namespace heap out-of-bounds write",
							Description: "Requires unprivileged user namespace clone",
							ExploitHint: "./exploit",
						},
					},
				},
			},
		}
		results := chain.Evaluate(report)
		if len(results) != 1 {
			t.Fatalf("expected 1 result, got %d", len(results))
		}
		if results[0].RiskLevel != "100% CONFIRMED" {
			t.Errorf("expected 100%% CONFIRMED, got %s", results[0].RiskLevel)
		}
	})

	// Chain 48: SubUIDNamespaceChain
	t.Run("Chain48_SubUIDNamespace", func(t *testing.T) {
		chain := &SubUIDNamespaceChain{}
		report := &models.ScanReport{
			SubUIDResults: []scanners.SubUIDResult{
				{
					Type:        "userns_unprivileged_enabled",
					IsDangerous: true,
					Reason:      "kernel.unprivileged_userns_clone = 1",
					ExploitHint: "unshare -Urm",
				},
			},
		}
		results := chain.Evaluate(report)
		if len(results) != 1 {
			t.Fatalf("expected 1 result, got %d", len(results))
		}
		if results[0].MitreID != "T1068" {
			t.Errorf("expected T1068, got %s", results[0].MitreID)
		}
	})

	// Chain 49: NfsLocalMountChain
	t.Run("Chain49_NfsLocalMount", func(t *testing.T) {
		chain := &NfsLocalMountChain{}
		report := &models.ScanReport{
			NFSExports: []scanners.NFSExportResult{
				{
					Path:            "/shared/data",
					HasNoRootSquash: true,
					IsDangerous:     true,
				},
			},
			Fstab: []scanners.FstabResult{
				{
					Device:     "127.0.0.1:/shared/data",
					MountPoint: "/mnt/nfs",
					FSType:     "nfs4",
				},
			},
		}
		results := chain.Evaluate(report)
		if len(results) != 1 {
			t.Fatalf("expected 1 result, got %d", len(results))
		}
		if results[0].RiskLevel != "100% CONFIRMED" {
			t.Errorf("expected 100%% CONFIRMED, got %s", results[0].RiskLevel)
		}
		if results[0].MitreID != "T1136.001" {
			t.Errorf("expected T1136.001, got %s", results[0].MitreID)
		}
	})

	// Chain 50: ShmSuidDeliveryChain
	t.Run("Chain50_ShmSuidDelivery", func(t *testing.T) {
		chain := &ShmSuidDeliveryChain{}
		report := &models.ScanReport{
			MountResults: []scanners.MountResult{
				{
					MountPoint:  "/dev/shm",
					MissingFlag: "nosuid,noexec",
					IsDangerous: true,
				},
			},
		}
		results := chain.Evaluate(report)
		if len(results) != 1 {
			t.Fatalf("expected 1 result, got %d", len(results))
		}
		if results[0].TriggerType != "⚡ INSTANT" {
			t.Errorf("expected ⚡ INSTANT, got %s", results[0].TriggerType)
		}
		if results[0].MitreID != "T1548.001" {
			t.Errorf("expected T1548.001, got %s", results[0].MitreID)
		}
	})
}

func TestChain22_ServiceBlankAuth(t *testing.T) {
	chain := &ServiceBlankAuthChain{}

	// Positive test: dangerous unauthenticated local service creates 100% CONFIRMED finding
	posReport := &models.ScanReport{
		Services: []scanners.ServiceAuditResult{
			{
				ServiceName: "Memcached",
				Port:        11211,
				IsDangerous: true,
				Reason:      "Memcached listening locally without authentication",
				ExploitHint: "nc 127.0.0.1 11211",
			},
		},
	}
	posResults := chain.Evaluate(posReport)
	if len(posResults) != 1 {
		t.Fatalf("expected 1 finding for dangerous service, got %d", len(posResults))
	}
	if posResults[0].RiskLevel != "100% CONFIRMED" {
		t.Errorf("expected RiskLevel '100%% CONFIRMED', got %q", posResults[0].RiskLevel)
	}
	if posResults[0].Exploit != "nc 127.0.0.1 11211" {
		t.Errorf("expected exploit hint preserved, got %q", posResults[0].Exploit)
	}

	// Negative boundary test: safe / non-dangerous service is excluded from attack chains
	negReport := &models.ScanReport{
		Services: []scanners.ServiceAuditResult{
			{
				ServiceName: "SafeService",
				Port:        8080,
				IsDangerous: false,
			},
		},
	}
	negResults := chain.Evaluate(negReport)
	if len(negResults) != 0 {
		t.Errorf("expected 0 chain results for safe service, got %d", len(negResults))
	}
}
