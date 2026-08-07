package config

import (
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	c := DefaultConfig()
	if c.LogLevel != "info" {
		t.Errorf("default LogLevel = %q, want info", c.LogLevel)
	}
	if c.SocketPath != DefaultSocketPath {
		t.Errorf("default SocketPath = %q, want %q", c.SocketPath, DefaultSocketPath)
	}
	if !c.IPv6 {
		t.Error("expected IPv6 enabled by default")
	}
	if c.Defaults.MaxRetries != 5 {
		t.Errorf("default MaxRetries = %d, want 5", c.Defaults.MaxRetries)
	}
}

func TestLoadConfigFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "goban.yaml")
	body := `
log_level: debug
sock_path: /tmp/test.sock
defaults:
  max_retries: 3
  findtime: 5m
  bantime: 30m
sources:
  - type: file
    name: auth-log
    path: /var/log/auth.log
rules:
  - name: sshd
    source: auth-log
    regex: 'Failed password.*from (?P<ip>\S+)'
`
	if err := writeFile(t, path, body); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfigFromFile(path)
	if err != nil {
		t.Fatalf("LoadConfigFromFile: %v", err)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want debug", cfg.LogLevel)
	}
	cfg.ApplyRuleDefaults()
	if cfg.Rules[0].MaxRetries != 3 {
		t.Errorf("rule inherited MaxRetries = %d, want 3", cfg.Rules[0].MaxRetries)
	}
	if cfg.Rules[0].FindTime != 5*time.Minute {
		t.Errorf("rule inherited FindTime = %v, want 5m", cfg.Rules[0].FindTime)
	}
}

func TestValidate(t *testing.T) {
	good := func() *Config {
		c := DefaultConfig()
		c.Sources = []SourceConfig{{Type: "file", Name: "auth", Path: "/var/log/auth.log"}}
		c.Rules = []RuleConfig{{
			Name: "sshd", Source: "auth",
			Regex:      `Failed password from (?P<ip>\S+)`,
			MaxRetries: 3, FindTime: 5 * time.Minute, BanTime: time.Hour,
		}}
		return c
	}

	cases := map[string]struct {
		mutate  func(*Config)
		wantErr bool
	}{
		"valid":                   {func(*Config) {}, false},
		"missing_source":          {func(c *Config) { c.Rules[0].Source = "nope" }, true},
		"missing_regex":           {func(c *Config) { c.Rules[0].Regex = "" }, true},
		"regex_no_ip_capture":     {func(c *Config) { c.Rules[0].Regex = `Failed from (\S+)` }, true},
		"bad_regex":               {func(c *Config) { c.Rules[0].Regex = `(?P<ip>` }, true},
		"duplicate_source":        {func(c *Config) { c.Sources = append(c.Sources, c.Sources[0]) }, true},
		"unknown_source_type":     {func(c *Config) { c.Sources[0].Type = "weird" }, true},
		"file_no_path":            {func(c *Config) { c.Sources[0].Path = "" }, true},
		"zero_findtime":           {func(c *Config) { c.Rules[0].FindTime = 0 }, true},
		"zero_bantime":            {func(c *Config) { c.Rules[0].BanTime = 0 }, true},
		"subsecond_bantime":       {func(c *Config) { c.Rules[0].BanTime = 500 * time.Millisecond }, true},
		"bad_rule_name":           {func(c *Config) { c.Rules[0].Name = "../../escape" }, true},
		"datepattern_no_capture":  {func(c *Config) { c.Rules[0].Datepattern = "iso8601" }, true},
		"exclude_unknown_capture": {func(c *Config) { c.Rules[0].Excludes = map[string]string{"user": "root"} }, true},
		"rule_allowlist_ok":       {func(c *Config) { c.Rules[0].Allowlist = []string{"10.0.0.0/8", "203.0.113.50/32"} }, false},
		"rule_allowlist_bad":      {func(c *Config) { c.Rules[0].Allowlist = []string{"not-a-cidr"} }, true},
		"rule_allowlist_all":      {func(c *Config) { c.Rules[0].Allowlist = []string{"0.0.0.0/0"} }, true},
		"rule_allowlist_v6_all":   {func(c *Config) { c.Rules[0].Allowlist = []string{"::/0"} }, true},
		"trusted_proxy_ok": {func(c *Config) {
			c.Rules[0].Regex = `peer=(?P<peer>\S+) client=(?P<ip>\S+)`
			c.Rules[0].TrustedProxyCapture = "peer"
			c.Rules[0].TrustedProxies = []string{"10.0.0.0/8", "2001:db8::/32"}
		}, false},
		"trusted_proxy_missing_capture": {func(c *Config) {
			c.Rules[0].TrustedProxies = []string{"10.0.0.0/8"}
		}, true},
		"trusted_proxy_unknown_capture": {func(c *Config) {
			c.Rules[0].TrustedProxyCapture = "peer"
			c.Rules[0].TrustedProxies = []string{"10.0.0.0/8"}
		}, true},
		"trusted_proxy_all": {func(c *Config) {
			c.Rules[0].Regex = `peer=(?P<peer>\S+) client=(?P<ip>\S+)`
			c.Rules[0].TrustedProxyCapture = "peer"
			c.Rules[0].TrustedProxies = []string{"0.0.0.0/0"}
		}, true},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := good()
			tc.mutate(cfg)
			err := cfg.Validate()
			if tc.wantErr && err == nil {
				t.Fatal("want error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("want no error, got %v", err)
			}
		})
	}
}

func TestApplyEnvOverrides(t *testing.T) {
	t.Setenv("GOBAN_LOG_LEVEL", "warn")
	t.Setenv("GOBAN_REPLAY_ON_START", "true")
	t.Setenv("GOBAN_SOCKET_MODE", "0644")
	t.Setenv("GOBAN_DEFAULT_FINDTIME", "15m")

	c := DefaultConfig()
	if err := ApplyEnvOverrides(c); err != nil {
		t.Fatalf("ApplyEnvOverrides: %v", err)
	}
	if c.LogLevel != "warn" {
		t.Errorf("LogLevel = %q, want warn", c.LogLevel)
	}
	if !c.ReplayOnStart {
		t.Error("ReplayOnStart not set")
	}
	if c.SocketMode != 0o644 {
		t.Errorf("SocketMode = %o, want 0644", c.SocketMode)
	}
	if c.Defaults.FindTime != 15*time.Minute {
		t.Errorf("Defaults.FindTime = %v, want 15m", c.Defaults.FindTime)
	}
}

func writeFile(t *testing.T, path, body string) error {
	t.Helper()
	return writeFileBytes(path, []byte(body))
}

func TestLoadConfigRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "goban.yaml")
	if err := writeFile(t, path, "bantmie: 1h\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfigFromFile(path); err == nil {
		t.Fatal("expected strict YAML error")
	}
}

func TestLoadRulesRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.yaml")
	body := "- name: sshd\n  source: auth\n  regex: 'from (?P<ip>\\\\S+)'\n  max_retrise: 3\n"
	if err := writeFile(t, path, body); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRulesFile(path); err == nil {
		t.Fatal("expected strict rules YAML error")
	}
}

func TestEnvironmentDefaultsApplyAfterMerge(t *testing.T) {
	t.Setenv("GOBAN_DEFAULT_BANTIME", "2h")
	cfg := DefaultConfig()
	cfg.Rules = []RuleConfig{{Name: "sshd"}}
	if err := ApplyEnvOverrides(cfg); err != nil {
		t.Fatal(err)
	}
	cfg.ApplyRuleDefaults()
	if cfg.Rules[0].BanTime != 2*time.Hour {
		t.Fatalf("bantime=%s, want 2h", cfg.Rules[0].BanTime)
	}
}

func TestLoadConfigRejectsMultipleDocuments(t *testing.T) {
	path := filepath.Join(t.TempDir(), "goban.yaml")
	if err := writeFile(t, path, "log_level: info\n---\nlog_level: debug\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfigFromFile(path); err == nil {
		t.Fatal("expected multiple-document YAML error")
	}
}

func TestLoadRulesRejectsMultipleDocuments(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.yaml")
	body := "- name: one\n  source: auth\n  regex: 'from (?P<ip>\\\\S+)'\n---\n- name: two\n  source: auth\n  regex: 'from (?P<ip>\\\\S+)'\n"
	if err := writeFile(t, path, body); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRulesFile(path); err == nil {
		t.Fatal("expected multiple-document rules YAML error")
	}
}

func TestEnforcerConfigValidation(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Sources = []SourceConfig{{Type: "file", Name: "auth", Path: "/tmp/auth.log"}}
	cfg.Rules = []RuleConfig{{Name: "sshd", Source: "auth", Regex: `(?P<ip>192\\.0\\.2\\.1)`, MaxRetries: 1, FindTime: time.Minute, BanTime: time.Minute}}
	cfg.Enforcer.Mode = "split"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid split enforcer rejected: %v", err)
	}
	cfg.Enforcer.SocketPath = "relative.sock"
	if err := cfg.Validate(); err == nil {
		t.Fatal("relative enforcer socket should be rejected")
	}
	cfg.Enforcer.SocketPath = "/run/goban-enforcer/enforcer.sock"
	cfg.Enforcer.Mode = "magic"
	if err := cfg.Validate(); err == nil {
		t.Fatal("unknown enforcer mode should be rejected")
	}
}

func TestEnforcementPolicyFingerprintIsSemantic(t *testing.T) {
	a := DefaultConfig()
	a.Allowlist = []string{"198.51.100.0/24", "203.0.113.7/32"}
	a.Rules = []RuleConfig{{Name: "ssh", Allowlist: []string{"192.0.2.0/24"}}}
	b := DefaultConfig()
	b.Allowlist = []string{"203.0.113.7/32", "198.51.100.42/24", "198.51.100.0/24"}
	b.Rules = []RuleConfig{{Name: "ssh", Allowlist: []string{"192.0.2.99/24"}}}
	if EnforcementPolicyFingerprint(a) != EnforcementPolicyFingerprint(b) {
		t.Fatal("equivalent CIDR policy should have the same fingerprint")
	}
	b.Rules[0].Allowlist = []string{"192.0.3.0/24"}
	if EnforcementPolicyFingerprint(a) == EnforcementPolicyFingerprint(b) {
		t.Fatal("policy change must change fingerprint")
	}
}
