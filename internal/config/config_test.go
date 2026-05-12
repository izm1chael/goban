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
		"valid":                 {func(*Config) {}, false},
		"missing_source":        {func(c *Config) { c.Rules[0].Source = "nope" }, true},
		"missing_regex":         {func(c *Config) { c.Rules[0].Regex = "" }, true},
		"regex_no_ip_capture":   {func(c *Config) { c.Rules[0].Regex = `Failed from (\S+)` }, true},
		"bad_regex":             {func(c *Config) { c.Rules[0].Regex = `(?P<ip>` }, true},
		"duplicate_source":      {func(c *Config) { c.Sources = append(c.Sources, c.Sources[0]) }, true},
		"unknown_source_type":   {func(c *Config) { c.Sources[0].Type = "weird" }, true},
		"file_no_path":          {func(c *Config) { c.Sources[0].Path = "" }, true},
		"zero_findtime":         {func(c *Config) { c.Rules[0].FindTime = 0 }, true},
		"zero_bantime":          {func(c *Config) { c.Rules[0].BanTime = 0 }, true},
		"rule_allowlist_ok":     {func(c *Config) { c.Rules[0].Allowlist = []string{"10.0.0.0/8", "203.0.113.50/32"} }, false},
		"rule_allowlist_bad":    {func(c *Config) { c.Rules[0].Allowlist = []string{"not-a-cidr"} }, true},
		"rule_allowlist_all":    {func(c *Config) { c.Rules[0].Allowlist = []string{"0.0.0.0/0"} }, true},
		"rule_allowlist_v6_all": {func(c *Config) { c.Rules[0].Allowlist = []string{"::/0"} }, true},
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
