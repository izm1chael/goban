package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// LoadEffective loads the main file, environment overrides, and rules.d in
// the same order as the daemon, then applies defaults and validates the final
// graph. Operator tooling must use this function so validation never drifts
// from production startup semantics.
func LoadEffective(path, rulesDir string) (*Config, error) {
	cfg, err := LoadConfigFromFile(path)
	if err != nil {
		return nil, err
	}
	if err := ApplyEnvOverrides(cfg); err != nil {
		return nil, fmt.Errorf("environment overrides: %w", err)
	}
	dir := rulesDir
	if dir == "" {
		dir = cfg.RulesDir
	}
	if dir != "" {
		rules, err := LoadRulesDir(dir)
		if err != nil {
			return nil, fmt.Errorf("rules directory %s: %w", dir, err)
		}
		cfg.Rules = append(cfg.Rules, rules...)
	}
	cfg.ApplyRuleDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// LoadRulesDir loads rule files in lexical order for deterministic effective
// configuration output and stable rule fingerprints across hosts.
func LoadRulesDir(dir string) ([]RuleConfig, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	var out []RuleConfig
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		rules, err := LoadRulesFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", entry.Name(), err)
		}
		out = append(out, rules...)
	}
	return out, nil
}

// EffectiveYAML returns a human-readable, fully resolved configuration. Time
// durations remain strings rather than implementation-detail nanoseconds.
func EffectiveYAML(cfg *Config) ([]byte, error) {
	return yaml.Marshal(newEffectiveView(cfg))
}

type effectiveRuleDefaults struct {
	MaxRetries int    `yaml:"max_retries"`
	FindTime   string `yaml:"findtime"`
	BanTime    string `yaml:"bantime"`
}

type effectiveRule struct {
	Name                string            `yaml:"name"`
	Source              string            `yaml:"source"`
	Regex               string            `yaml:"regex"`
	MaxRetries          int               `yaml:"max_retries"`
	FindTime            string            `yaml:"findtime"`
	BanTime             string            `yaml:"bantime"`
	Allowlist           []string          `yaml:"allowlist,omitempty"`
	Datepattern         string            `yaml:"datepattern,omitempty"`
	Timezone            string            `yaml:"timezone,omitempty"`
	DateFailurePolicy   string            `yaml:"date_failure_policy,omitempty"`
	Excludes            map[string]string `yaml:"excludes,omitempty"`
	TrustedProxyCapture string            `yaml:"trusted_proxy_capture,omitempty"`
	TrustedProxies      []string          `yaml:"trusted_proxies,omitempty"`
}

type octalMode uint32

func (m octalMode) MarshalYAML() (any, error) {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: fmt.Sprintf("0o%o", uint32(m))}, nil
}

type effectiveConfig struct {
	LogLevel          string                `yaml:"log_level"`
	LogFile           string                `yaml:"log_file,omitempty"`
	SocketPath        string                `yaml:"sock_path"`
	SocketMode        octalMode             `yaml:"socket_mode"`
	SocketGroup       string                `yaml:"socket_group,omitempty"`
	Allowlist         []string              `yaml:"allowlist"`
	Defaults          effectiveRuleDefaults `yaml:"defaults"`
	Sources           []SourceConfig        `yaml:"sources"`
	Rules             []effectiveRule       `yaml:"rules"`
	RulesDir          string                `yaml:"rules_dir,omitempty"`
	ReplayOnStart     bool                  `yaml:"replay_on_start"`
	FlushOnExit       bool                  `yaml:"flush_on_exit"`
	IPv6              bool                  `yaml:"ipv6"`
	IPSetNameV4       string                `yaml:"ipset_name_v4"`
	IPSetNameV6       string                `yaml:"ipset_name_v6,omitempty"`
	Banner            BannerConfig          `yaml:"banner"`
	StrikeChanSize    int                   `yaml:"strike_chan_size"`
	DryRun            bool                  `yaml:"dry_run"`
	BatchBans         bool                  `yaml:"batch_bans"`
	AuditLog          string                `yaml:"audit_log,omitempty"`
	StatePath         string                `yaml:"state_path,omitempty"`
	StateSaveInterval string                `yaml:"state_save_interval"`
}

func newEffectiveView(cfg *Config) effectiveConfig {
	rules := make([]effectiveRule, 0, len(cfg.Rules))
	for _, r := range cfg.Rules {
		rules = append(rules, effectiveRule{
			Name: r.Name, Source: r.Source, Regex: r.Regex,
			MaxRetries: r.MaxRetries, FindTime: durationString(r.FindTime), BanTime: durationString(r.BanTime),
			Allowlist: r.Allowlist, Datepattern: r.Datepattern, Timezone: r.Timezone,
			DateFailurePolicy: r.DateFailurePolicy, Excludes: r.Excludes,
			TrustedProxyCapture: r.TrustedProxyCapture, TrustedProxies: r.TrustedProxies,
		})
	}
	return effectiveConfig{
		LogLevel: cfg.LogLevel, LogFile: cfg.LogFile, SocketPath: cfg.SocketPath,
		SocketMode: octalMode(cfg.SocketMode), SocketGroup: cfg.SocketGroup,
		Allowlist: cfg.Allowlist,
		Defaults:  effectiveRuleDefaults{MaxRetries: cfg.Defaults.MaxRetries, FindTime: durationString(cfg.Defaults.FindTime), BanTime: durationString(cfg.Defaults.BanTime)},
		Sources:   cfg.Sources, Rules: rules, RulesDir: cfg.RulesDir,
		ReplayOnStart: cfg.ReplayOnStart, FlushOnExit: cfg.FlushOnExit, IPv6: cfg.IPv6,
		IPSetNameV4: cfg.IPSetNameV4, IPSetNameV6: cfg.IPSetNameV6, Banner: cfg.Banner,
		StrikeChanSize: cfg.StrikeChanSize, DryRun: cfg.DryRun, BatchBans: cfg.BatchBans,
		AuditLog: cfg.AuditLog, StatePath: cfg.StatePath, StateSaveInterval: durationString(cfg.StateSaveInterval),
	}
}

func durationString(d time.Duration) string {
	if d == 0 {
		return "0s"
	}
	return d.String()
}
