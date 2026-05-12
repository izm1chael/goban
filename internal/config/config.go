// Package config loads and validates GoBan configuration from defaults, a YAML
// file, and environment overrides (in that order).
package config

import (
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/izm1chael/goban/internal/datepattern"
)

// datepatternResolve indirects to internal/datepattern.Resolve so the
// validator can fail fast on misconfigured rule files without coupling test
// code that imports config to the datepattern package's testdata.
var datepatternResolve = datepattern.Resolve

const (
	// DefaultSocketPath is the default unix-socket path the daemon listens on.
	DefaultSocketPath = "/run/goban/goban.sock"
	// DefaultSocketMode is the unix-socket file mode if not overridden.
	DefaultSocketMode = 0o660
	// DefaultMaxLineBytes caps log lines passed to the matcher to neutralise
	// pathologically long inputs before regex matching.
	DefaultMaxLineBytes = 16 * 1024
)

// Config is the top-level GoBan configuration.
type Config struct {
	LogLevel          string         `yaml:"log_level"`
	LogFile           string         `yaml:"log_file"`
	SocketPath        string         `yaml:"sock_path"`
	SocketMode        uint32         `yaml:"socket_mode"`
	SocketGroup       string         `yaml:"socket_group"`
	Allowlist         []string       `yaml:"allowlist"`
	Defaults          RuleDefaults   `yaml:"defaults"`
	Sources           []SourceConfig `yaml:"sources"`
	Rules             []RuleConfig   `yaml:"rules"`
	RulesDir          string         `yaml:"rules_dir"`
	ReplayOnStart     bool           `yaml:"replay_on_start"`
	FlushOnExit       bool           `yaml:"flush_on_exit"`
	IPv6              bool           `yaml:"ipv6"`
	IPSetNameV4       string         `yaml:"ipset_name_v4"`
	IPSetNameV6       string         `yaml:"ipset_name_v6"`
	Banner            BannerConfig   `yaml:"banner"`
	StrikeChanSize    int            `yaml:"strike_chan_size"`
	DryRun            bool           `yaml:"dry_run"`
	BatchBans         bool           `yaml:"batch_bans"`
	AuditLog          string         `yaml:"audit_log"`
	StatePath         string         `yaml:"state_path"`
	StateSaveInterval time.Duration  `yaml:"state_save_interval"`
}

// BannerConfig selects the kernel firewall backend and its tunables. The
// default backend is iptables + ipset (matching v0.x behavior); operators on
// pure-nftables hosts can set backend: nftables to talk directly to the
// nftables subsystem instead.
type BannerConfig struct {
	Backend string `yaml:"backend"` // "iptables" (default) or "nftables"
	// nftables-only knobs (iptables uses Config.IPSetNameV4 / V6 instead).
	Table string `yaml:"table"`
	SetV4 string `yaml:"set_v4"`
	SetV6 string `yaml:"set_v6"`
	Chain string `yaml:"chain"`
}

// RuleDefaults supplies fallback per-rule settings when a rule leaves them
// unset.
type RuleDefaults struct {
	MaxRetries int           `yaml:"max_retries"`
	FindTime   time.Duration `yaml:"findtime"`
	BanTime    time.Duration `yaml:"bantime"`
}

// SourceConfig describes one log source. Type selects the backend.
type SourceConfig struct {
	Type      string            `yaml:"type"` // file | docker | journal
	Name      string            `yaml:"name"`
	Path      string            `yaml:"path"`      // file
	Container string            `yaml:"container"` // docker (name or label k=v)
	Match     string            `yaml:"match"`     // journal (e.g. _SYSTEMD_UNIT=ssh.service)
	Labels    map[string]string `yaml:"labels"`    // docker label filter
}

// RuleConfig describes one rule and references a Source by name.
//
// Allowlist is an optional, rule-specific CIDR list checked BEFORE the global
// allowlist. Use it for "this VPN range should bypass the sshd rule but the
// nginx rule can still ban it" semantics. Both lists are additive — an IP in
// either is exempted from strike registration.
//
// Datepattern is the format of the timestamp embedded in matched log lines.
// When set, the regex MUST also include a (?P<time>...) named capture; the
// extracted string is parsed with the configured layout and used as the
// strike-window event time instead of wall-clock. Accepts named presets
// (sshd, iso8601, rfc3339, syslog_traditional, nginx_combined,
// apache_combined) or a raw Go time layout (e.g. "2006-01-02T15:04:05").
// When unset, the rule uses wall-clock — backwards-compatible default.
//
// Excludes is a post-match filter: for each entry, the rule extracts the
// named regex capture and skips the line when the captured value equals the
// configured skip value. The recidive rule uses this to ignore its own ban
// events. A rule named "recidive" auto-applies excludes[rule]=recidive even
// if Excludes is empty, as defense against operator misconfig.
type RuleConfig struct {
	Name        string            `yaml:"name"`
	Source      string            `yaml:"source"`
	Regex       string            `yaml:"regex"`
	MaxRetries  int               `yaml:"max_retries"`
	FindTime    time.Duration     `yaml:"findtime"`
	BanTime     time.Duration     `yaml:"bantime"`
	Allowlist   []string          `yaml:"allowlist"`
	Datepattern string            `yaml:"datepattern"`
	Excludes    map[string]string `yaml:"excludes"`
}

// DefaultConfig returns a Config populated with safe defaults.
func DefaultConfig() *Config {
	return &Config{
		LogLevel:    "info",
		SocketPath:  DefaultSocketPath,
		SocketMode:  uint32(DefaultSocketMode),
		IPv6:        true,
		IPSetNameV4: "goban-ban-v4",
		IPSetNameV6: "goban-ban-v6",
		Allowlist: []string{
			"127.0.0.0/8",
			"::1/128",
			"10.0.0.0/8",
			"172.16.0.0/12",
			"192.168.0.0/16",
			"fc00::/7",
		},
		Defaults: RuleDefaults{
			MaxRetries: 5,
			FindTime:   10 * time.Minute,
			BanTime:    1 * time.Hour,
		},
		ReplayOnStart:     false,
		FlushOnExit:       false,
		StrikeChanSize:    256,
		BatchBans:         true,
		StatePath:         "/var/lib/goban/state.gob",
		StateSaveInterval: 30 * time.Second,
		Banner: BannerConfig{
			Backend: "iptables",
			Table:   "goban",
			SetV4:   "goban-ban-v4",
			SetV6:   "goban-ban-v6",
			Chain:   "input",
		},
	}
}

// LoadConfigFromFile reads a YAML config file and overlays it on the defaults.
func LoadConfigFromFile(path string) (*Config, error) {
	cfg := DefaultConfig()
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	cfg.ApplyRuleDefaults()
	return cfg, nil
}

// ApplyRuleDefaults fills in any zero per-rule fields with the configured
// global defaults. Idempotent.
func (c *Config) ApplyRuleDefaults() {
	for i := range c.Rules {
		r := &c.Rules[i]
		if r.MaxRetries == 0 {
			r.MaxRetries = c.Defaults.MaxRetries
		}
		if r.FindTime == 0 {
			r.FindTime = c.Defaults.FindTime
		}
		if r.BanTime == 0 {
			r.BanTime = c.Defaults.BanTime
		}
	}
}

// Validate checks the loaded Config for self-consistency and fails fast on
// misconfiguration that would cause runtime errors deep in goroutines.
func (c *Config) Validate() error {
	if c.SocketPath == "" {
		return fmt.Errorf("sock_path must not be empty")
	}
	if c.IPSetNameV4 == "" {
		return fmt.Errorf("ipset_name_v4 must not be empty")
	}
	if c.IPv6 && c.IPSetNameV6 == "" {
		return fmt.Errorf("ipset_name_v6 must not be empty when ipv6 is true")
	}
	if err := c.validateBanner(); err != nil {
		return err
	}
	srcNames, err := c.validateSources()
	if err != nil {
		return err
	}
	return c.validateRules(srcNames)
}

func (c *Config) validateBanner() error {
	switch c.Banner.Backend {
	case "", "iptables", "nftables":
		// ok; "" maps to iptables in the daemon constructor
	default:
		return fmt.Errorf("banner.backend %q: must be iptables or nftables", c.Banner.Backend)
	}
	if c.Banner.Backend != "nftables" {
		return nil
	}
	if c.Banner.Table == "" {
		return fmt.Errorf("banner.table must not be empty when backend=nftables")
	}
	if c.Banner.SetV4 == "" {
		return fmt.Errorf("banner.set_v4 must not be empty when backend=nftables")
	}
	if c.IPv6 && c.Banner.SetV6 == "" {
		return fmt.Errorf("banner.set_v6 must not be empty when ipv6 is true and backend=nftables")
	}
	if c.Banner.Chain == "" {
		return fmt.Errorf("banner.chain must not be empty when backend=nftables")
	}
	return nil
}

func (c *Config) validateSources() (map[string]struct{}, error) {
	names := make(map[string]struct{}, len(c.Sources))
	for i, s := range c.Sources {
		if s.Name == "" {
			return nil, fmt.Errorf("sources[%d]: name must not be empty", i)
		}
		if _, dup := names[s.Name]; dup {
			return nil, fmt.Errorf("sources[%d]: duplicate name %q", i, s.Name)
		}
		names[s.Name] = struct{}{}
		switch s.Type {
		case "file":
			if s.Path == "" {
				return nil, fmt.Errorf("sources[%d] %q: file source requires path", i, s.Name)
			}
		case "docker":
			if s.Container == "" && len(s.Labels) == 0 {
				return nil, fmt.Errorf("sources[%d] %q: docker source requires container or labels", i, s.Name)
			}
		case "journal":
			// Match is optional (empty == follow whole journal).
		default:
			return nil, fmt.Errorf("sources[%d] %q: unknown type %q (want file|docker|journal)", i, s.Name, s.Type)
		}
	}
	return names, nil
}

func (c *Config) validateRules(srcNames map[string]struct{}) error {
	ruleNames := make(map[string]struct{}, len(c.Rules))
	for i, r := range c.Rules {
		if r.Name == "" {
			return fmt.Errorf("rules[%d]: name must not be empty", i)
		}
		if _, dup := ruleNames[r.Name]; dup {
			return fmt.Errorf("rules[%d]: duplicate name %q", i, r.Name)
		}
		ruleNames[r.Name] = struct{}{}
		if _, ok := srcNames[r.Source]; !ok {
			return fmt.Errorf("rules[%d] %q: source %q not defined", i, r.Name, r.Source)
		}
		if err := validateRuleConfig(i, r); err != nil {
			return err
		}
	}
	return nil
}

func validateRuleConfig(i int, r RuleConfig) error {
	if r.Regex == "" {
		return fmt.Errorf("rules[%d] %q: regex must not be empty", i, r.Name)
	}
	re, err := regexp.Compile(r.Regex)
	if err != nil {
		return fmt.Errorf("rules[%d] %q: invalid regex: %w", i, r.Name, err)
	}
	if !hasIPCapture(re) {
		return fmt.Errorf("rules[%d] %q: regex must contain a named capture group (?P<ip>...)", i, r.Name)
	}
	if r.MaxRetries < 1 {
		return fmt.Errorf("rules[%d] %q: max_retries must be >= 1", i, r.Name)
	}
	if r.FindTime <= 0 {
		return fmt.Errorf("rules[%d] %q: findtime must be > 0", i, r.Name)
	}
	if r.BanTime <= 0 {
		return fmt.Errorf("rules[%d] %q: bantime must be > 0", i, r.Name)
	}
	for j, cidr := range r.Allowlist {
		if cidr == "0.0.0.0/0" || cidr == "::/0" {
			return fmt.Errorf("rules[%d] %q: allowlist[%d]=%q would disable the rule (refused)", i, r.Name, j, cidr)
		}
		if _, err := netip.ParsePrefix(cidr); err != nil {
			return fmt.Errorf("rules[%d] %q: allowlist[%d]=%q: %w", i, r.Name, j, cidr, err)
		}
	}
	if r.Datepattern != "" {
		if _, err := datepatternResolve(r.Datepattern); err != nil {
			return fmt.Errorf("rules[%d] %q: %w", i, r.Name, err)
		}
	}
	return nil
}

func hasIPCapture(re *regexp.Regexp) bool {
	for _, name := range re.SubexpNames() {
		if name == "ip" {
			return true
		}
	}
	return false
}
