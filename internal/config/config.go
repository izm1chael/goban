// Package config loads and validates GoBan configuration from defaults, a YAML
// file, and environment overrides (in that order).
package config

import (
	"bytes"
	"fmt"
	"io"
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

	// IPTablesChains are the filter-table chains where the ipset drop rule is
	// installed. INPUT protects host services; FORWARD protects bridged and
	// routed workloads such as normal Docker containers.
	IPTablesChains []string `yaml:"iptables_chains"`

	// nftables-only knobs (iptables uses Config.IPSetNameV4 / V6 instead).
	Table        string `yaml:"table"`
	SetV4        string `yaml:"set_v4"`
	SetV6        string `yaml:"set_v6"`
	Chain        string `yaml:"chain"`         // input-hook chain
	ForwardChain string `yaml:"forward_chain"` // forward-hook chain; empty disables forwarded-traffic protection
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
	Name                string            `yaml:"name"`
	Source              string            `yaml:"source"`
	Regex               string            `yaml:"regex"`
	MaxRetries          int               `yaml:"max_retries"`
	FindTime            time.Duration     `yaml:"findtime"`
	BanTime             time.Duration     `yaml:"bantime"`
	Allowlist           []string          `yaml:"allowlist"`
	Datepattern         string            `yaml:"datepattern"`
	Timezone            string            `yaml:"timezone"`            // IANA name or "Local"; default Local
	DateFailurePolicy   string            `yaml:"date_failure_policy"` // drop (default) or source_time
	Excludes            map[string]string `yaml:"excludes"`
	TrustedProxyCapture string            `yaml:"trusted_proxy_capture"` // named capture containing the direct proxy peer
	TrustedProxies      []string          `yaml:"trusted_proxies"`       // CIDRs permitted to supply the captured client IP
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
		AuditLog:          "/var/log/goban/audit.log",
		StatePath:         "/var/lib/goban/state.gob",
		StateSaveInterval: 30 * time.Second,
		Banner: BannerConfig{
			Backend:        "iptables",
			IPTablesChains: []string{"INPUT", "FORWARD"},
			Table:          "goban",
			SetV4:          "goban-ban-v4",
			SetV6:          "goban-ban-v6",
			Chain:          "input",
			ForwardChain:   "forward",
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
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if err := requireYAMLEOF(dec); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	// Rule defaults are intentionally applied only after every configuration
	// layer (file, environment, CLI, and rules.d) has been merged.
	return cfg, nil
}

func requireYAMLEOF(dec *yaml.Decoder) error {
	var extra yaml.Node
	err := dec.Decode(&extra)
	if err == io.EOF {
		return nil
	}
	if err != nil {
		return err
	}
	return fmt.Errorf("multiple YAML documents are not supported")
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
	for i, cidr := range c.Allowlist {
		if cidr == "0.0.0.0/0" || cidr == "::/0" {
			return fmt.Errorf("allowlist[%d]=%q would disable protection (refused)", i, cidr)
		}
		if _, err := netip.ParsePrefix(cidr); err != nil {
			return fmt.Errorf("allowlist[%d]=%q: %w", i, cidr, err)
		}
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
		if len(c.Banner.IPTablesChains) == 0 {
			return fmt.Errorf("banner.iptables_chains must contain at least one chain")
		}
		seen := make(map[string]struct{}, len(c.Banner.IPTablesChains))
		for i, chain := range c.Banner.IPTablesChains {
			if !validIPTablesChain(chain) {
				return fmt.Errorf("banner.iptables_chains[%d]=%q: invalid chain name (1-28 safe characters)", i, chain)
			}
			if _, dup := seen[chain]; dup {
				return fmt.Errorf("banner.iptables_chains[%d]=%q: duplicate chain", i, chain)
			}
			seen[chain] = struct{}{}
		}
		return nil
	}
	for field, value := range map[string]string{
		"table":  c.Banner.Table,
		"set_v4": c.Banner.SetV4,
		"chain":  c.Banner.Chain,
	} {
		if value == "" {
			return fmt.Errorf("banner.%s must not be empty when backend=nftables", field)
		}
		if !validNFTName(value) {
			return fmt.Errorf("banner.%s=%q: invalid nftables identifier (1-31 safe characters)", field, value)
		}
	}
	if c.IPv6 {
		if c.Banner.SetV6 == "" {
			return fmt.Errorf("banner.set_v6 must not be empty when ipv6 is true and backend=nftables")
		}
		if !validNFTName(c.Banner.SetV6) {
			return fmt.Errorf("banner.set_v6=%q: invalid nftables identifier (1-31 safe characters)", c.Banner.SetV6)
		}
	}
	if c.Banner.ForwardChain != "" && !validNFTName(c.Banner.ForwardChain) {
		return fmt.Errorf("banner.forward_chain=%q: invalid nftables identifier (1-31 safe characters)", c.Banner.ForwardChain)
	}
	return nil
}

func (c *Config) validateSources() (map[string]struct{}, error) {
	names := make(map[string]struct{}, len(c.Sources))
	for i, s := range c.Sources {
		if !validIdentifier(s.Name) {
			return nil, fmt.Errorf("sources[%d]: name %q must match %s", i, s.Name, identifierPattern.String())
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
		if !validIdentifier(r.Name) {
			return fmt.Errorf("rules[%d]: name %q must match %s", i, r.Name, identifierPattern.String())
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
	if r.BanTime < time.Second {
		return fmt.Errorf("rules[%d] %q: bantime must be at least 1s", i, r.Name)
	}
	if r.BanTime/time.Second > time.Duration(^uint32(0)) {
		return fmt.Errorf("rules[%d] %q: bantime exceeds backend maximum of %ds", i, r.Name, uint64(^uint32(0)))
	}
	for j, cidr := range r.Allowlist {
		if cidr == "0.0.0.0/0" || cidr == "::/0" {
			return fmt.Errorf("rules[%d] %q: allowlist[%d]=%q would disable the rule (refused)", i, r.Name, j, cidr)
		}
		if _, err := netip.ParsePrefix(cidr); err != nil {
			return fmt.Errorf("rules[%d] %q: allowlist[%d]=%q: %w", i, r.Name, j, cidr, err)
		}
	}
	captures := captureNames(re)
	if r.DateFailurePolicy != "" && r.DateFailurePolicy != "drop" && r.DateFailurePolicy != "source_time" {
		return fmt.Errorf("rules[%d] %q: date_failure_policy must be drop or source_time", i, r.Name)
	}
	if r.Timezone != "" && r.Timezone != "Local" {
		if _, err := time.LoadLocation(r.Timezone); err != nil {
			return fmt.Errorf("rules[%d] %q: timezone %q: %w", i, r.Name, r.Timezone, err)
		}
	}
	if r.Datepattern != "" {
		if _, err := datepatternResolve(r.Datepattern); err != nil {
			return fmt.Errorf("rules[%d] %q: %w", i, r.Name, err)
		}
		if _, ok := captures["time"]; !ok {
			return fmt.Errorf("rules[%d] %q: datepattern requires a named capture group (?P<time>...)", i, r.Name)
		}
	}
	if (r.TrustedProxyCapture == "") != (len(r.TrustedProxies) == 0) {
		return fmt.Errorf("rules[%d] %q: trusted_proxy_capture and trusted_proxies must be configured together", i, r.Name)
	}
	if r.TrustedProxyCapture != "" {
		if _, ok := captures[r.TrustedProxyCapture]; !ok {
			return fmt.Errorf("rules[%d] %q: trusted_proxy_capture %q does not name a regex capture", i, r.Name, r.TrustedProxyCapture)
		}
		for j, cidr := range r.TrustedProxies {
			if cidr == "0.0.0.0/0" || cidr == "::/0" {
				return fmt.Errorf("rules[%d] %q: trusted_proxies[%d]=%q trusts every sender (refused)", i, r.Name, j, cidr)
			}
			if _, err := netip.ParsePrefix(cidr); err != nil {
				return fmt.Errorf("rules[%d] %q: trusted_proxies[%d]=%q: %w", i, r.Name, j, cidr, err)
			}
		}
	}
	for name, value := range r.Excludes {
		if name == "" {
			return fmt.Errorf("rules[%d] %q: excludes contains an empty capture name", i, r.Name)
		}
		if value == "" {
			return fmt.Errorf("rules[%d] %q: excludes[%q] must not be empty", i, r.Name, name)
		}
		if _, ok := captures[name]; !ok {
			return fmt.Errorf("rules[%d] %q: excludes[%q] does not name a regex capture", i, r.Name, name)
		}
	}
	return nil
}

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
var firewallChainPattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.:-]{0,63}$`)

func validIdentifier(s string) bool { return identifierPattern.MatchString(s) }
func validIPTablesChain(s string) bool {
	return len(s) >= 1 && len(s) <= 28 && firewallChainPattern.MatchString(s)
}
func validNFTName(s string) bool {
	return len(s) >= 1 && len(s) <= 31 && firewallChainPattern.MatchString(s)
}

func captureNames(re *regexp.Regexp) map[string]struct{} {
	out := make(map[string]struct{})
	for _, name := range re.SubexpNames() {
		if name != "" {
			out[name] = struct{}{}
		}
	}
	return out
}

func hasIPCapture(re *regexp.Regexp) bool {
	for _, name := range re.SubexpNames() {
		if name == "ip" {
			return true
		}
	}
	return false
}
