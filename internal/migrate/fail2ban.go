// Package migrate converts a conservative subset of Fail2Ban jail
// configuration into a reviewable GoBan staging directory.
package migrate

import (
	"bufio"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/izm1chael/goban/internal/config"
)

// Options controls a Fail2Ban migration. The output is always a staging
// directory; this package never edits /etc/goban or stops either daemon.
type Options struct {
	Root           string
	OutputDir      string
	RulesAvailable string
	Overwrite      bool
}

// JailResult records how one enabled Fail2Ban jail was handled.
type JailResult struct {
	Name        string   `yaml:"name" json:"name"`
	Status      string   `yaml:"status" json:"status"` // converted | review | unsupported
	Rule        string   `yaml:"rule,omitempty" json:"rule,omitempty"`
	Source      string   `yaml:"source,omitempty" json:"source,omitempty"`
	Warnings    []string `yaml:"warnings,omitempty" json:"warnings,omitempty"`
	Unsupported []string `yaml:"unsupported,omitempty" json:"unsupported,omitempty"`
}

// Report is written to migration-report.yaml and returned to callers.
type Report struct {
	GeneratedAt time.Time    `yaml:"generated_at" json:"generated_at"`
	SourceRoot  string       `yaml:"source_root" json:"source_root"`
	OutputDir   string       `yaml:"output_dir" json:"output_dir"`
	Jails       []JailResult `yaml:"jails" json:"jails"`
	Warnings    []string     `yaml:"warnings,omitempty" json:"warnings,omitempty"`
}

type jailMapping struct {
	Bundle     string
	Rule       string
	Source     string
	Journal    string
	DefaultLog string
}

var knownJails = map[string]jailMapping{
	"sshd":             {Bundle: "sshd.yaml", Rule: "sshd", Source: "auth-log", Journal: "_SYSTEMD_UNIT=ssh.service", DefaultLog: "/var/log/auth.log"},
	"nginx-http-auth":  {Bundle: "nginx.yaml", Rule: "nginx-http-auth", Source: "nginx-access", DefaultLog: "/var/log/nginx/error.log"},
	"nginx-botsearch":  {Bundle: "nginx.yaml", Rule: "nginx-probes", Source: "nginx-access", DefaultLog: "/var/log/nginx/access.log"},
	"apache-auth":      {Bundle: "apache.yaml", Rule: "apache-auth", Source: "apache-error", DefaultLog: "/var/log/apache2/error.log"},
	"apache-noscript":  {Bundle: "apache.yaml", Rule: "apache-noscript", Source: "apache-access", DefaultLog: "/var/log/apache2/access.log"},
	"apache-overflows": {Bundle: "apache.yaml", Rule: "apache-overflows", Source: "apache-error", DefaultLog: "/var/log/apache2/error.log"},
	"postfix-sasl":     {Bundle: "postfix.yaml", Rule: "postfix-sasl", Source: "mail-log", DefaultLog: "/var/log/mail.log"},
	"dovecot":          {Bundle: "dovecot.yaml", Rule: "dovecot", Source: "mail-log", DefaultLog: "/var/log/mail.log"},
	"vsftpd":           {Bundle: "vsftpd.yaml", Rule: "vsftpd", Source: "vsftpd-log", DefaultLog: "/var/log/vsftpd.log"},
	"traefik-auth":     {Bundle: "traefik.yaml", Rule: "traefik-auth", Source: "traefik-container"},
	"nextcloud":        {Bundle: "nextcloud.yaml", Rule: "nextcloud-login", Source: "nextcloud-container"},
	"nextcloud-login":  {Bundle: "nextcloud.yaml", Rule: "nextcloud-login", Source: "nextcloud-container"},
	"portainer":        {Bundle: "portainer.yaml", Rule: "portainer-login", Source: "portainer-container"},
	"wordpress-auth":   {Bundle: "wordpress.yaml", Rule: "wordpress-login", Source: "nginx-access", DefaultLog: "/var/log/nginx/access.log"},
	"recidive":         {Bundle: "recidive.yaml", Rule: "recidive", Source: "audit", DefaultLog: "/var/log/goban/audit.log"},
}

type section map[string]string

type ini struct {
	Defaults section
	Sections map[string]section
}

// Convert creates a reviewable migration directory containing goban.yaml,
// selected rules.d files, a report, and rollback/parallel-observation notes.
func Convert(opts Options) (Report, error) {
	if opts.Root == "" {
		opts.Root = "/etc/fail2ban"
	}
	if opts.OutputDir == "" {
		return Report{}, errors.New("output directory is required")
	}
	if opts.RulesAvailable == "" {
		opts.RulesAvailable = "/usr/share/goban/rules-available"
	}
	if err := prepareOutput(opts.OutputDir, opts.Overwrite); err != nil {
		return Report{}, err
	}

	files, err := discoverFiles(opts.Root)
	if err != nil {
		return Report{}, err
	}
	parsed := ini{Defaults: section{}, Sections: map[string]section{}}
	for _, path := range files {
		if err := mergeINIFile(path, &parsed); err != nil {
			return Report{}, err
		}
	}

	cfg := config.DefaultConfig()
	cfg.Rules = nil
	cfg.Sources = nil
	cfg.RulesDir = "/etc/goban/rules.d"
	cfg.DryRun = true
	cfg.Allowlist = append([]string(nil), cfg.Allowlist...)
	report := Report{GeneratedAt: time.Now().UTC(), SourceRoot: opts.Root, OutputDir: opts.OutputDir}
	if ignore := parsed.Defaults["ignoreip"]; ignore != "" {
		prefixes, warnings := normaliseIgnoreIP(ignore)
		cfg.Allowlist = appendUnique(cfg.Allowlist, prefixes...)
		report.Warnings = append(report.Warnings, warnings...)
	}
	sources := map[string]config.SourceConfig{}
	rulesByBundle := map[string][]config.RuleConfig{}
	selectedRules := map[string]string{}

	names := make([]string, 0, len(parsed.Sections))
	for name := range parsed.Sections {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		values := overlay(parsed.Defaults, parsed.Sections[name])
		if !parseBool(values["enabled"]) {
			continue
		}
		jr := JailResult{Name: name}
		mapping, ok := knownJails[strings.ToLower(name)]
		if !ok {
			jr.Status = "unsupported"
			jr.Unsupported = []string{"no reviewed GoBan rule mapping exists for this jail"}
			if values["filter"] != "" {
				jr.Unsupported = append(jr.Unsupported, "custom/alternate filter: "+values["filter"])
			}
			report.Jails = append(report.Jails, jr)
			continue
		}

		rule, err := loadSelectedRule(opts.RulesAvailable, mapping)
		if err != nil {
			jr.Status = "unsupported"
			jr.Unsupported = []string{err.Error()}
			report.Jails = append(report.Jails, jr)
			continue
		}
		jr.Rule, jr.Source = rule.Name, mapping.Source
		if previous, exists := selectedRules[rule.Name]; exists {
			jr.Status = "review"
			jr.Warnings = append(jr.Warnings, fmt.Sprintf("rule %s was already selected by jail %s; skipped duplicate", rule.Name, previous))
			report.Jails = append(report.Jails, jr)
			continue
		}
		selectedRules[rule.Name] = name
		rule.Source = mapping.Source
		applyJailTiming(&rule, values, &jr)
		if ignore := values["ignoreip"]; ignore != "" {
			prefixes, warnings := normaliseIgnoreIP(ignore)
			rule.Allowlist = appendUnique(rule.Allowlist, prefixes...)
			jr.Warnings = append(jr.Warnings, warnings...)
		}

		source, sourceWarnings, sourceUnsupported := sourceFor(mapping, values)
		jr.Warnings = append(jr.Warnings, sourceWarnings...)
		jr.Unsupported = append(jr.Unsupported, sourceUnsupported...)
		if existing, exists := sources[source.Name]; exists && !sameSource(existing, source) {
			jr.Warnings = append(jr.Warnings, fmt.Sprintf("source %s had conflicting log settings; kept %s", source.Name, describeSource(existing)))
		} else {
			sources[source.Name] = source
		}

		for _, key := range []string{"action", "banaction", "mta", "destemail", "sender", "protocol", "port"} {
			if value := strings.TrimSpace(values[key]); value != "" && !isDefaultActionValue(key, value) {
				jr.Unsupported = append(jr.Unsupported, fmt.Sprintf("%s=%s", key, value))
			}
		}
		if len(jr.Unsupported) > 0 || len(jr.Warnings) > 0 {
			jr.Status = "review"
		} else {
			jr.Status = "converted"
		}
		rulesByBundle[mapping.Bundle] = append(rulesByBundle[mapping.Bundle], rule)
		report.Jails = append(report.Jails, jr)
	}

	if len(report.Jails) == 0 {
		report.Warnings = append(report.Warnings, "no enabled Fail2Ban jails were found")
	}
	for _, source := range sources {
		cfg.Sources = append(cfg.Sources, source)
	}
	sort.Slice(cfg.Sources, func(i, j int) bool { return cfg.Sources[i].Name < cfg.Sources[j].Name })
	cfg.ApplyRuleDefaults()

	if err := writeMigration(opts.OutputDir, cfg, rulesByBundle, report); err != nil {
		return Report{}, err
	}
	return report, nil
}

func prepareOutput(dir string, overwrite bool) error {
	if st, err := os.Stat(dir); err == nil {
		if !st.IsDir() {
			return fmt.Errorf("output %s is not a directory", dir)
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return err
		}
		if len(entries) > 0 && !overwrite {
			return fmt.Errorf("output directory %s is not empty (use --overwrite)", dir)
		}
		if overwrite {
			if err := os.RemoveAll(dir); err != nil {
				return err
			}
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	return os.MkdirAll(filepath.Join(dir, "rules.d"), 0o755)
}

func discoverFiles(root string) ([]string, error) {
	if st, err := os.Stat(root); err != nil || !st.IsDir() {
		if err == nil {
			err = fmt.Errorf("not a directory")
		}
		return nil, fmt.Errorf("Fail2Ban root %s: %w", root, err)
	}
	var files []string
	add := func(path string) {
		if st, err := os.Stat(path); err == nil && !st.IsDir() {
			files = append(files, path)
		}
	}
	add(filepath.Join(root, "jail.conf"))
	conf, _ := filepath.Glob(filepath.Join(root, "jail.d", "*.conf"))
	sort.Strings(conf)
	files = append(files, conf...)
	add(filepath.Join(root, "jail.local"))
	local, _ := filepath.Glob(filepath.Join(root, "jail.d", "*.local"))
	sort.Strings(local)
	files = append(files, local...)
	if len(files) == 0 {
		return nil, fmt.Errorf("no jail.conf, jail.local, or jail.d files found under %s", root)
	}
	return files, nil
}

func mergeINIFile(path string, out *ini) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	current := "DEFAULT"
	var lastKey string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	for lineNo := 1; scanner.Scan(); lineNo++ {
		raw := scanner.Text()
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
			current = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(trimmed, "["), "]"))
			if current == "" {
				return fmt.Errorf("%s:%d: empty section", path, lineNo)
			}
			if !strings.EqualFold(current, "DEFAULT") && out.Sections[current] == nil {
				out.Sections[current] = section{}
			}
			lastKey = ""
			continue
		}
		target := out.Defaults
		if !strings.EqualFold(current, "DEFAULT") {
			target = out.Sections[current]
		}
		if (strings.HasPrefix(raw, " ") || strings.HasPrefix(raw, "\t")) && lastKey != "" && !strings.Contains(trimmed, "=") {
			target[lastKey] = strings.TrimSpace(target[lastKey] + " " + trimmed)
			continue
		}
		key, value, ok := strings.Cut(trimmed, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(stripInlineComment(value))
		target[key] = value
		lastKey = key
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	return nil
}

func stripInlineComment(value string) string {
	for i := 0; i < len(value); i++ {
		if (value[i] == '#' || value[i] == ';') && (i == 0 || value[i-1] == ' ' || value[i-1] == '\t') {
			return strings.TrimSpace(value[:i])
		}
	}
	return value
}

func overlay(base, override section) section {
	out := section{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range override {
		out[k] = v
	}
	return out
}

func parseBool(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "yes", "true", "on":
		return true
	default:
		return false
	}
}

func splitWords(value string) []string {
	return strings.Fields(strings.ReplaceAll(value, ",", " "))
}

func appendUnique(values []string, additions ...string) []string {
	seen := make(map[string]struct{}, len(values)+len(additions))
	out := make([]string, 0, len(values)+len(additions))
	for _, value := range append(append([]string(nil), values...), additions...) {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func normaliseIgnoreIP(value string) ([]string, []string) {
	var prefixes, warnings []string
	for _, item := range splitWords(value) {
		if prefix, err := netip.ParsePrefix(item); err == nil {
			prefixes = append(prefixes, prefix.Masked().String())
			continue
		}
		if addr, err := netip.ParseAddr(item); err == nil {
			bits := 128
			if addr.Is4() {
				bits = 32
			}
			prefixes = append(prefixes, netip.PrefixFrom(addr, bits).String())
			continue
		}
		warnings = append(warnings, "ignoreip entry requires manual review (not an IP/CIDR): "+item)
	}
	return prefixes, warnings
}

func loadSelectedRule(dir string, mapping jailMapping) (config.RuleConfig, error) {
	rules, err := config.LoadRulesFile(filepath.Join(dir, mapping.Bundle))
	if err != nil {
		return config.RuleConfig{}, fmt.Errorf("load %s: %w", mapping.Bundle, err)
	}
	for _, rule := range rules {
		if rule.Name == mapping.Rule {
			return rule, nil
		}
	}
	return config.RuleConfig{}, fmt.Errorf("rule %s not found in %s", mapping.Rule, mapping.Bundle)
}

func applyJailTiming(rule *config.RuleConfig, values section, jr *JailResult) {
	if v := values["maxretry"]; v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			rule.MaxRetries = n
		} else {
			jr.Warnings = append(jr.Warnings, "could not convert maxretry="+v)
		}
	}
	if v := values["findtime"]; v != "" {
		if d, err := parseF2BDuration(v); err == nil {
			rule.FindTime = d
		} else {
			jr.Warnings = append(jr.Warnings, "could not convert findtime="+v)
		}
	}
	if v := values["bantime"]; v != "" {
		if d, err := parseF2BDuration(v); err == nil {
			rule.BanTime = d
		} else {
			jr.Warnings = append(jr.Warnings, "could not convert bantime="+v)
		}
	}
}

func parseF2BDuration(value string) (time.Duration, error) {
	value = strings.TrimSpace(value)
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		if seconds < 1 {
			return 0, errors.New("duration must be positive")
		}
		return time.Duration(seconds) * time.Second, nil
	}
	if strings.HasSuffix(value, "d") || strings.HasSuffix(value, "w") {
		n, err := strconv.ParseInt(value[:len(value)-1], 10, 64)
		if err != nil || n < 1 {
			return 0, errors.New("invalid duration")
		}
		if strings.HasSuffix(value, "d") {
			return time.Duration(n) * 24 * time.Hour, nil
		}
		return time.Duration(n) * 7 * 24 * time.Hour, nil
	}
	return time.ParseDuration(value)
}

func sourceFor(mapping jailMapping, values section) (config.SourceConfig, []string, []string) {
	var warnings, unsupported []string
	backend := strings.ToLower(values["backend"])
	logpath := firstUsableLogPath(values["logpath"])
	if mapping.Rule == "nginx-http-auth" && strings.Contains(strings.ToLower(logpath), "error") {
		warnings = append(warnings, "GoBan's reviewed nginx-http-auth rule consumes access-log 401 records; replaced the Fail2Ban error-log path")
		logpath = mapping.DefaultLog
	}
	if mapping.Rule == "recidive" && logpath != "" && logpath != mapping.DefaultLog {
		warnings = append(warnings, "GoBan recidive consumes GoBan's confirmed audit stream, not fail2ban.log")
		logpath = mapping.DefaultLog
	}
	if mapping.Source == "traefik-container" || mapping.Source == "nextcloud-container" || mapping.Source == "portainer-container" {
		container := strings.TrimSpace(values["container"])
		if container == "" {
			container = strings.TrimSuffix(mapping.Source, "-container")
			warnings = append(warnings, "container selector was inferred; confirm the Docker container name or labels")
		}
		return config.SourceConfig{Type: "docker", Name: mapping.Source, Container: container}, warnings, unsupported
	}
	if backend == "systemd" || backend == "journal" {
		match := strings.TrimSpace(values["journalmatch"])
		if match == "" {
			match = mapping.Journal
		}
		if match == "" {
			warnings = append(warnings, "Fail2Ban used journald but no reviewed journal match exists; using the detected file/default path")
		} else {
			return config.SourceConfig{Type: "journal", Name: mapping.Source, Match: match}, warnings, unsupported
		}
	}
	if logpath == "" {
		logpath = mapping.DefaultLog
	}
	if strings.Contains(logpath, "%(") || strings.Contains(logpath, "${") {
		unsupported = append(unsupported, "unresolved Fail2Ban logpath interpolation: "+logpath)
		logpath = mapping.DefaultLog
	}
	if strings.ContainsAny(logpath, "*?[") {
		unsupported = append(unsupported, "GoBan file sources do not expand Fail2Ban logpath globs: "+logpath)
		if mapping.DefaultLog != "" {
			logpath = mapping.DefaultLog
		}
	}
	if logpath == "" {
		unsupported = append(unsupported, "no file log path or journal mapping available")
	}
	return config.SourceConfig{Type: "file", Name: mapping.Source, Path: logpath}, warnings, unsupported
}

func firstUsableLogPath(value string) string {
	for _, field := range strings.Fields(strings.ReplaceAll(value, "\n", " ")) {
		if strings.HasPrefix(field, "/") {
			return field
		}
	}
	return ""
}

func sameSource(a, b config.SourceConfig) bool {
	return a.Type == b.Type && a.Name == b.Name && a.Path == b.Path && a.Match == b.Match && a.Container == b.Container
}

func describeSource(s config.SourceConfig) string {
	switch s.Type {
	case "file":
		return "file:" + s.Path
	case "journal":
		return "journal:" + s.Match
	case "docker":
		return "docker:" + s.Container
	default:
		return s.Type
	}
}

func isDefaultActionValue(key, value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	switch key {
	case "protocol":
		return value == "tcp" || value == "all"
	case "port":
		return value == "ssh" || value == "http,https" || value == "http" || value == "allports"
	case "action", "banaction":
		return value == "" || strings.HasPrefix(value, "iptables") || strings.HasPrefix(value, "nftables")
	default:
		return false
	}
}

// outputRule keeps migration artifacts human-reviewable. time.Duration's
// default YAML representation is an integer number of nanoseconds, which is
// valid but unsafe for an operator to review during a security cutover.
type outputRule struct {
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

func marshalRuleBundle(rules []config.RuleConfig) ([]byte, error) {
	out := struct {
		Rules []outputRule `yaml:"rules"`
	}{Rules: make([]outputRule, 0, len(rules))}
	for _, rule := range rules {
		out.Rules = append(out.Rules, outputRule{
			Name:                rule.Name,
			Source:              rule.Source,
			Regex:               rule.Regex,
			MaxRetries:          rule.MaxRetries,
			FindTime:            rule.FindTime.String(),
			BanTime:             rule.BanTime.String(),
			Allowlist:           rule.Allowlist,
			Datepattern:         rule.Datepattern,
			Timezone:            rule.Timezone,
			DateFailurePolicy:   rule.DateFailurePolicy,
			Excludes:            rule.Excludes,
			TrustedProxyCapture: rule.TrustedProxyCapture,
			TrustedProxies:      rule.TrustedProxies,
		})
	}
	return yaml.Marshal(out)
}

func writeMigration(dir string, cfg *config.Config, rules map[string][]config.RuleConfig, report Report) error {
	cfgData, err := config.EffectiveYAML(cfg)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "goban.yaml"), cfgData, 0o640); err != nil {
		return err
	}
	bundles := make([]string, 0, len(rules))
	for bundle := range rules {
		bundles = append(bundles, bundle)
	}
	sort.Strings(bundles)
	for _, bundle := range bundles {
		data, err := marshalRuleBundle(rules[bundle])
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, "rules.d", bundle), data, 0o640); err != nil {
			return err
		}
	}
	reportData, err := yaml.Marshal(report)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "migration-report.yaml"), reportData, 0o640); err != nil {
		return err
	}
	readme := `# GoBan migration staging directory

This directory was generated from Fail2Ban configuration. It is deliberately
not installed automatically.

1. Review migration-report.yaml. Any jail marked review or unsupported needs
   operator attention.
2. Validate the staged configuration:

       goban-client config validate --config ./goban.yaml --rules-dir ./rules.d

3. Run GoBan in dry-run/observe-only mode while Fail2Ban remains active. Do not
   let both products enforce the same events at the same time.
4. Compare detections and false positives, then schedule a controlled cutover.
5. Back up /etc/fail2ban and /etc/goban before copying staged files.

Rollback: stop GoBan, restore the previous GoBan configuration, re-enable
Fail2Ban, and verify both firewall state and the Fail2Ban service.
`
	return os.WriteFile(filepath.Join(dir, "README.md"), []byte(readme), 0o644)
}
