// Package setup detects a Linux host's logging and firewall environment and
// writes a reviewable GoBan configuration proposal. It never starts services
// or edits the live firewall.
package setup

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/izm1chael/goban/internal/config"
)

// Facts are the host observations used to build a setup plan.
type Facts struct {
	GeneratedAt  time.Time `yaml:"generated_at" json:"generated_at"`
	Distribution string    `yaml:"distribution" json:"distribution"`
	Version      string    `yaml:"version,omitempty" json:"version,omitempty"`
	Systemd      bool      `yaml:"systemd" json:"systemd"`
	Journald     bool      `yaml:"journald" json:"journald"`
	NFTables     bool      `yaml:"nftables" json:"nftables"`
	IPTables     bool      `yaml:"iptables" json:"iptables"`
	IPSet        bool      `yaml:"ipset" json:"ipset"`
	Docker       bool      `yaml:"docker" json:"docker"`
	IPv6         bool      `yaml:"ipv6" json:"ipv6"`
	Fail2Ban     bool      `yaml:"fail2ban" json:"fail2ban"`
	Services     []string  `yaml:"services" json:"services"`
	LogFiles     []string  `yaml:"log_files" json:"log_files"`
	Warnings     []string  `yaml:"warnings,omitempty" json:"warnings,omitempty"`
}

// Plan is the deterministic proposal returned by Detect.
type Plan struct {
	Facts          Facts          `yaml:"facts" json:"facts"`
	Config         *config.Config `yaml:"config" json:"config"`
	EnabledBundles []string       `yaml:"enabled_bundles" json:"enabled_bundles"`
}

// Options controls proposal generation.
type Options struct {
	Root           string
	OutputDir      string
	RulesAvailable string
	Overwrite      bool
}

// Detect inspects a host or a fixture root. Root defaults to /. Command
// detection is only performed for the real root; fixture roots rely on files.
func Detect(root string) (Plan, error) {
	if root == "" {
		root = "/"
	}
	facts := Facts{GeneratedAt: time.Now().UTC()}
	facts.Distribution, facts.Version = readOSRelease(root)
	facts.Systemd = exists(root, "/run/systemd/system") || commandAvailable(root, "systemctl")
	facts.Journald = facts.Systemd && (exists(root, "/run/log/journal") || exists(root, "/var/log/journal") || commandAvailable(root, "journalctl"))
	facts.NFTables = commandAvailable(root, "nft") || exists(root, "/etc/nftables.conf")
	facts.IPTables = commandAvailable(root, "iptables")
	facts.IPSet = commandAvailable(root, "ipset")
	facts.Docker = exists(root, "/var/run/docker.sock") || commandAvailable(root, "docker")
	facts.IPv6 = exists(root, "/proc/net/if_inet6")
	facts.Fail2Ban = exists(root, "/etc/fail2ban") || commandAvailable(root, "fail2ban-client")

	cfg := config.DefaultConfig()
	cfg.Sources = nil
	cfg.Rules = nil
	cfg.DryRun = true // setup always begins in observe-only mode
	cfg.IPv6 = facts.IPv6
	if facts.NFTables {
		cfg.Banner.Backend = "nftables"
	} else if facts.IPTables {
		// The iptables backend manages ipset entries through netlink directly;
		// the ipset userspace binary is optional and only useful for diagnostics.
		cfg.Banner.Backend = "iptables"
	} else {
		facts.Warnings = append(facts.Warnings, "no supported nftables or iptables backend was detected")
	}

	bundles := []string{}
	if source, ok := detectSSH(root, facts.Journald); ok {
		cfg.Sources = append(cfg.Sources, source)
		if source.Type == "journal" {
			facts.Warnings = append(facts.Warnings, "OpenSSH requires the journald-enabled GoBan build because no auth log file was found")
		}
		facts.Services = append(facts.Services, "OpenSSH")
		bundles = append(bundles, "sshd.yaml")
		if source.Path != "" {
			facts.LogFiles = append(facts.LogFiles, source.Path)
		}
	}
	if sources, ok := detectNginx(root); ok {
		cfg.Sources = append(cfg.Sources, sources...)
		facts.Services = append(facts.Services, "Nginx")
		bundles = append(bundles, "nginx.yaml")
		for _, source := range sources {
			facts.LogFiles = append(facts.LogFiles, source.Path)
		}
	}
	if sources, ok := detectApache(root); ok {
		cfg.Sources = append(cfg.Sources, sources...)
		facts.Services = append(facts.Services, "Apache HTTP Server")
		bundles = append(bundles, "apache.yaml")
		for _, source := range sources {
			facts.LogFiles = append(facts.LogFiles, source.Path)
		}
	}
	if source, ok := detectMail(root); ok {
		cfg.Sources = append(cfg.Sources, source)
		facts.Services = append(facts.Services, "mail authentication")
		bundles = append(bundles, "postfix.yaml", "dovecot.yaml")
		facts.LogFiles = append(facts.LogFiles, source.Path)
	}
	if exists(root, "/var/log/goban/audit.log") || root == "/" {
		cfg.Sources = append(cfg.Sources, config.SourceConfig{Type: "file", Name: "audit", Path: "/var/log/goban/audit.log"})
		bundles = append(bundles, "recidive.yaml")
	}
	if facts.Docker {
		facts.Warnings = append(facts.Warnings, "Docker was detected; container-specific rule bundles require explicit container names or labels")
	}
	if facts.Fail2Ban {
		facts.Warnings = append(facts.Warnings, "Fail2Ban is installed; use 'goban-client migrate fail2ban' and keep GoBan in dry-run until cutover")
	}
	if len(cfg.Sources) == 0 {
		facts.Warnings = append(facts.Warnings, "no supported service log sources were detected")
	}
	cfg.RulesDir = "/etc/goban/rules.d"
	cfg.ApplyRuleDefaults()
	sort.Strings(facts.Services)
	sort.Strings(facts.LogFiles)
	bundles = uniqueSorted(bundles)
	return Plan{Facts: facts, Config: cfg, EnabledBundles: bundles}, nil
}

// Write writes a staging directory containing goban.yaml, copied rule
// bundles, plan.yaml, and operator instructions.
func Write(plan Plan, opts Options) error {
	if opts.OutputDir == "" {
		return errors.New("output directory is required")
	}
	if opts.RulesAvailable == "" {
		opts.RulesAvailable = "/usr/share/goban/rules-available"
	}
	if err := prepare(opts.OutputDir, opts.Overwrite); err != nil {
		return err
	}
	cfgCopy := *plan.Config
	cfgCopy.RulesDir = "/etc/goban/rules.d"
	cfgData, err := config.EffectiveYAML(&cfgCopy)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(opts.OutputDir, "goban.yaml"), cfgData, 0o640); err != nil {
		return err
	}
	for _, bundle := range plan.EnabledBundles {
		src := filepath.Join(opts.RulesAvailable, bundle)
		data, err := os.ReadFile(src)
		if err != nil {
			return fmt.Errorf("read rule bundle %s: %w", src, err)
		}
		if err := os.WriteFile(filepath.Join(opts.OutputDir, "rules.d", bundle), data, 0o640); err != nil {
			return err
		}
	}
	planData, err := yaml.Marshal(plan)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(opts.OutputDir, "setup-plan.yaml"), planData, 0o640); err != nil {
		return err
	}
	readme := `# GoBan setup proposal

This is a staging directory. The live system has not been changed.

The generated configuration starts with dry_run: true. Keep it that way while
checking rule matches and while any existing Fail2Ban service is enforcing.

Validate:

    goban-client config validate --config ./goban.yaml --rules-dir ./rules.d

Review setup-plan.yaml, especially warnings. Copy the files into /etc/goban
only after confirming log paths and firewall backend. Start GoBan, run
'goban-client doctor --probe', compare dry-run detections, then set dry_run to
false during a controlled cutover.
`
	return os.WriteFile(filepath.Join(opts.OutputDir, "README.md"), []byte(readme), 0o644)
}

func prepare(dir string, overwrite bool) error {
	if entries, err := os.ReadDir(dir); err == nil {
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

func readOSRelease(root string) (string, string) {
	f, err := os.Open(joinRoot(root, "/etc/os-release"))
	if err != nil {
		return "unknown", ""
	}
	defer f.Close()
	values := map[string]string{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "=")
		if ok {
			values[key] = strings.Trim(strings.TrimSpace(value), "\"")
		}
	}
	name := values["PRETTY_NAME"]
	if name == "" {
		name = values["ID"]
	}
	return name, values["VERSION_ID"]
}

func commandAvailable(root, name string) bool {
	if root == "/" {
		_, err := exec.LookPath(name)
		return err == nil
	}
	for _, dir := range []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin"} {
		if exists(root, filepath.Join(dir, name)) {
			return true
		}
	}
	return false
}

func exists(root, path string) bool {
	_, err := os.Stat(joinRoot(root, path))
	return err == nil
}

func joinRoot(root, path string) string {
	if root == "/" {
		return path
	}
	return filepath.Join(root, strings.TrimPrefix(path, "/"))
}

func firstExisting(root string, paths ...string) string {
	for _, path := range paths {
		if exists(root, path) {
			return path
		}
	}
	return ""
}

func detectSSH(root string, journald bool) (config.SourceConfig, bool) {
	path := firstExisting(root, "/var/log/auth.log", "/var/log/secure")
	if path != "" {
		return config.SourceConfig{Type: "file", Name: "auth-log", Path: path}, true
	}
	if journald && (exists(root, "/etc/ssh/sshd_config") || commandAvailable(root, "sshd")) {
		unit := "ssh.service"
		if exists(root, "/usr/lib/systemd/system/sshd.service") || exists(root, "/etc/systemd/system/sshd.service") {
			unit = "sshd.service"
		}
		return config.SourceConfig{Type: "journal", Name: "auth-log", Match: "_SYSTEMD_UNIT=" + unit}, true
	}
	return config.SourceConfig{}, false
}

func detectNginx(root string) ([]config.SourceConfig, bool) {
	access := firstExisting(root, "/var/log/nginx/access.log")
	errorLog := firstExisting(root, "/var/log/nginx/error.log")
	if access == "" && errorLog == "" && !exists(root, "/etc/nginx") {
		return nil, false
	}
	if access == "" {
		access = "/var/log/nginx/access.log"
	}
	return []config.SourceConfig{{Type: "file", Name: "nginx-access", Path: access}}, true
}

func detectApache(root string) ([]config.SourceConfig, bool) {
	access := firstExisting(root, "/var/log/apache2/access.log", "/var/log/httpd/access_log")
	errorLog := firstExisting(root, "/var/log/apache2/error.log", "/var/log/httpd/error_log")
	if access == "" && errorLog == "" && !exists(root, "/etc/apache2") && !exists(root, "/etc/httpd") {
		return nil, false
	}
	if access == "" {
		access = "/var/log/apache2/access.log"
	}
	if errorLog == "" {
		errorLog = "/var/log/apache2/error.log"
	}
	return []config.SourceConfig{{Type: "file", Name: "apache-access", Path: access}, {Type: "file", Name: "apache-error", Path: errorLog}}, true
}

func detectMail(root string) (config.SourceConfig, bool) {
	path := firstExisting(root, "/var/log/mail.log", "/var/log/maillog")
	if path == "" {
		return config.SourceConfig{}, false
	}
	return config.SourceConfig{Type: "file", Name: "mail-log", Path: path}, true
}

func uniqueSorted(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
