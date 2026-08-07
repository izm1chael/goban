// Command goban-client talks to goban-daemon over its unix socket.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/rs/zerolog"

	"github.com/izm1chael/goban/internal/allowlist"
	"github.com/izm1chael/goban/internal/banner"
	"github.com/izm1chael/goban/internal/config"
	"github.com/izm1chael/goban/internal/control"
	"github.com/izm1chael/goban/internal/matcher"
	"github.com/izm1chael/goban/internal/migrate"
	"github.com/izm1chael/goban/internal/rule"
	setupplan "github.com/izm1chael/goban/internal/setup"
	"github.com/izm1chael/goban/internal/source"
)

var version = "dev"

const defaultSocket = "/run/goban/goban.sock"

func usage() {
	fmt.Fprintf(os.Stderr, `goban-client — talk to a running goban daemon

Usage:
  goban-client [--sock PATH] <command> [args]

Commands:
  status                       show daemon status
  doctor [--probe]             verify live protection and optional kernel write path
  rules                        list rules with hit/ban counters
  sources                      show live source health and queue drops
  list                         list currently-banned IPs
  explain <ip|decision-id>     explain an active decision and its evidence
  unban <ip>                   remove a ban
  ban <ip> --rule manual [--ttl 1h]   manually ban an IP (flags may appear before or after IP)
  rule test --rule NAME <file|->      simulate the production rule pipeline
  config validate [flags]      validate the exact effective startup config
  config show-effective [flags]       print the resolved effective config
  setup [flags]                detect the host and write a dry-run setup proposal
  migrate fail2ban [flags]     convert enabled Fail2Ban jails into a staging directory
  reload                       reload config from disk (validate-then-swap)
  version                      print client version

Global flags:
  --sock PATH                  daemon socket path (default %s)
  --json                       emit JSON instead of formatted text
`, defaultSocket)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "goban-client:", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	sock := defaultSocket
	asJSON := false
	args := os.Args[1:]
	args = extractFlag(args, "--sock", func(v string) { sock = v })
	args, asJSON = extractBoolFlag(args, "--json")

	if len(args) == 0 {
		usage()
		os.Exit(2)
	}
	cmd, rest := args[0], args[1:]

	c := control.NewClient(sock)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	switch cmd {
	case "status":
		return doStatus(ctx, c, asJSON)
	case "doctor":
		return doDoctor(ctx, c, rest, asJSON)
	case "rules":
		return doRules(ctx, c, asJSON)
	case "sources":
		return doSources(ctx, c, asJSON)
	case "list", "banned":
		return doList(ctx, c, asJSON)
	case "explain":
		return doExplain(ctx, c, rest, asJSON)
	case "unban":
		return doUnban(ctx, c, rest)
	case "ban":
		return doBan(ctx, c, rest)
	case "test":
		return doTest(ctx, c, rest) // compatibility alias
	case "rule":
		if len(rest) == 0 || rest[0] != "test" {
			return fmt.Errorf("usage: goban-client rule test --rule NAME [--config PATH] [--rules-dir DIR] <logfile|->")
		}
		return doTest(ctx, c, rest[1:])
	case "config":
		return doConfig(rest, asJSON)
	case "setup":
		return doSetup(rest, asJSON)
	case "migrate":
		return doMigrate(rest, asJSON)
	case "reload":
		return doReload(ctx, c)
	case "version":
		fmt.Println(version)
		return nil
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		return fmt.Errorf("unknown command %q", cmd)
	}
}

func doSetup(args []string, asJSON bool) error {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	root := fs.String("root", "/", "filesystem root to inspect (used by tests/chroots)")
	out := fs.String("out", "./goban-setup", "staging directory to write")
	rulesAvailable := fs.String("rules-available", defaultRulesAvailable(), "directory containing reviewed GoBan rule bundles")
	write := fs.Bool("write", false, "write the proposal to --out")
	overwrite := fs.Bool("overwrite", false, "replace a non-empty output directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("usage: goban-client setup [--root /] [--write] [--out DIR] [--rules-available DIR]")
	}
	plan, err := setupplan.Detect(*root)
	if err != nil {
		return err
	}
	if *write {
		if err := setupplan.Write(plan, setupplan.Options{Root: *root, OutputDir: *out, RulesAvailable: *rulesAvailable, Overwrite: *overwrite}); err != nil {
			return err
		}
	}
	if asJSON {
		return printJSON(plan)
	}
	fmt.Printf("Detected host: %s", plan.Facts.Distribution)
	if plan.Facts.Version != "" {
		fmt.Printf(" %s", plan.Facts.Version)
	}
	fmt.Println()
	fmt.Printf("Firewall: nftables=%t iptables=%t ipset=%t IPv6=%t\n", plan.Facts.NFTables, plan.Facts.IPTables, plan.Facts.IPSet, plan.Facts.IPv6)
	fmt.Printf("Logging: systemd=%t journald=%t Docker=%t\n", plan.Facts.Systemd, plan.Facts.Journald, plan.Facts.Docker)
	fmt.Printf("Detected services: %s\n", valueOr(strings.Join(plan.Facts.Services, ", "), "none"))
	backend := plan.Config.Banner.Backend
	if !plan.Facts.NFTables && !(plan.Facts.IPTables && plan.Facts.IPSet) {
		backend = "none detected (iptables placeholder; dry-run only)"
	}
	fmt.Printf("Proposed backend: %s\n", backend)
	fmt.Printf("Proposed bundles: %s\n", valueOr(strings.Join(plan.EnabledBundles, ", "), "none"))
	fmt.Println("Safety mode: dry_run=true")
	for _, warning := range plan.Facts.Warnings {
		fmt.Printf("WARNING: %s\n", warning)
	}
	if *write {
		abs, _ := filepath.Abs(*out)
		fmt.Printf("Staging directory written: %s\n", abs)
		fmt.Printf("Validate: goban-client config validate --config %s --rules-dir %s\n", filepath.Join(abs, "goban.yaml"), filepath.Join(abs, "rules.d"))
	} else {
		fmt.Println("No files changed. Re-run with --write to create a staging directory.")
	}
	return nil
}

func doMigrate(args []string, asJSON bool) error {
	if len(args) == 0 || args[0] != "fail2ban" {
		return fmt.Errorf("usage: goban-client migrate fail2ban [--root /etc/fail2ban] --out DIR [--rules-available DIR] [--overwrite]")
	}
	fs := flag.NewFlagSet("migrate fail2ban", flag.ContinueOnError)
	root := fs.String("root", "/etc/fail2ban", "Fail2Ban configuration root")
	out := fs.String("out", "./goban-migration", "staging directory to write")
	rulesAvailable := fs.String("rules-available", defaultRulesAvailable(), "directory containing reviewed GoBan rule bundles")
	overwrite := fs.Bool("overwrite", false, "replace a non-empty output directory")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	report, err := migrate.Convert(migrate.Options{Root: *root, OutputDir: *out, RulesAvailable: *rulesAvailable, Overwrite: *overwrite})
	if err != nil {
		return err
	}
	if asJSON {
		return printJSON(report)
	}
	converted, review, unsupported := 0, 0, 0
	for _, jail := range report.Jails {
		switch jail.Status {
		case "converted":
			converted++
		case "review":
			review++
		case "unsupported":
			unsupported++
		}
		fmt.Printf("%-12s %-24s", strings.ToUpper(jail.Status), jail.Name)
		if jail.Rule != "" {
			fmt.Printf(" -> %s", jail.Rule)
		}
		fmt.Println()
		for _, warning := range jail.Warnings {
			fmt.Printf("  review: %s\n", warning)
		}
		for _, item := range jail.Unsupported {
			fmt.Printf("  unsupported: %s\n", item)
		}
	}
	fmt.Printf("\nConverted: %d  Review: %d  Unsupported: %d\n", converted, review, unsupported)
	abs, _ := filepath.Abs(*out)
	fmt.Printf("Staging directory: %s\n", abs)
	fmt.Printf("Validate: goban-client config validate --config %s --rules-dir %s\n", filepath.Join(abs, "goban.yaml"), filepath.Join(abs, "rules.d"))
	return nil
}

func defaultRulesAvailable() string {
	for _, candidate := range []string{"/usr/share/goban/rules-available", "./examples/rules.d"} {
		if st, err := os.Stat(candidate); err == nil && st.IsDir() {
			return candidate
		}
	}
	return "/usr/share/goban/rules-available"
}

func doStatus(ctx context.Context, c *control.Client, asJSON bool) error {
	st, err := c.Status(ctx)
	if err != nil {
		return err
	}
	if asJSON {
		return printJSON(st)
	}
	fmt.Printf("version:    %s\n", st.Version)
	fmt.Printf("uptime:     %s\n", st.Uptime)
	fmt.Printf("started:    %s\n", st.StartedAt.Format(time.RFC3339))
	fmt.Printf("sources:    %d (%d degraded)\n", st.NumSources, st.DegradedSources)
	fmt.Printf("dropped:    %d lines\n", st.DroppedLines)
	fmt.Printf("memory:     %d bytes\n", st.MemoryBytes)
	fmt.Printf("goroutines: %d\n", st.Goroutines)
	if st.EnforcementMode != "" {
		fmt.Printf("enforcement: %s\n", st.EnforcementMode)
	}
	if st.BannerError != "" {
		fmt.Printf("banner:     ERROR: %s\n", st.BannerError)
	}
	fmt.Printf("rules:      %d\n", st.NumRules)
	fmt.Printf("total bans: %d\n", st.TotalBans)
	return nil
}

func doDoctor(ctx context.Context, c *control.Client, args []string, asJSON bool) error {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	probe := fs.Bool("probe", false, "perform a temporary kernel insert/list/remove probe")
	probeIP := fs.String("probe-ip", "", "non-production address to use for --probe")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("usage: goban-client doctor [--probe] [--probe-ip 192.0.2.254]")
	}
	result, err := c.Doctor(ctx, control.DoctorReq{Probe: *probe, ProbeIP: *probeIP})
	if err != nil {
		return err
	}
	if asJSON {
		return printJSON(result)
	}
	fmt.Printf("GoBan protection: %s\nChecked: %s\n\n", strings.ToUpper(strings.ReplaceAll(result.Overall, "_", " ")), result.CheckedAt.Format(time.RFC3339))
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "STATUS\tCHECK\tDETAIL")
	for _, check := range result.Checks {
		fmt.Fprintf(w, "%s\t%s\t%s\n", strings.ToUpper(check.Status), check.Name, check.Detail)
		if check.Remediation != "" {
			fmt.Fprintf(w, "\t↳ action\t%s\n", check.Remediation)
		}
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if result.Overall == "not_enforcing" {
		return fmt.Errorf("host is not fully enforcing protection")
	}
	return nil
}

func doExplain(ctx context.Context, c *control.Client, args []string, asJSON bool) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: goban-client explain <ip|decision-id>")
	}
	needle := args[0]
	bans, err := c.Banned(ctx)
	if err != nil {
		return err
	}
	var found *control.BanInfo
	for i := range bans {
		if bans[i].IP == needle || bans[i].DecisionID == needle {
			found = &bans[i]
			break
		}
	}
	if found == nil {
		if _, err := netip.ParseAddr(needle); err == nil {
			return fmt.Errorf("%s is not currently banned", needle)
		}
		return fmt.Errorf("decision %q was not found among active bans", needle)
	}
	if asJSON {
		return printJSON(found)
	}
	fmt.Printf("Decision:    %s\n", valueOr(found.DecisionID, "legacy/unattributed"))
	fmt.Printf("Subject:     %s\n", found.IP)
	fmt.Printf("Rule:        %s\n", valueOr(found.Rule, "unknown"))
	fmt.Printf("Source:      %s\n", valueOr(found.Source, "unknown"))
	fmt.Printf("Origin:      %s\n", valueOr(found.Origin, "unknown"))
	if !found.BannedAt.IsZero() {
		fmt.Printf("Applied:     %s\n", found.BannedAt.Format(time.RFC3339))
	}
	fmt.Printf("Remaining:   %s\n", found.TTL)
	if !found.ExpiresAt.IsZero() {
		fmt.Printf("Expires:     %s\n", found.ExpiresAt.Format(time.RFC3339))
	}
	if found.EvidenceCount > 0 {
		fmt.Printf("Evidence:    %d accepted strikes\n", found.EvidenceCount)
		fmt.Printf("Window:      %s → %s\n", found.FirstSeen.Format(time.RFC3339), found.LastSeen.Format(time.RFC3339))
	} else if found.Origin == "manual" {
		fmt.Println("Evidence:    manual operator decision")
	} else {
		fmt.Println("Evidence:    unavailable (legacy decision metadata)")
	}

	rules, err := c.Rules(ctx)
	if err == nil {
		for _, r := range rules {
			if r.Name == found.Rule {
				fmt.Printf("Threshold:   %d accepted strikes within %s\n", r.Threshold, r.FindTime)
				fmt.Printf("Ban policy:  %s\n", r.BanTime)
				break
			}
		}
	}
	return nil
}

func valueOr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func doConfig(args []string, asJSON bool) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: goban-client config <validate|show-effective> [--config PATH] [--rules-dir DIR]")
	}
	action, rest := args[0], args[1:]
	fs := flag.NewFlagSet("config "+action, flag.ContinueOnError)
	path := fs.String("config", "/etc/goban/goban.yaml", "main configuration file")
	rulesDir := fs.String("rules-dir", "", "override rules directory")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	cfg, err := config.LoadEffective(*path, *rulesDir)
	if err != nil {
		return fmt.Errorf("effective configuration is invalid: %w", err)
	}
	switch action {
	case "validate":
		if asJSON {
			return printJSON(map[string]any{"valid": true, "config": *path, "sources": len(cfg.Sources), "rules": len(cfg.Rules), "backend": cfg.Banner.Backend})
		}
		backend := cfg.Banner.Backend
		if backend == "" {
			backend = "iptables"
		}
		fmt.Printf("valid: %s\nsources: %d\nrules: %d\nbackend: %s\n", *path, len(cfg.Sources), len(cfg.Rules), backend)
		return nil
	case "show-effective":
		if asJSON {
			return printJSON(cfg)
		}
		data, err := config.EffectiveYAML(cfg)
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(data)
		return err
	default:
		return fmt.Errorf("unknown config command %q", action)
	}
}

func doRules(ctx context.Context, c *control.Client, asJSON bool) error {
	rules, err := c.Rules(ctx)
	if err != nil {
		return err
	}
	if asJSON {
		return printJSON(rules)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tSOURCE\tTHRESHOLD\tFINDTIME\tBANTIME\tTRACKED\tHITS\tBANS\tMISSES\tDATE_DROPS")
	for _, r := range rules {
		fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\t%d\t%d\t%d\t%d\t%d\n",
			r.Name, r.Source, r.Threshold, r.FindTime, r.BanTime,
			r.Tracked, r.Hits, r.Bans, r.Misses, r.DateDrops)
	}
	return w.Flush()
}

func doSources(ctx context.Context, c *control.Client, asJSON bool) error {
	sources, err := c.Sources(ctx)
	if err != nil {
		return err
	}
	if asJSON {
		return printJSON(sources)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tSTATUS\tSUBSCRIBERS\tDELIVERED\tDROPPED\tRECONNECTS\tLAST_EVENT\tLAST_ERROR")
	for _, src := range sources {
		lastEvent := "-"
		if !src.LastEventAt.IsZero() {
			lastEvent = src.LastEventAt.Format(time.RFC3339)
		}
		fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%d\t%d\t%s\t%s\n",
			src.Name, src.Status, src.Subscribers, src.Delivered, src.Dropped,
			src.Reconnects, lastEvent, src.LastError)
	}
	return w.Flush()
}

func doList(ctx context.Context, c *control.Client, asJSON bool) error {
	bans, err := c.Banned(ctx)
	if err != nil {
		return err
	}
	if asJSON {
		return printJSON(bans)
	}
	if len(bans) == 0 {
		fmt.Println("no active bans")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "IP\tRULE\tDECISION\tTTL\tEXPIRES")
	for _, b := range bans {
		exp := "permanent"
		if !b.ExpiresAt.IsZero() {
			exp = b.ExpiresAt.Format(time.RFC3339)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", b.IP, b.Rule, valueOr(b.DecisionID, "legacy"), b.TTL, exp)
	}
	return w.Flush()
}

func doUnban(ctx context.Context, c *control.Client, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: goban-client unban <ip>")
	}
	if err := c.Unban(ctx, args[0]); err != nil {
		return err
	}
	fmt.Printf("unbanned %s\n", args[0])
	return nil
}

func doBan(ctx context.Context, c *control.Client, args []string) error {
	ip, ruleName, ttl, err := parseBanArgs(args)
	if err != nil {
		return err
	}
	if err := c.Ban(ctx, ip, ruleName, ttl); err != nil {
		return err
	}
	fmt.Printf("banned %s for %s (rule=%s)\n", ip, ttl, ruleName)
	return nil
}

func parseBanArgs(args []string) (string, string, time.Duration, error) {
	ruleName := ""
	ttlRaw := time.Hour.String()
	positional := make([]string, 0, 1)

	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--rule":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return "", "", 0, fmt.Errorf("--rule requires a value")
			}
			i++
			ruleName = args[i]
		case strings.HasPrefix(a, "--rule="):
			ruleName = strings.TrimPrefix(a, "--rule=")
		case a == "--ttl":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return "", "", 0, fmt.Errorf("--ttl requires a duration")
			}
			i++
			ttlRaw = args[i]
		case strings.HasPrefix(a, "--ttl="):
			ttlRaw = strings.TrimPrefix(a, "--ttl=")
		case strings.HasPrefix(a, "-"):
			return "", "", 0, fmt.Errorf("unknown ban flag %q", a)
		default:
			positional = append(positional, a)
		}
	}

	if len(positional) != 1 {
		return "", "", 0, fmt.Errorf("usage: goban-client ban <ip> --rule manual [--ttl 1h]")
	}
	if ruleName == "" {
		return "", "", 0, fmt.Errorf("--rule is required (use 'manual' to be explicit and avoid lockouts)")
	}
	ttl, err := time.ParseDuration(ttlRaw)
	if err != nil {
		return "", "", 0, fmt.Errorf("invalid --ttl %q: %w", ttlRaw, err)
	}
	return positional[0], ruleName, ttl, nil
}

func doReload(ctx context.Context, c *control.Client) error {
	if err := c.Reload(ctx); err != nil {
		return err
	}
	fmt.Println("reload requested; daemon applied successfully")
	return nil
}

func doTest(ctx context.Context, c *control.Client, args []string) error {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	ruleName := fs.String("rule", "", "rule name")
	configPath := fs.String("config", "", "load the rule from this config instead of a running daemon")
	rulesDir := fs.String("rules-dir", "", "override rules directory when --config is used")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *ruleName == "" || fs.NArg() != 1 {
		return fmt.Errorf("usage: goban-client rule test --rule NAME [--config PATH] [--rules-dir DIR] <logfile|->")
	}
	if *configPath == "" && *rulesDir != "" {
		return fmt.Errorf("--rules-dir requires --config")
	}
	target := fs.Arg(0)

	info, err := effectiveRuleForTest(ctx, c, *ruleName, *configPath, *rulesDir)
	if err != nil {
		return err
	}

	global, err := allowlist.New(info.GlobalAllowlist)
	if err != nil {
		return fmt.Errorf("global allowlist: %w", err)
	}
	perRule, err := allowlist.New(info.Allowlist)
	if err != nil {
		return fmt.Errorf("rule allowlist: %w", err)
	}
	trustedProxies, err := allowlist.New(info.TrustedProxies)
	if err != nil {
		return fmt.Errorf("trusted proxies: %w", err)
	}

	type banEvent struct {
		ip                string
		bannedAt, expires time.Time
	}
	var simulated []banEvent
	r, err := rule.New(rule.Config{
		Name: info.Name, SourceName: info.Source, Pattern: info.Regex,
		MaxRetries: info.Threshold, FindTime: info.FindTime, BanTime: info.BanTime,
		Datepattern: info.Datepattern, Timezone: info.Timezone,
		DateFailurePolicy: info.DateFailurePolicy, Excludes: info.Excludes,
		TrustedProxyCapture: info.TrustedProxyCapture, TrustedProxies: trustedProxies,
		Allowlist: global, AllowlistRule: perRule, Banner: banner.NewNoop(), Logger: zerolog.Nop(),
		OnBan: func(ev rule.BanEvent) {
			simulated = append(simulated, banEvent{ip: ev.IP, bannedAt: ev.OccurredAt, expires: ev.OccurredAt.Add(ev.TTL)})
		},
	})
	if err != nil {
		return fmt.Errorf("construct rule: %w", err)
	}
	probe, err := matcher.New(info.Regex)
	if err != nil {
		return fmt.Errorf("compile rule regex: %w", err)
	}

	var in io.Reader
	if target == "-" {
		in = os.Stdin
	} else {
		f, err := os.Open(target)
		if err != nil {
			return fmt.Errorf("open %s: %w", target, err)
		}
		defer f.Close()
		in = f
	}

	linesRead, regexMatches := 0, 0
	unique := make(map[string]struct{})
	err = source.ReadBoundedLines(in, 16*1024, func(text string) bool {
		linesRead++
		if ip, _, ok := probe.Match(text); ok {
			regexMatches++
			unique[ip.String()] = struct{}{}
		}
		now := time.Now()
		r.Process(ctx, source.LogLine{Text: text, Time: now, ReceivedAt: now})
		return ctx.Err() == nil
	})
	if err != nil {
		return fmt.Errorf("read input: %w", err)
	}

	stats := r.Stats()
	fmt.Printf("=== production-pipeline test for rule %q against %s ===\n", *ruleName, target)
	fmt.Printf("Lines read:        %d\nRegex matches:     %d\nAccepted strikes:  %d\nUnique IPs seen:   %d\nDate drops:        %d\nSimulated bans:    %d\n\n",
		linesRead, regexMatches, stats.Hits, len(unique), stats.DateDrops, len(simulated))
	fmt.Printf("Rule settings: max_retries=%d, findtime=%s, bantime=%s, date_policy=%s\n\n",
		info.Threshold, info.FindTime, info.BanTime, info.DateFailurePolicy)
	if len(simulated) == 0 {
		fmt.Println("(no IPs would be banned with the effective daemon settings)")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "IP\tBANNED_AT\tEXPIRES")
	for _, event := range simulated {
		fmt.Fprintf(w, "%s\t%s\t%s\n", event.ip, event.bannedAt.Format(time.RFC3339), event.expires.Format(time.RFC3339))
	}
	return w.Flush()
}

func effectiveRuleForTest(ctx context.Context, c *control.Client, name, configPath, rulesDir string) (*control.RuleInfo, error) {
	if configPath == "" {
		rules, err := c.Rules(ctx)
		if err != nil {
			return nil, fmt.Errorf("fetch /rules: %w (use --config for an offline test)", err)
		}
		for i := range rules {
			if rules[i].Name == name {
				if rules[i].Regex == "" {
					return nil, fmt.Errorf("daemon did not return the effective rule configuration")
				}
				return &rules[i], nil
			}
		}
		return nil, fmt.Errorf("rule %q is not loaded by the daemon", name)
	}

	cfg, err := config.LoadEffective(configPath, rulesDir)
	if err != nil {
		return nil, fmt.Errorf("load effective configuration: %w", err)
	}
	for _, rc := range cfg.Rules {
		if rc.Name != name {
			continue
		}
		return &control.RuleInfo{
			Name: rc.Name, Source: rc.Source, Regex: rc.Regex, Threshold: rc.MaxRetries,
			FindTime: rc.FindTime, BanTime: rc.BanTime, Datepattern: rc.Datepattern, Timezone: rc.Timezone,
			DateFailurePolicy: rc.DateFailurePolicy, Excludes: rc.Excludes, Allowlist: rc.Allowlist,
			GlobalAllowlist: cfg.Allowlist, TrustedProxyCapture: rc.TrustedProxyCapture, TrustedProxies: rc.TrustedProxies,
		}, nil
	}
	return nil, fmt.Errorf("rule %q is not present in the effective configuration", name)
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// extractFlag pulls out a --name VALUE pair (or --name=VALUE) from args.
func extractFlag(args []string, name string, set func(string)) []string {
	out := args[:0]
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == name && i+1 < len(args):
			set(args[i+1])
			i++
		case strings.HasPrefix(a, name+"="):
			set(strings.TrimPrefix(a, name+"="))
		default:
			out = append(out, a)
		}
	}
	return out
}

// extractBoolFlag returns whether --name appeared, and the args with it
// removed.
func extractBoolFlag(args []string, name string) ([]string, bool) {
	out := args[:0]
	present := false
	for _, a := range args {
		if a == name {
			present = true
			continue
		}
		out = append(out, a)
	}
	return out, present
}
