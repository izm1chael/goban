// Command goban-client talks to goban-daemon over its unix socket.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/rs/zerolog"

	"github.com/izm1chael/goban/internal/allowlist"
	"github.com/izm1chael/goban/internal/banner"
	"github.com/izm1chael/goban/internal/control"
	"github.com/izm1chael/goban/internal/matcher"
	"github.com/izm1chael/goban/internal/rule"
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
  rules                        list rules with hit/ban counters
  sources                      show live source health and queue drops
  list                         list currently-banned IPs
  unban <ip>                   remove a ban
  ban <ip> --rule manual [--ttl 1h]   manually ban an IP (rule label required)
  test --rule NAME <file|->    dry-run a rule against a log file (or stdin)
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
	case "rules":
		return doRules(ctx, c, asJSON)
	case "sources":
		return doSources(ctx, c, asJSON)
	case "list", "banned":
		return doList(ctx, c, asJSON)
	case "unban":
		return doUnban(ctx, c, rest)
	case "ban":
		return doBan(ctx, c, rest)
	case "test":
		return doTest(ctx, c, rest)
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
	if st.BannerError != "" {
		fmt.Printf("banner:     ERROR: %s\n", st.BannerError)
	}
	fmt.Printf("rules:      %d\n", st.NumRules)
	fmt.Printf("total bans: %d\n", st.TotalBans)
	return nil
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
	fmt.Fprintln(w, "IP\tRULE\tTTL\tEXPIRES")
	for _, b := range bans {
		exp := "permanent"
		if !b.ExpiresAt.IsZero() {
			exp = b.ExpiresAt.Format(time.RFC3339)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", b.IP, b.Rule, b.TTL, exp)
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
	fs := flag.NewFlagSet("ban", flag.ContinueOnError)
	rule := fs.String("rule", "", "rule label (required; use 'manual' to be explicit)")
	ttl := fs.Duration("ttl", time.Hour, "ban duration")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: goban-client ban <ip> --rule manual [--ttl 1h]")
	}
	if *rule == "" {
		return fmt.Errorf("--rule is required (use 'manual' to be explicit and avoid lockouts)")
	}
	ip := fs.Arg(0)
	if err := c.Ban(ctx, ip, *rule, *ttl); err != nil {
		return err
	}
	fmt.Printf("banned %s for %s (rule=%s)\n", ip, *ttl, *rule)
	return nil
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
	ruleName := fs.String("rule", "", "name of a rule already loaded by the daemon")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *ruleName == "" || fs.NArg() != 1 {
		return fmt.Errorf("usage: goban-client test --rule NAME <logfile|->")
	}
	target := fs.Arg(0)

	rules, err := c.Rules(ctx)
	if err != nil {
		return fmt.Errorf("fetch /rules: %w", err)
	}
	var info *control.RuleInfo
	for i := range rules {
		if rules[i].Name == *ruleName {
			info = &rules[i]
			break
		}
	}
	if info == nil {
		return fmt.Errorf("rule %q not loaded by the daemon", *ruleName)
	}
	if info.Regex == "" {
		return fmt.Errorf("daemon did not return the effective rule configuration")
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
