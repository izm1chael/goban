// Command goban-client talks to goban-daemon over its unix socket.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/izm1chael/goban/internal/control"
	"github.com/izm1chael/goban/internal/matcher"
	"github.com/izm1chael/goban/internal/tracker"
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
	fmt.Printf("sources:    %d\n", st.NumSources)
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
	fmt.Fprintln(w, "NAME\tSOURCE\tTHRESHOLD\tFINDTIME\tBANTIME\tTRACKED\tHITS\tBANS\tMISSES")
	for _, r := range rules {
		fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\t%d\t%d\t%d\t%d\n",
			r.Name, r.Source, r.Threshold, r.FindTime, r.BanTime,
			r.Tracked, r.Hits, r.Bans, r.Misses)
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
	if *ruleName == "" {
		return fmt.Errorf("usage: goban-client test --rule NAME <logfile|->")
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: goban-client test --rule NAME <logfile|->")
	}
	target := fs.Arg(0)

	// Fetch the rule's full config from the daemon.
	rules, err := c.Rules(ctx)
	if err != nil {
		return fmt.Errorf("fetch /rules: %w", err)
	}
	var target_rule *control.RuleInfo
	for i := range rules {
		if rules[i].Name == *ruleName {
			target_rule = &rules[i]
			break
		}
	}
	if target_rule == nil {
		return fmt.Errorf("rule %q not loaded by the daemon", *ruleName)
	}
	if target_rule.Regex == "" {
		return fmt.Errorf("daemon did not return the rule's regex (running an older binary?)")
	}

	m, err := matcher.New(target_rule.Regex)
	if err != nil {
		return fmt.Errorf("compile rule regex: %w", err)
	}
	tr := tracker.New(target_rule.Threshold, target_rule.FindTime)

	// Open the input — file path, or stdin if "-".
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

	type banEvent struct {
		ip        netip.Addr
		firstSeen time.Time
		bannedAt  time.Time
		expires   time.Time
	}
	firstSeenAt := make(map[netip.Addr]time.Time)
	simulated := []banEvent{}
	bannedSet := make(map[netip.Addr]struct{})
	uniqueIPs := make(map[netip.Addr]struct{})
	linesRead, linesMatched := 0, 0

	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		linesRead++
		ip, _, ok := m.Match(scanner.Text())
		if !ok {
			continue
		}
		linesMatched++
		uniqueIPs[ip] = struct{}{}
		now := time.Now()
		if _, seen := firstSeenAt[ip]; !seen {
			firstSeenAt[ip] = now
		}
		if _, alreadyBanned := bannedSet[ip]; alreadyBanned {
			continue
		}
		if tr.Hit(ip) {
			bannedSet[ip] = struct{}{}
			simulated = append(simulated, banEvent{
				ip:        ip,
				firstSeen: firstSeenAt[ip],
				bannedAt:  now,
				expires:   now.Add(target_rule.BanTime),
			})
			tr.Reset(ip)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("scan input: %w", err)
	}

	// Summary
	fmt.Printf("=== test results for rule %q against %s ===\n", *ruleName, target)
	fmt.Printf("Lines read:        %d\n", linesRead)
	fmt.Printf("Lines matched:     %d\n", linesMatched)
	fmt.Printf("Unique IPs seen:   %d\n", len(uniqueIPs))
	fmt.Printf("Simulated bans:    %d\n", len(simulated))
	fmt.Println()
	fmt.Printf("Rule settings: max_retries=%d, findtime=%s, bantime=%s\n",
		target_rule.Threshold, target_rule.FindTime, target_rule.BanTime)
	fmt.Println()
	if len(simulated) == 0 {
		fmt.Println("(no IPs would be banned with these settings)")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "IP\tFIRST_SEEN\tBANNED_AT\tEXPIRES")
	for _, e := range simulated {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			e.ip.String(),
			e.firstSeen.Format("15:04:05"),
			e.bannedAt.Format("15:04:05"),
			e.expires.Format(time.RFC3339),
		)
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
