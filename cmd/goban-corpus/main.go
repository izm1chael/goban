// Command goban-corpus is a maintainer tool for deterministic and external
// compatibility testing. It is intentionally not part of the daemon process.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/izm1chael/goban/internal/config"
	"github.com/izm1chael/goban/internal/corpus"
	"github.com/izm1chael/goban/internal/matcher"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "goban-corpus:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		usage()
		return flag.ErrHelp
	}
	switch args[0] {
	case "test":
		return testCommand(args[1:])
	case "generate":
		return generateCommand(args[1:])
	case "sources":
		return sourcesCommand(args[1:])
	case "fetch":
		return fetchCommand(args[1:])
	case "compat-fail2ban":
		return compatFail2BanCommand(args[1:])
	case "scan":
		return scanCommand(args[1:])
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `goban-corpus — maintainer corpus and compatibility tooling

Usage:
  goban-corpus test [flags]
  goban-corpus generate --out FILE [--lines 100000] [--profile mixed]
  goban-corpus sources [--manifest FILE] [--json]
  goban-corpus fetch --accept-third-party-licenses [flags]
  goban-corpus compat-fail2ban --rule NAME --file FILE [flags]
  goban-corpus scan --rule NAME --file FILE [flags]

The repository does not vendor third-party corpora. The fetch command downloads
pinned external test inputs into a local cache only after explicit acceptance of
their individual licences.
`)
}

func testCommand(args []string) error {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	manifestPath := fs.String("manifest", "testdata/corpus/manifest.yaml", "corpus manifest")
	rulesDir := fs.String("rules-dir", "examples/rules.d", "rule directory")
	ruleName := fs.String("rule", "", "only test one rule")
	service := fs.String("service", "", "only test one service")
	tag := fs.String("tag", "", "only test cases with this tag")
	asJSON := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	manifest, err := corpus.Load(*manifestPath)
	if err != nil {
		return err
	}
	rules, err := config.LoadRulesDir(*rulesDir)
	if err != nil {
		return err
	}
	report := corpus.Run(context.Background(), manifest, rules, corpus.Options{Rule: *ruleName, Service: *service, Tag: *tag})
	if *asJSON {
		if err := printJSON(report); err != nil {
			return err
		}
	} else {
		fmt.Printf("Corpus: %d/%d passed, %d lines, %d matches, %d confirmed noop bans, %d rules, %d services\n",
			report.Passed, report.Total, report.Lines, report.Matches, report.Bans, report.UniqueRules, report.UniqueSvcs)
		for _, result := range report.Results {
			if result.Passed {
				continue
			}
			fmt.Printf("FAIL %s (%s/%s): %s\n", result.ID, result.Service, result.Rule, strings.Join(result.Errors, "; "))
		}
	}
	if report.Total == 0 {
		return fmt.Errorf("no corpus cases selected")
	}
	if report.Failed > 0 {
		return fmt.Errorf("%d corpus cases failed", report.Failed)
	}
	return nil
}

func generateCommand(args []string) error {
	fs := flag.NewFlagSet("generate", flag.ContinueOnError)
	output := fs.String("out", "", "output log file")
	lines := fs.Int("lines", 100000, "number of lines")
	seed := fs.Int64("seed", 1, "deterministic RNG seed")
	profile := fs.String("profile", "mixed", "mixed, sshd, web, or mail")
	verify := fs.Bool("verify", false, "scan the generated file and verify exact matcher counts")
	rulesDir := fs.String("rules-dir", "examples/rules.d", "rule directory used by --verify")
	asJSON := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	report, err := corpus.Generate(corpus.GenerateOptions{Output: *output, Lines: *lines, Seed: *seed, Profile: *profile})
	if err != nil {
		return err
	}
	observed := make(map[string]int)
	if *verify {
		rules, err := config.LoadRulesDir(*rulesDir)
		if err != nil {
			return err
		}
		byName := make(map[string]config.RuleConfig, len(rules))
		for _, rule := range rules {
			byName[rule.Name] = rule
		}
		for ruleName, want := range report.Expected {
			ruleCfg, ok := byName[ruleName]
			if !ok {
				return fmt.Errorf("generated corpus references missing rule %q", ruleName)
			}
			m, err := matcher.New(ruleCfg.Regex)
			if err != nil {
				return err
			}
			scan, err := corpus.Scan(report.Output, m, 0)
			if err != nil {
				return err
			}
			observed[ruleName] = scan.Matches
			if scan.Matches != want {
				return fmt.Errorf("generated corpus %s matches=%d, want %d", ruleName, scan.Matches, want)
			}
		}
	}
	if *asJSON {
		return printJSON(struct {
			corpus.GenerateReport
			Observed map[string]int `json:"observed_matches,omitempty"`
		}{GenerateReport: report, Observed: observed})
	}
	fmt.Printf("generated %d deterministic %s lines at %s (seed=%d)\n", report.Lines, report.Profile, report.Output, report.Seed)
	keys := make([]string, 0, len(report.Expected))
	for key := range report.Expected {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if *verify {
			fmt.Printf("  %-20s %d verified regex matches\n", key, observed[key])
		} else {
			fmt.Printf("  %-20s %d expected regex matches\n", key, report.Expected[key])
		}
	}
	return nil
}

func sourcesCommand(args []string) error {
	fs := flag.NewFlagSet("sources", flag.ContinueOnError)
	manifestPath := fs.String("manifest", "testdata/corpus/manifest.yaml", "corpus manifest")
	asJSON := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	manifest, err := corpus.Load(*manifestPath)
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(manifest.Sources)
	}
	for _, source := range manifest.Sources {
		fmt.Printf("%s\n  project: %s\n  license: %s (%s)\n  adapter: %s\n  rule: %s\n  url: %s\n",
			source.ID, source.Project, source.License, source.Redistribution, source.Adapter, valueOr(source.Rule, "n/a"), source.URL)
		if source.Notes != "" {
			fmt.Printf("  notes: %s\n", source.Notes)
		}
	}
	return nil
}

func fetchCommand(args []string) error {
	fs := flag.NewFlagSet("fetch", flag.ContinueOnError)
	manifestPath := fs.String("manifest", "testdata/corpus/manifest.yaml", "corpus manifest")
	root := fs.String("root", ".cache/goban-corpus", "download directory")
	only := fs.String("source", "", "download only one source ID")
	accepted := fs.Bool("accept-third-party-licenses", false, "acknowledge the listed external licences")
	asJSON := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if !*accepted {
		return fmt.Errorf("refusing external downloads without --accept-third-party-licenses; inspect `goban-corpus sources` first")
	}
	manifest, err := corpus.Load(*manifestPath)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 3 * time.Minute}
	results := make([]corpus.FetchResult, 0, len(manifest.Sources))
	for _, source := range manifest.Sources {
		if *only != "" && source.ID != *only {
			continue
		}
		result, err := corpus.Fetch(context.Background(), client, source, *root)
		if err != nil {
			return err
		}
		results = append(results, result)
		if !*asJSON {
			fmt.Printf("fetched %-24s %9d bytes sha256=%s\n", result.ID, result.Bytes, result.SHA256)
		}
	}
	if len(results) == 0 {
		return fmt.Errorf("no external sources selected")
	}
	if *asJSON {
		return printJSON(results)
	}
	return writeFetchManifest(*root, results)
}

func writeFetchManifest(root string, results []corpus.FetchResult) error {
	path := filepath.Join(root, "FETCHED.json")
	data, err := json.MarshalIndent(struct {
		FetchedAt time.Time            `json:"fetched_at"`
		Results   []corpus.FetchResult `json:"results"`
	}{FetchedAt: time.Now().UTC(), Results: results}, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o600)
}

func compatFail2BanCommand(args []string) error {
	fs := flag.NewFlagSet("compat-fail2ban", flag.ContinueOnError)
	ruleName := fs.String("rule", "", "GoBan rule name")
	path := fs.String("file", "", "Fail2Ban annotated log file")
	rulesDir := fs.String("rules-dir", "examples/rules.d", "rule directory")
	maxFalsePositive := fs.Int("max-false-positive", 0, "allowed false positives")
	minRecall := fs.Float64("min-recall", 0, "minimum expected-hit recall from 0 to 1")
	asJSON := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ruleCfg, err := loadRule(*rulesDir, *ruleName)
	if err != nil {
		return err
	}
	m, err := matcher.New(ruleCfg.Regex)
	if err != nil {
		return err
	}
	report, err := corpus.CompareFail2Ban(*path, m)
	if err != nil {
		return err
	}
	if *asJSON {
		if err := printJSON(report); err != nil {
			return err
		}
	} else {
		recall := ratio(report.TruePositive, report.ExpectedHits)
		precision := ratio(report.TruePositive, report.TruePositive+report.FalsePositive)
		fmt.Printf("Fail2Ban compatibility for %s\n", *ruleName)
		fmt.Printf("  annotated cases: %d (expected hits=%d misses=%d)\n", report.Total, report.ExpectedHits, report.ExpectedMiss)
		fmt.Printf("  TP=%d TN=%d FP=%d FN=%d host-mismatch=%d unannotated=%d\n", report.TruePositive, report.TrueNegative, report.FalsePositive, report.FalseNegative, report.HostMismatch, report.Unannotated)
		fmt.Printf("  recall=%.2f%% precision=%.2f%%\n", recall*100, precision*100)
	}
	if report.FalsePositive > *maxFalsePositive {
		return fmt.Errorf("false positives %d exceed allowed %d", report.FalsePositive, *maxFalsePositive)
	}
	if *minRecall > 0 && ratio(report.TruePositive, report.ExpectedHits) < *minRecall {
		return fmt.Errorf("recall is below %.2f", *minRecall)
	}
	return nil
}

func scanCommand(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	ruleName := fs.String("rule", "", "GoBan rule name")
	path := fs.String("file", "", "plain log file")
	rulesDir := fs.String("rules-dir", "examples/rules.d", "rule directory")
	sample := fs.Int("sample", 10, "number of matching IP samples")
	asJSON := fs.Bool("json", false, "emit JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ruleCfg, err := loadRule(*rulesDir, *ruleName)
	if err != nil {
		return err
	}
	m, err := matcher.New(ruleCfg.Regex)
	if err != nil {
		return err
	}
	report, err := corpus.Scan(*path, m, *sample)
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(report)
	}
	fmt.Printf("scanned %d lines: %d matches, %d unique IPs\n", report.Lines, report.Matches, report.UniqueIPs)
	if len(report.SampleIPs) > 0 {
		fmt.Printf("sample IPs: %s\n", strings.Join(report.SampleIPs, ", "))
	}
	return nil
}

func loadRule(dir, name string) (config.RuleConfig, error) {
	if name == "" {
		return config.RuleConfig{}, fmt.Errorf("--rule is required")
	}
	rules, err := config.LoadRulesDir(dir)
	if err != nil {
		return config.RuleConfig{}, err
	}
	for _, rule := range rules {
		if rule.Name == name {
			return rule, nil
		}
	}
	return config.RuleConfig{}, fmt.Errorf("rule %q was not found in %s", name, dir)
}

func ratio(numerator, denominator int) float64 {
	if denominator == 0 {
		return 1
	}
	return float64(numerator) / float64(denominator)
}

func valueOr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func printJSON(value any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(value)
}
