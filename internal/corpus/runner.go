package corpus

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"time"

	"github.com/rs/zerolog"

	"github.com/izm1chael/goban/internal/allowlist"
	"github.com/izm1chael/goban/internal/banner"
	"github.com/izm1chael/goban/internal/config"
	"github.com/izm1chael/goban/internal/matcher"
	rulepkg "github.com/izm1chael/goban/internal/rule"
	sourcepkg "github.com/izm1chael/goban/internal/source"
)

type Options struct {
	Rule    string
	Service string
	Tag     string
	Now     time.Time
}

type Report struct {
	StartedAt   time.Time    `json:"started_at"`
	FinishedAt  time.Time    `json:"finished_at"`
	Total       int          `json:"total"`
	Passed      int          `json:"passed"`
	Failed      int          `json:"failed"`
	Lines       int          `json:"lines"`
	Matches     int          `json:"matches"`
	Bans        int          `json:"bans"`
	UniqueRules int          `json:"unique_rules"`
	UniqueSvcs  int          `json:"unique_services"`
	Results     []CaseResult `json:"results"`
}

type CaseResult struct {
	ID              string   `json:"id"`
	Service         string   `json:"service"`
	Rule            string   `json:"rule"`
	Passed          bool     `json:"passed"`
	Errors          []string `json:"errors,omitempty"`
	Lines           int      `json:"lines"`
	Matches         int      `json:"matches"`
	Bans            int      `json:"bans"`
	MatchedIPs      []string `json:"matched_ips,omitempty"`
	ExpectedMatches int      `json:"expected_matches"`
	ExpectedBans    int      `json:"expected_bans"`
}

func Run(ctx context.Context, manifest *Manifest, rules []config.RuleConfig, opts Options) Report {
	started := time.Now().UTC()
	base := opts.Now
	if base.IsZero() {
		base = started
	}
	byName := make(map[string]config.RuleConfig, len(rules))
	for _, cfg := range rules {
		byName[cfg.Name] = cfg
	}
	selected := manifest.Filter(opts.Rule, opts.Service, opts.Tag)
	report := Report{StartedAt: started, Results: make([]CaseResult, 0, len(selected))}
	ruleNames := make(map[string]struct{})
	services := make(map[string]struct{})
	for i, tc := range selected {
		result := runCase(ctx, tc, byName, base.Add(time.Duration(i)*time.Minute))
		report.Results = append(report.Results, result)
		report.Total++
		report.Lines += result.Lines
		report.Matches += result.Matches
		report.Bans += result.Bans
		ruleNames[result.Rule] = struct{}{}
		services[result.Service] = struct{}{}
		if result.Passed {
			report.Passed++
		} else {
			report.Failed++
		}
	}
	report.UniqueRules = len(ruleNames)
	report.UniqueSvcs = len(services)
	report.FinishedAt = time.Now().UTC()
	return report
}

func runCase(ctx context.Context, tc Case, byName map[string]config.RuleConfig, base time.Time) CaseResult {
	result := CaseResult{
		ID: tc.ID, Service: tc.Service, Rule: tc.Rule,
		ExpectedMatches: tc.ExpectedMatch, ExpectedBans: tc.ExpectedBans,
	}
	cfg, ok := byName[tc.Rule]
	if !ok {
		result.Errors = append(result.Errors, fmt.Sprintf("rule %q is not present in the loaded rule directory", tc.Rule))
		return result
	}
	m, err := matcher.New(cfg.Regex)
	if err != nil {
		result.Errors = append(result.Errors, err.Error())
		return result
	}
	global, err := allowlist.New(nil)
	if err != nil {
		result.Errors = append(result.Errors, err.Error())
		return result
	}
	perRule, err := allowlist.New(cfg.Allowlist)
	if err != nil {
		result.Errors = append(result.Errors, err.Error())
		return result
	}
	trusted, err := allowlist.New(cfg.TrustedProxies)
	if err != nil {
		result.Errors = append(result.Errors, err.Error())
		return result
	}
	bans := 0
	p, err := rulepkg.New(rulepkg.Config{
		Name: cfg.Name, SourceName: cfg.Source, Pattern: cfg.Regex,
		MaxRetries: cfg.MaxRetries, FindTime: cfg.FindTime, BanTime: cfg.BanTime,
		Datepattern: cfg.Datepattern, Timezone: cfg.Timezone,
		DateFailurePolicy: cfg.DateFailurePolicy, Excludes: cfg.Excludes,
		TrustedProxyCapture: cfg.TrustedProxyCapture, TrustedProxies: trusted,
		Allowlist: global, AllowlistRule: perRule, Banner: banner.NewNoop(),
		Logger: zerolog.Nop(), OnBan: func(rulepkg.BanEvent) { bans++ },
	})
	if err != nil {
		result.Errors = append(result.Errors, err.Error())
		return result
	}
	p.Tracker().Now = func() time.Time { return base }

	repeats := tc.Repeat
	if repeats == 0 {
		repeats = 1
	}
	matchedIPs := make(map[netip.Addr]struct{})
	sequence := 0
	for repeat := 0; repeat < repeats; repeat++ {
		for _, line := range tc.Lines {
			result.Lines++
			if ip, _, matched := m.Match(line); matched {
				matchedIPs[ip] = struct{}{}
			}
			observed := base.Add(time.Duration(sequence) * 100 * time.Millisecond)
			p.Process(ctx, sourcepkg.LogLine{Source: cfg.Source, Text: line, Time: observed, ReceivedAt: observed})
			sequence++
		}
	}
	result.Matches = int(p.Stats().Hits)
	result.Bans = bans
	for ip := range matchedIPs {
		result.MatchedIPs = append(result.MatchedIPs, ip.String())
	}
	sort.Strings(result.MatchedIPs)

	if result.Matches != tc.ExpectedMatch {
		result.Errors = append(result.Errors, fmt.Sprintf("matches=%d, want %d", result.Matches, tc.ExpectedMatch))
	}
	if result.Bans != tc.ExpectedBans {
		result.Errors = append(result.Errors, fmt.Sprintf("bans=%d, want %d", result.Bans, tc.ExpectedBans))
	}
	if tc.ExpectedIP != "" {
		expected, err := netip.ParseAddr(tc.ExpectedIP)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("invalid expected_ip %q: %v", tc.ExpectedIP, err))
		} else {
			expected = expected.Unmap()
			if _, found := matchedIPs[expected]; !found {
				result.Errors = append(result.Errors, fmt.Sprintf("expected IP %s was not extracted (got %v)", expected, result.MatchedIPs))
			}
		}
	}
	result.Passed = len(result.Errors) == 0
	return result
}
