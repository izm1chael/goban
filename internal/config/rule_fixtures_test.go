package config_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"gopkg.in/yaml.v3"

	"github.com/izm1chael/goban/internal/allowlist"
	"github.com/izm1chael/goban/internal/banner"
	"github.com/izm1chael/goban/internal/config"
	"github.com/izm1chael/goban/internal/matcher"
	rulepkg "github.com/izm1chael/goban/internal/rule"
	"github.com/izm1chael/goban/internal/source"
)

type fixtureFile struct {
	Cases []ruleFixture `yaml:"cases"`
}

type ruleFixture struct {
	Name  string `yaml:"name"`
	Rule  string `yaml:"rule"`
	Line  string `yaml:"line"`
	Match bool   `yaml:"match"`
	IP    string `yaml:"ip"`
}

// TestCoreRuleFixtures is the release gate for the small set of rules we are
// prepared to describe as supported. Additional rules may remain available,
// but do not become core-supported until they have positive, negative, IPv4,
// IPv6, and malformed fixtures here.
func TestCoreRuleFixtures(t *testing.T) {
	ruleDir := filepath.Join("..", "..", "examples", "rules.d")
	rules, err := config.LoadRulesDir(ruleDir)
	if err != nil {
		t.Fatal(err)
	}
	byName := make(map[string]config.RuleConfig, len(rules))
	for _, rule := range rules {
		byName[rule.Name] = rule
	}

	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "rules", "core-fixtures.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var fixtures fixtureFile
	if err := yaml.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	if len(fixtures.Cases) == 0 {
		t.Fatal("no core rule fixtures loaded")
	}
	seenPositive := map[string]bool{}
	seenNegative := map[string]bool{}
	for _, fixture := range fixtures.Cases {
		t.Run(fixture.Name, func(t *testing.T) {
			rule, ok := byName[fixture.Rule]
			if !ok {
				t.Fatalf("fixture references unknown bundled rule %q", fixture.Rule)
			}
			m, err := matcher.New(rule.Regex)
			if err != nil {
				t.Fatal(err)
			}
			ip, _, got := m.Match(fixture.Line)
			if got != fixture.Match {
				t.Fatalf("Match=%v, want %v (ip=%s)", got, fixture.Match, ip)
			}

			global, err := allowlist.New(nil)
			if err != nil {
				t.Fatal(err)
			}
			perRule, err := allowlist.New(rule.Allowlist)
			if err != nil {
				t.Fatal(err)
			}
			trusted, err := allowlist.New(rule.TrustedProxies)
			if err != nil {
				t.Fatal(err)
			}
			decisions := 0
			processor, err := rulepkg.New(rulepkg.Config{
				Name: rule.Name, SourceName: rule.Source, Pattern: rule.Regex, MaxRetries: 1,
				FindTime: time.Minute, BanTime: time.Minute, Datepattern: rule.Datepattern,
				Timezone: rule.Timezone, DateFailurePolicy: rule.DateFailurePolicy, Excludes: rule.Excludes,
				TrustedProxyCapture: rule.TrustedProxyCapture, TrustedProxies: trusted,
				Allowlist: global, AllowlistRule: perRule, Banner: banner.NewNoop(), Logger: zerolog.Nop(),
				OnBan: func(rulepkg.BanEvent) { decisions++ },
			})
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now()
			processor.Process(context.Background(), source.LogLine{Source: rule.Source, Text: fixture.Line, Time: now, ReceivedAt: now})
			wantDecisions := 0
			if fixture.Match {
				wantDecisions = 1
			}
			if decisions != wantDecisions {
				t.Fatalf("production pipeline decisions=%d, want %d", decisions, wantDecisions)
			}
			if fixture.Match {
				seenPositive[fixture.Rule] = true
				if fixture.IP != "" && ip.String() != fixture.IP {
					t.Fatalf("IP=%s, want %s", ip, fixture.IP)
				}
			} else {
				seenNegative[fixture.Rule] = true
			}
		})
	}
	for _, core := range []string{"sshd", "nginx-http-auth", "apache-auth"} {
		if !seenPositive[core] || !seenNegative[core] {
			t.Errorf("core rule %q needs at least one positive and one negative fixture", core)
		}
	}
}
