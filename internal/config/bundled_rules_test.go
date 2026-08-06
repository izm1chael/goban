package config_test

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/izm1chael/goban/internal/config"
	"github.com/izm1chael/goban/internal/matcher"
)

// TestBundledRulesValidate ensures every shipped rule file is strict-YAML
// decodable and valid when its documented source exists. This prevents the
// package's rules-available library drifting into a first-use failure.
func TestBundledRulesValidate(t *testing.T) {
	dir := filepath.Join("..", "..", "examples", "rules.d")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	sourceNames := map[string]struct{}{}
	for _, entry := range entries {
		if entry.IsDir() || (filepath.Ext(entry.Name()) != ".yaml" && filepath.Ext(entry.Name()) != ".yml") {
			continue
		}
		rules, err := config.LoadRulesFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatalf("%s: %v", entry.Name(), err)
		}
		cfg.Rules = append(cfg.Rules, rules...)
		for _, r := range rules {
			sourceNames[r.Source] = struct{}{}
		}
	}
	names := make([]string, 0, len(sourceNames))
	for name := range sourceNames {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		cfg.Sources = append(cfg.Sources, config.SourceConfig{Type: "file", Name: name, Path: "/tmp/" + name + ".log"})
	}
	cfg.ApplyRuleDefaults()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestBundledRuleIPv4AndIPv6Fixtures(t *testing.T) {
	tests := []struct {
		name, pattern, line, want string
	}{
		{"sshd-v4", `Failed password for (?:invalid user )?\S+ from (?P<ip>\S+) port`, `Failed password for invalid user root from 198.51.100.7 port 5522 ssh2`, "198.51.100.7"},
		{"sshd-v6", `Failed password for (?:invalid user )?\S+ from (?P<ip>\S+) port`, `Failed password for root from 2001:db8::7 port 5522 ssh2`, "2001:db8::7"},
		{"nginx-v6", `^(?P<ip>\S+) .* "(?:GET|POST) [^"]*" 401`, `2001:db8::8 - - [06/Aug/2026:17:00:00 +0100] "POST /login HTTP/1.1" 401 123 "-" "agent"`, "2001:db8::8"},
		{"apache-v4", `\[client (?P<ip>\[[0-9A-Fa-f:]+\]|[0-9A-Fa-f:.]+?)(?::\d+)?\] user .* authentication failure`, `[client 198.51.100.9:43122] user root authentication failure`, "198.51.100.9"},
		{"apache-v6", `\[client (?P<ip>\[[0-9A-Fa-f:]+\]|[0-9A-Fa-f:.]+?)(?::\d+)?\] user .* authentication failure`, `[client [2001:db8::9]:43122] user root authentication failure`, "2001:db8::9"},
		{"traefik-v6-port", `"ClientHost":"(?P<ip>[^"]+)"[^}]*"DownstreamStatus":401`, `{"ClientHost":"[2001:db8::10]:54321","DownstreamStatus":401}`, "2001:db8::10"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := matcher.New(tt.pattern)
			if err != nil {
				t.Fatal(err)
			}
			ip, _, ok := m.Match(tt.line)
			if !ok || ip.String() != tt.want {
				t.Fatalf("Match=(%v,%v), want %s", ip, ok, tt.want)
			}
		})
	}
}
