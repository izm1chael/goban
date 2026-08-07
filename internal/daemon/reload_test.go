package daemon

import (
	"testing"
	"time"

	"github.com/izm1chael/goban/internal/config"
	"github.com/izm1chael/goban/internal/source"
)

func TestCutoverRecordingCountsOnlyWhileEnabled(t *testing.T) {
	ri := &ruleInstance{}
	line := source.LogLine{Source: "auth", Text: "failed from 192.0.2.1"}

	ri.beginCutoverRecording()
	ri.recordCutoverLine(line)
	ri.recordCutoverLine(line)
	counts := ri.endCutoverRecording()

	if got := counts[reloadLineKey(line)]; got != 2 {
		t.Fatalf("recorded count = %d, want 2", got)
	}
	ri.recordCutoverLine(line)
	if got := counts[reloadLineKey(line)]; got != 2 {
		t.Fatalf("recording continued after cutover ended: %d", got)
	}
}

func TestReloadLineKeyIsLengthDelimited(t *testing.T) {
	a := source.LogLine{Source: "ab", Container: "c", Text: "d"}
	b := source.LogLine{Source: "a", Container: "bc", Text: "d"}
	if reloadLineKey(a) == reloadLineKey(b) {
		t.Fatal("different source/container boundaries produced the same key")
	}
}

func TestRuleSigNormalizesOrderInsensitiveCIDRs(t *testing.T) {
	a := config.RuleConfig{
		Name: "web", Source: "access", Regex: `peer=(?P<peer>\S+) ip=(?P<ip>\S+)`,
		MaxRetries: 3, FindTime: time.Minute, BanTime: time.Hour,
		Allowlist:           []string{"192.0.2.2/32", "192.0.2.1/32"},
		TrustedProxyCapture: "peer",
		TrustedProxies:      []string{"2001:db8::/32", "10.0.0.0/8"},
	}
	b := a
	b.Allowlist = []string{"192.0.2.1/32", "192.0.2.2/32"}
	b.TrustedProxies = []string{"10.0.0.0/8", "2001:db8::/32"}
	if ruleSig(a) != ruleSig(b) {
		t.Fatal("equivalent CIDR ordering changed the semantic fingerprint")
	}
}

func TestImmutableReloadSettings(t *testing.T) {
	oldCfg := config.DefaultConfig()
	newCfg := *oldCfg
	newCfg.Rules = []config.RuleConfig{{Name: "new-rule"}}
	newCfg.Allowlist = []string{"127.0.0.1/32"}
	if err := assertImmutableFieldsUnchanged(oldCfg, &newCfg); err != nil {
		t.Fatalf("reloadable changes rejected: %v", err)
	}

	newCfg = *oldCfg
	newCfg.Banner.Backend = "nftables"
	if err := assertImmutableFieldsUnchanged(oldCfg, &newCfg); err == nil {
		t.Fatal("firewall backend change should require restart")
	}
}

func TestBanMetadataPathFor(t *testing.T) {
	if got := banMetadataPathFor("/var/lib/goban/state.gob"); got != "/var/lib/goban/state-bans.json" {
		t.Fatalf("metadata path = %q", got)
	}
	if got := banMetadataPathFor(""); got != "" {
		t.Fatalf("empty state path produced %q", got)
	}
}

func TestApplyRuntimeOverrides(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.LogLevel = "info"
	cfg.LogFile = "/from-yaml.log"
	applyRuntimeOverrides(cfg, RuntimeOverrides{LogLevel: "debug", LogFile: "/from-cli.log", EnforcerMode: "split"})
	if cfg.LogLevel != "debug" || cfg.LogFile != "/from-cli.log" || cfg.Enforcer.Mode != "split" {
		t.Fatalf("runtime overrides not applied: level=%q file=%q enforcer=%q", cfg.LogLevel, cfg.LogFile, cfg.Enforcer.Mode)
	}
}
