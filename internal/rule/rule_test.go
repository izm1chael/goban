package rule

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/izm1chael/goban/internal/allowlist"
	"github.com/izm1chael/goban/internal/banner"
	"github.com/izm1chael/goban/internal/source"
)

func newRule(t *testing.T, b banner.Banner, al *allowlist.Allowlist, retries int) *Rule {
	t.Helper()
	r, err := New(Config{
		Name:       "test",
		SourceName: "auth",
		Pattern:    `Failed password from (?P<ip>\S+)`,
		MaxRetries: retries,
		FindTime:   time.Minute,
		BanTime:    time.Hour,
		Allowlist:  al,
		Banner:     b,
		Logger:     zerolog.Nop(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return r
}

func TestRule_BansAfterThreshold(t *testing.T) {
	b := banner.NewNoop()
	r := newRule(t, b, nil, 3)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		r.process(ctx, source.LogLine{Text: "Failed password from 1.2.3.4"})
	}
	bans, _ := b.List(ctx)
	if len(bans) != 1 {
		t.Fatalf("bans=%d, want 1", len(bans))
	}
	if bans[0].IP.String() != "1.2.3.4" {
		t.Errorf("banned IP = %q, want 1.2.3.4", bans[0].IP.String())
	}
	if bans[0].Rule != "test" {
		t.Errorf("banned rule = %q, want test", bans[0].Rule)
	}
}

func TestRule_AllowlistedNotBanned(t *testing.T) {
	b := banner.NewNoop()
	al, _ := allowlist.New([]string{"1.2.3.0/24"})
	r := newRule(t, b, al, 1)
	ctx := context.Background()
	r.process(ctx, source.LogLine{Text: "Failed password from 1.2.3.4"})
	bans, _ := b.List(ctx)
	if len(bans) != 0 {
		t.Errorf("allowlisted IP banned: %v", bans)
	}
}

func TestRule_PerRuleAllowlist(t *testing.T) {
	// Per-rule allowlist suppresses bans for one rule's traffic even when
	// the global allowlist would not. An IP outside the per-rule list is
	// still banned normally.
	b := banner.NewNoop()
	ruleAllow, _ := allowlist.New([]string{"203.0.113.50/32"})
	r, err := New(Config{
		Name:          "test",
		SourceName:    "auth",
		Pattern:       `Failed password from (?P<ip>\S+)`,
		MaxRetries:    1,
		FindTime:      time.Minute,
		BanTime:       time.Hour,
		AllowlistRule: ruleAllow,
		Banner:        b,
		Logger:        zerolog.Nop(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	// Allowlisted IP should NOT be banned
	r.process(ctx, source.LogLine{Text: "Failed password from 203.0.113.50"})
	// Non-allowlisted IP SHOULD be banned
	r.process(ctx, source.LogLine{Text: "Failed password from 198.51.100.1"})

	bans, _ := b.List(ctx)
	if len(bans) != 1 {
		t.Fatalf("len(bans) = %d, want 1", len(bans))
	}
	if bans[0].IP.String() != "198.51.100.1" {
		t.Errorf("banned IP = %q, want 198.51.100.1", bans[0].IP.String())
	}
}

func TestRule_PatternAccessor(t *testing.T) {
	b := banner.NewNoop()
	r := newRule(t, b, nil, 3)
	got := r.Pattern()
	want := `Failed password from (?P<ip>\S+)`
	if got != want {
		t.Errorf("Pattern() = %q, want %q", got, want)
	}
}

func TestRule_NoMatchIsAMiss(t *testing.T) {
	b := banner.NewNoop()
	r := newRule(t, b, nil, 1)
	ctx := context.Background()
	r.process(ctx, source.LogLine{Text: "totally unrelated line"})
	s := r.Stats()
	if s.Misses != 1 {
		t.Errorf("misses = %d, want 1", s.Misses)
	}
	if s.Hits != 0 {
		t.Errorf("hits = %d, want 0", s.Hits)
	}
}

func TestRule_DatepatternUsesParsedTime(t *testing.T) {
	// With datepattern: iso8601 and the test pattern below, three lines whose
	// embedded timestamps span 8 minutes will all land in a 10-minute window.
	// The third line should trip the threshold (3). With wall-clock-only Hit,
	// this is fine too — the value is that the strikes are recorded at the
	// parsed times, not "now".
	b := banner.NewNoop()
	r, err := New(Config{
		Name:        "sshd",
		SourceName:  "auth",
		Pattern:     `^(?P<time>\S+) .* from (?P<ip>\S+) port`,
		Datepattern: "iso8601",
		Timezone:    "UTC",
		MaxRetries:  3,
		FindTime:    10 * time.Minute,
		BanTime:     time.Hour,
		Banner:      b,
		Logger:      zerolog.Nop(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	now := time.Now()
	// Within last 8 minutes (inside the 10-minute window).
	for i, age := range []time.Duration{-8 * time.Minute, -5 * time.Minute, -2 * time.Minute} {
		t.Logf("hit %d at %s", i, now.Add(age).Format("15:04:05"))
		r.process(context.Background(), source.LogLine{
			Text: now.Add(age).UTC().Format("2006-01-02T15:04:05") + " sshd[1]: Failed password for invalid user bob from 198.51.100.7 port 22 ssh2",
		})
	}
	bans, _ := b.List(context.Background())
	if len(bans) != 1 {
		t.Fatalf("len(bans) = %d, want 1 — parsed-time strikes should trip", len(bans))
	}
}

func TestRule_DatepatternDriftDropsByDefault(t *testing.T) {
	b := banner.NewNoop()
	r, err := New(Config{
		Name: "sshd", SourceName: "auth",
		Pattern: `^(?P<time>\S+) .* from (?P<ip>\S+) port`, Datepattern: "iso8601",
		MaxRetries: 1, FindTime: 10 * time.Minute, BanTime: time.Hour,
		Banner: b, Logger: zerolog.Nop(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	old := time.Now().Add(-48 * time.Hour).UTC().Format("2006-01-02T15:04:05")
	r.process(context.Background(), source.LogLine{Text: old + " sshd[1]: Failed password from 198.51.100.7 port 22"})
	stats := r.Stats()
	if stats.DateDriftFallbacks != 1 || stats.DateDrops != 1 {
		t.Fatalf("stats=%+v", stats)
	}
	bans, _ := b.List(context.Background())
	if len(bans) != 0 {
		t.Fatalf("stale event produced ban: %+v", bans)
	}
}

func TestRule_DatepatternSourceTimeFallbackIsExplicit(t *testing.T) {
	b := banner.NewNoop()
	r, err := New(Config{
		Name: "sshd", SourceName: "auth",
		Pattern: `^(?P<time>\S+) .* from (?P<ip>\S+) port`, Datepattern: "iso8601",
		DateFailurePolicy: "source_time", MaxRetries: 1, FindTime: time.Minute, BanTime: time.Hour,
		Banner: b, Logger: zerolog.Nop(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	now := time.Now()
	r.process(context.Background(), source.LogLine{Text: "notatime sshd[1]: Failed password from 198.51.100.7 port 22", Time: now})
	stats := r.Stats()
	if stats.DateParseFails != 1 || stats.DateDrops != 0 {
		t.Fatalf("stats=%+v", stats)
	}
	bans, _ := b.List(context.Background())
	if len(bans) != 1 {
		t.Fatalf("len(bans)=%d, want 1", len(bans))
	}
}

func TestRule_DatepatternParseFailureDropsByDefault(t *testing.T) {
	b := banner.NewNoop()
	r, err := New(Config{
		Name: "sshd", SourceName: "auth",
		Pattern: `^(?P<time>\S+) .* from (?P<ip>\S+) port`, Datepattern: "iso8601",
		MaxRetries: 1, FindTime: time.Minute, BanTime: time.Hour,
		Banner: b, Logger: zerolog.Nop(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r.process(context.Background(), source.LogLine{Text: `notatime sshd[1]: Failed password from 198.51.100.7 port 22`})
	stats := r.Stats()
	if stats.DateParseFails != 1 || stats.DateDrops != 1 {
		t.Fatalf("stats=%+v", stats)
	}
}

func TestParseEventTimeInjectsNearestSyslogYear(t *testing.T) {
	reference := time.Date(2026, 1, 1, 0, 1, 0, 0, time.UTC)
	got, err := parseEventTime("Jan _2 15:04:05", "Dec 31 23:59:30", reference, time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	if got.Year() != 2025 || got.Month() != time.December {
		t.Fatalf("got %s", got)
	}
}

func TestRule_ExcludesSuppressesHit(t *testing.T) {
	// With excludes: rule=recidive, lines whose `rule` capture is "recidive"
	// must NOT count as hits. This is the mechanism that breaks the recidive
	// feedback loop.
	b := banner.NewNoop()
	r, err := New(Config{
		Name:       "recidive-test", // explicit non-recidive name so auto-exclude doesn't fire
		SourceName: "audit",
		Pattern:    `"event":"ban".*?"rule":"(?P<rule>[^"]+)".*?"ip":"(?P<ip>[^"]+)"`,
		Excludes:   map[string]string{"rule": "recidive"},
		MaxRetries: 1,
		FindTime:   time.Minute,
		BanTime:    time.Hour,
		Banner:     b,
		Logger:     zerolog.Nop(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// This line WOULD trip the rule (threshold=1) — but excludes filters it.
	r.process(context.Background(), source.LogLine{
		Text: `{"event":"ban","rule":"recidive","ip":"198.51.100.7","ttl":"168h"}`,
	})
	bans, _ := b.List(context.Background())
	if len(bans) != 0 {
		t.Errorf("len(bans) = %d, want 0 — excludes should filter recidive's own bans", len(bans))
	}
	// A non-recidive ban event SHOULD trip.
	r.process(context.Background(), source.LogLine{
		Text: `{"event":"ban","rule":"sshd","ip":"198.51.100.7","ttl":"1h"}`,
	})
	bans, _ = b.List(context.Background())
	if len(bans) != 1 {
		t.Errorf("len(bans) = %d, want 1 — non-recidive ban should still trip", len(bans))
	}
}

func TestRule_RecidiveAutoExclude(t *testing.T) {
	// A rule named "recidive" must auto-apply excludes against its own
	// ban events EVEN IF the YAML didn't specify excludes — guards against
	// operator misconfiguration.
	b := banner.NewNoop()
	r, err := New(Config{
		Name:       "recidive", // the magic name
		SourceName: "audit",
		Pattern:    `"event":"ban".*?"rule":"(?P<rule>[^"]+)".*?"ip":"(?P<ip>[^"]+)"`,
		// no Excludes — auto-applied
		MaxRetries: 1,
		FindTime:   time.Minute,
		BanTime:    time.Hour,
		Banner:     b,
		Logger:     zerolog.Nop(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r.process(context.Background(), source.LogLine{
		Text: `{"event":"ban","rule":"recidive","ip":"198.51.100.7","ttl":"168h"}`,
	})
	bans, _ := b.List(context.Background())
	if len(bans) != 0 {
		t.Errorf("len(bans) = %d, want 0 — auto-exclude should suppress recidive feedback", len(bans))
	}
}

func TestRule_RunDrainsOnContextCancel(t *testing.T) {
	b := banner.NewNoop()
	r := newRule(t, b, nil, 3)
	in := make(chan source.LogLine, 1)
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		r.Run(ctx, in)
		close(done)
	}()
	in <- source.LogLine{Text: "Failed password from 9.9.9.9"}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Run did not return after context cancel")
	}
}

type failingBanner struct{ err error }

func (f failingBanner) Setup(context.Context) error                                  { return nil }
func (f failingBanner) Ban(context.Context, netip.Addr, string, time.Duration) error { return f.err }
func (f failingBanner) BanBatch(context.Context, []banner.BanRequest) error          { return f.err }
func (f failingBanner) Unban(context.Context, netip.Addr) error                      { return nil }
func (f failingBanner) List(context.Context) ([]banner.BanInfo, error)               { return nil, nil }
func (f failingBanner) Close(context.Context, bool) error                            { return nil }

func TestRule_FailedBanDoesNotResetOrEmitSuccess(t *testing.T) {
	want := errors.New("kernel rejected ban")
	emitted := 0
	r, err := New(Config{
		Name: "test", SourceName: "auth", Pattern: `from (?P<ip>\S+)`,
		MaxRetries: 1, FindTime: time.Minute, BanTime: time.Hour,
		Banner: failingBanner{err: want}, Logger: zerolog.Nop(), OnBan: func(BanEvent) { emitted++ },
	})
	if err != nil {
		t.Fatal(err)
	}
	r.process(context.Background(), source.LogLine{Text: "failed from 198.51.100.8"})
	if emitted != 0 {
		t.Fatalf("emitted=%d, want 0", emitted)
	}
	if r.Stats().Bans != 0 {
		t.Fatalf("bans=%d, want 0", r.Stats().Bans)
	}
	if r.Tracker().Snapshot()[netip.MustParseAddr("198.51.100.8")] != 1 {
		t.Fatal("strike was reset after failed ban")
	}
}

func TestRule_ForwardedClientRequiresTrustedProxy(t *testing.T) {
	b := banner.NewNoop()
	trusted, err := allowlist.New([]string{"10.0.0.0/8", "2001:db8::/32"})
	if err != nil {
		t.Fatal(err)
	}
	r, err := New(Config{
		Name: "proxy", SourceName: "access",
		Pattern:             `peer=(?P<peer>\S+) client=(?P<ip>\S+) status=401`,
		TrustedProxyCapture: "peer", TrustedProxies: trusted,
		MaxRetries: 1, FindTime: time.Minute, BanTime: time.Hour,
		Banner: b, Logger: zerolog.Nop(),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	r.process(ctx, source.LogLine{Text: "peer=203.0.113.10 client=198.51.100.7 status=401"})
	bans, _ := b.List(ctx)
	if len(bans) != 0 {
		t.Fatalf("untrusted proxy produced ban: %+v", bans)
	}
	r.process(ctx, source.LogLine{Text: "peer=10.1.2.3:443 client=198.51.100.7 status=401"})
	bans, _ = b.List(ctx)
	if len(bans) != 1 || bans[0].IP.String() != "198.51.100.7" {
		t.Fatalf("trusted proxy bans=%+v", bans)
	}
}

func TestRule_BanEventIncludesEvidence(t *testing.T) {
	b := banner.NewNoop()
	var got BanEvent
	r, err := New(Config{
		Name: "sshd", SourceName: "auth", Pattern: `Failed password from (?P<ip>\S+)`,
		MaxRetries: 3, FindTime: time.Minute, BanTime: time.Hour,
		Banner: b, Logger: zerolog.Nop(), OnBan: func(ev BanEvent) { got = ev },
	})
	if err != nil {
		t.Fatal(err)
	}
	base := time.Now().Add(-10 * time.Second)
	for i := 0; i < 3; i++ {
		r.Process(context.Background(), source.LogLine{Text: "Failed password from 198.51.100.11", Time: base.Add(time.Duration(i) * time.Second)})
	}
	if got.EvidenceCount != 3 {
		t.Fatalf("EvidenceCount=%d, want 3", got.EvidenceCount)
	}
	if got.FirstSeen.IsZero() || got.LastSeen.IsZero() || got.LastSeen.Before(got.FirstSeen) {
		t.Fatalf("invalid evidence window: %+v", got)
	}
}
