package rule

import (
	"context"
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

func TestRule_DatepatternDriftFallsBackToWallClock(t *testing.T) {
	// Lines with timestamps 2 days old are well outside the drift window;
	// the rule must fall back to wall-clock and increment the drift counter.
	b := banner.NewNoop()
	r, err := New(Config{
		Name:        "sshd",
		SourceName:  "auth",
		Pattern:     `^(?P<time>\S+) .* from (?P<ip>\S+) port`,
		Datepattern: "iso8601",
		MaxRetries:  3,
		FindTime:    10 * time.Minute,
		BanTime:     time.Hour,
		Banner:      b,
		Logger:      zerolog.Nop(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	old := time.Now().Add(-48 * time.Hour).UTC().Format("2006-01-02T15:04:05")
	for i := 0; i < 3; i++ {
		r.process(context.Background(), source.LogLine{
			Text: old + " sshd[1]: Failed password for invalid user bob from 198.51.100.7 port 22 ssh2",
		})
	}
	s := r.Stats()
	if s.DateDriftFallbacks != 3 {
		t.Errorf("DateDriftFallbacks = %d, want 3", s.DateDriftFallbacks)
	}
	// And the wall-clock fallback still produced a ban (three strikes all
	// at "now" definitely trip a threshold of 3).
	bans, _ := b.List(context.Background())
	if len(bans) != 1 {
		t.Errorf("len(bans) = %d, want 1 — fallback should still ban", len(bans))
	}
}

func TestRule_DatepatternParseFailureCount(t *testing.T) {
	// When the regex captures `time` but the captured string can't be parsed
	// with the configured layout, the parse-fail counter increments and the
	// rule falls back to wall-clock.
	b := banner.NewNoop()
	r, err := New(Config{
		Name:        "sshd",
		SourceName:  "auth",
		Pattern:     `^(?P<time>\S+) .* from (?P<ip>\S+) port`,
		Datepattern: "iso8601",
		MaxRetries:  1,
		FindTime:    time.Minute,
		BanTime:     time.Hour,
		Banner:      b,
		Logger:      zerolog.Nop(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r.process(context.Background(), source.LogLine{
		Text: `notatime sshd[1]: Failed password for invalid user bob from 198.51.100.7 port 22 ssh2`,
	})
	s := r.Stats()
	if s.DateParseFails != 1 {
		t.Errorf("DateParseFails = %d, want 1", s.DateParseFails)
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
