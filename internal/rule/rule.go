// Package rule orchestrates the per-rule pipeline: line → matcher → date
// parse → excludes filter → allowlist → tracker → banner. A rule pairs one
// regex filter with one ban action.
package rule

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"

	"github.com/izm1chael/goban/internal/allowlist"
	"github.com/izm1chael/goban/internal/banner"
	"github.com/izm1chael/goban/internal/datepattern"
	"github.com/izm1chael/goban/internal/matcher"
	"github.com/izm1chael/goban/internal/source"
	"github.com/izm1chael/goban/internal/tracker"
)

// recidiveRuleName is the well-known rule name that auto-applies an
// excludes filter against itself, blocking the audit-log feedback loop.
const recidiveRuleName = "recidive"

// driftFuture is the maximum amount a parsed event time may be in the future
// before the rule falls back to wall-clock. Small clock skew between hosts is
// normal; an hour is generous.
const driftFuture = time.Hour

// driftPast is the maximum amount a parsed event time may be in the past
// before the rule falls back to wall-clock. Six hours covers a typical
// journald backlog after a daemon restart but rejects obviously-stale logs
// that might compress old bursts into the live window.
const driftPast = 6 * time.Hour

// driftLogInterval rate-limits per-rule drift warnings so a single misconfig
// can't fill the operational log.
const driftLogInterval = time.Minute

// Rule wires a single regex-defined filter onto a source's line stream.
type Rule struct {
	Name       string
	SourceName string
	BanTime    time.Duration

	matcher       *matcher.Matcher
	tracker       *tracker.Tracker
	allowlist     *allowlist.Allowlist // global allowlist (always non-nil)
	allowlistRule *allowlist.Allowlist // per-rule allowlist (nil if unconfigured)
	banner        banner.Banner
	log           zerolog.Logger

	dateLayout string            // resolved Go layout (empty when no datepattern)
	excludes   map[string]string // capture-name → skip-value (post-match filter)

	hits               atomic.Uint64
	bans               atomic.Uint64
	misses             atomic.Uint64
	dateParseFails     atomic.Uint64
	dateDriftFallbacks atomic.Uint64
	lastDriftLogNano   atomic.Int64 // unix nano of last drift warn (rate-limit)
}

// Config bundles everything Rule needs at construction time.
type Config struct {
	Name          string
	SourceName    string
	Pattern       string
	MaxRetries    int
	FindTime      time.Duration
	BanTime       time.Duration
	Datepattern   string            // preset name (sshd, iso8601, ...) or raw Go layout; "" = wall-clock
	Excludes      map[string]string // post-match filter: capture-name → skip-value
	Allowlist     *allowlist.Allowlist
	AllowlistRule *allowlist.Allowlist
	Banner        banner.Banner
	Logger        zerolog.Logger
}

// New constructs a Rule. The regex pattern must contain a (?P<ip>...) named
// capture or New returns an error. A (?P<time>...) capture is required when
// Datepattern is set; without it the parse step would never have input to work
// with and the configuration is silently useless, so we surface the misconfig
// here.
func New(cfg Config) (*Rule, error) {
	m, err := matcher.New(cfg.Pattern)
	if err != nil {
		return nil, err
	}
	layout, err := datepattern.Resolve(cfg.Datepattern)
	if err != nil {
		return nil, err
	}
	excludes := cloneExcludes(cfg.Excludes)
	// Belt-and-suspenders: any rule named "recidive" auto-applies an
	// exclude against itself so a misconfigured YAML can't create a
	// feedback loop where recidive's own ban events trip recidive.
	if cfg.Name == recidiveRuleName {
		if excludes == nil {
			excludes = make(map[string]string, 1)
		}
		excludes["rule"] = recidiveRuleName
	}
	return &Rule{
		Name:          cfg.Name,
		SourceName:    cfg.SourceName,
		BanTime:       cfg.BanTime,
		matcher:       m,
		tracker:       tracker.New(cfg.MaxRetries, cfg.FindTime),
		allowlist:     cfg.Allowlist,
		allowlistRule: cfg.AllowlistRule,
		banner:        cfg.Banner,
		dateLayout:    layout,
		excludes:      excludes,
		log:           cfg.Logger.With().Str("rule", cfg.Name).Logger(),
	}, nil
}

func cloneExcludes(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// Pattern returns the compiled regex's source pattern. Used by goban-client
// test to fetch the regex via the control plane and run it locally.
func (r *Rule) Pattern() string { return r.matcher.String() }

// Tracker exposes the rule's tracker for state-persistence integration.
// Returns nil if Rule wasn't fully initialized.
func (r *Rule) Tracker() *tracker.Tracker { return r.tracker }

// Run consumes lines from in until ctx is cancelled or in is closed. Returns
// when the goroutine has fully drained.
func (r *Rule) Run(ctx context.Context, in <-chan source.LogLine) {
	for {
		select {
		case <-ctx.Done():
			return
		case line, ok := <-in:
			if !ok {
				return
			}
			r.process(ctx, line)
		}
	}
}

func (r *Rule) process(ctx context.Context, line source.LogLine) {
	ip, timeStr, ok := r.matcher.Match(line.Text)
	if !ok {
		r.misses.Add(1)
		return
	}
	// Post-match excludes filter: if any configured capture matches its
	// skip value, treat the line as a non-hit. Recidive uses this to avoid
	// counting its own ban events.
	for name, skip := range r.excludes {
		if r.matcher.Capture(name, line.Text) == skip {
			r.misses.Add(1)
			return
		}
	}
	// Per-rule allowlist is consulted first because it tends to be small
	// (a handful of CIDRs) and rule-specific intent overrides global.
	if r.allowlistRule != nil && r.allowlistRule.Permit(ip) {
		r.log.Debug().Str("ip", ip.String()).Msg("rule-allowlisted, skipping")
		return
	}
	if r.allowlist != nil && r.allowlist.Permit(ip) {
		r.log.Debug().Str("ip", ip.String()).Msg("allowlisted, skipping")
		return
	}
	r.hits.Add(1)

	eventTime := r.resolveEventTime(timeStr)
	trip := r.tracker.HitAt(ip, eventTime)
	r.log.Debug().Str("ip", ip.String()).Bool("trip", trip).Msg("strike")
	if !trip {
		return
	}
	if err := r.banner.Ban(ctx, ip, r.Name, r.BanTime); err != nil {
		r.log.Error().Err(err).Str("ip", ip.String()).Msg("ban failed")
		return
	}
	r.bans.Add(1)
	r.tracker.Reset(ip)
	r.log.Info().Str("ip", ip.String()).Dur("ttl", r.BanTime).Msg("banned")
}

// resolveEventTime returns the time at which the matched event occurred —
// the parsed timestamp from the line when both datepattern and (?P<time>...)
// capture are present and the parsed value is within the drift window, or
// wall-clock otherwise. Counters track parse failures and drift fallbacks so
// `goban-client rules` can surface misconfigurations.
func (r *Rule) resolveEventTime(timeStr string) time.Time {
	now := time.Now()
	if r.dateLayout == "" || timeStr == "" {
		return now
	}
	parsed, err := time.Parse(r.dateLayout, timeStr)
	if err != nil {
		r.dateParseFails.Add(1)
		return now
	}
	delta := now.Sub(parsed)
	if delta > driftPast || delta < -driftFuture {
		r.dateDriftFallbacks.Add(1)
		r.logDriftRateLimited(parsed, delta)
		return now
	}
	return parsed
}

func (r *Rule) logDriftRateLimited(parsed time.Time, delta time.Duration) {
	now := time.Now().UnixNano()
	last := r.lastDriftLogNano.Load()
	if now-last < int64(driftLogInterval) {
		return
	}
	if !r.lastDriftLogNano.CompareAndSwap(last, now) {
		return
	}
	r.log.Warn().
		Time("parsed", parsed).
		Dur("delta_past", delta).
		Msg("datepattern drift exceeded window; falling back to wall-clock")
}

// Sweep prunes stale strike records and returns the number dropped.
func (r *Rule) Sweep() int { return r.tracker.Sweep() }

// Stats is a snapshot of one rule's counters and tracker state.
type Stats struct {
	Hits               uint64
	Bans               uint64
	Misses             uint64
	Threshold          int
	FindTime           time.Duration
	BanTime            time.Duration
	Tracked            int
	DateParseFails     uint64
	DateDriftFallbacks uint64
}

// Stats returns a snapshot of rule counters.
func (r *Rule) Stats() Stats {
	return Stats{
		Hits:               r.hits.Load(),
		Bans:               r.bans.Load(),
		Misses:             r.misses.Load(),
		Threshold:          r.tracker.Threshold(),
		FindTime:           r.tracker.FindTime(),
		BanTime:            r.BanTime,
		Tracked:            r.tracker.Size(),
		DateParseFails:     r.dateParseFails.Load(),
		DateDriftFallbacks: r.dateDriftFallbacks.Load(),
	}
}
