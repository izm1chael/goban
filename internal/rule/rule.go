// Package rule orchestrates the per-rule pipeline: line → matcher → timestamp
// policy → excludes → allowlists → tracker → confirmed banner operation.
package rule

import (
	"context"
	"fmt"
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

const recidiveRuleName = "recidive"

const (
	driftFuture      = time.Hour
	driftPast        = 6 * time.Hour
	driftLogInterval = time.Minute
)

// BanEvent is emitted only after the banner has confirmed the kernel-side ban.
type BanEvent struct {
	IP         string
	Rule       string
	Source     string
	TTL        time.Duration
	OccurredAt time.Time
}

type Rule struct {
	Name       string
	SourceName string
	BanTime    time.Duration

	matcher       *matcher.Matcher
	tracker       *tracker.Tracker
	allowlist     *allowlist.Allowlist
	allowlistRule *allowlist.Allowlist
	banner        banner.Banner
	log           zerolog.Logger
	onBan         func(BanEvent)

	datepattern         string
	dateLayout          string
	dateLocation        *time.Location
	dateFailurePolicy   string
	excludes            map[string]string
	trustedProxyCapture string
	trustedProxies      *allowlist.Allowlist

	hits               atomic.Uint64
	bans               atomic.Uint64
	misses             atomic.Uint64
	dateParseFails     atomic.Uint64
	dateDriftFallbacks atomic.Uint64
	dateDrops          atomic.Uint64
	lastDriftLogNano   atomic.Int64
}

type Config struct {
	Name                string
	SourceName          string
	Pattern             string
	MaxRetries          int
	FindTime            time.Duration
	BanTime             time.Duration
	Datepattern         string
	Timezone            string
	DateFailurePolicy   string
	Excludes            map[string]string
	TrustedProxyCapture string
	TrustedProxies      *allowlist.Allowlist
	Allowlist           *allowlist.Allowlist
	AllowlistRule       *allowlist.Allowlist
	Banner              banner.Banner
	Logger              zerolog.Logger
	OnBan               func(BanEvent)
}

func New(cfg Config) (*Rule, error) {
	m, err := matcher.New(cfg.Pattern)
	if err != nil {
		return nil, err
	}
	layout, err := datepattern.Resolve(cfg.Datepattern)
	if err != nil {
		return nil, err
	}
	if layout != "" && !m.HasCapture("time") {
		return nil, fmt.Errorf("datepattern requires a (?P<time>...) named capture")
	}
	location := time.Local
	if cfg.Timezone != "" && cfg.Timezone != "Local" {
		location, err = time.LoadLocation(cfg.Timezone)
		if err != nil {
			return nil, fmt.Errorf("load timezone %q: %w", cfg.Timezone, err)
		}
	}
	policy := cfg.DateFailurePolicy
	if policy == "" {
		policy = "drop"
	}
	if policy != "drop" && policy != "source_time" {
		return nil, fmt.Errorf("date failure policy %q: want drop or source_time", policy)
	}
	if cfg.TrustedProxyCapture != "" {
		if cfg.TrustedProxies == nil {
			return nil, fmt.Errorf("trusted proxy capture requires trusted proxy CIDRs")
		}
		if !m.HasCapture(cfg.TrustedProxyCapture) {
			return nil, fmt.Errorf("trusted proxy capture %q does not name a regex capture", cfg.TrustedProxyCapture)
		}
	}
	excludes := cloneExcludes(cfg.Excludes)
	if cfg.Name == recidiveRuleName {
		if excludes == nil {
			excludes = make(map[string]string, 1)
		}
		excludes["rule"] = recidiveRuleName
	}
	return &Rule{
		Name:                cfg.Name,
		SourceName:          cfg.SourceName,
		BanTime:             cfg.BanTime,
		matcher:             m,
		tracker:             tracker.New(cfg.MaxRetries, cfg.FindTime),
		allowlist:           cfg.Allowlist,
		allowlistRule:       cfg.AllowlistRule,
		banner:              cfg.Banner,
		log:                 cfg.Logger.With().Str("rule", cfg.Name).Logger(),
		onBan:               cfg.OnBan,
		datepattern:         cfg.Datepattern,
		dateLayout:          layout,
		dateLocation:        location,
		dateFailurePolicy:   policy,
		excludes:            excludes,
		trustedProxyCapture: cfg.TrustedProxyCapture,
		trustedProxies:      cfg.TrustedProxies,
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

func (r *Rule) Pattern() string           { return r.matcher.String() }
func (r *Rule) Tracker() *tracker.Tracker { return r.tracker }
func (r *Rule) Datepattern() string       { return r.datepattern }
func (r *Rule) DateFailurePolicy() string { return r.dateFailurePolicy }
func (r *Rule) Timezone() string {
	if r.dateLocation == time.Local {
		return "Local"
	}
	return r.dateLocation.String()
}
func (r *Rule) Excludes() map[string]string { return cloneExcludes(r.excludes) }
func (r *Rule) TrustedProxyCapture() string { return r.trustedProxyCapture }
func (r *Rule) TrustedProxies() []string {
	if r.trustedProxies == nil {
		return nil
	}
	prefixes := r.trustedProxies.Prefixes()
	out := make([]string, len(prefixes))
	for i, p := range prefixes {
		out[i] = p.String()
	}
	return out
}
func (r *Rule) RuleAllowlist() []string {
	if r.allowlistRule == nil {
		return nil
	}
	prefixes := r.allowlistRule.Prefixes()
	out := make([]string, len(prefixes))
	for i, p := range prefixes {
		out[i] = p.String()
	}
	return out
}
func (r *Rule) GlobalAllowlist() []string {
	if r.allowlist == nil {
		return nil
	}
	prefixes := r.allowlist.Prefixes()
	out := make([]string, len(prefixes))
	for i, p := range prefixes {
		out[i] = p.String()
	}
	return out
}

// Process runs one log line through the exact production rule pipeline. It is
// exported for offline validation tools and integration tests.
func (r *Rule) Process(ctx context.Context, line source.LogLine) { r.process(ctx, line) }

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
	for name, skip := range r.excludes {
		if r.matcher.Capture(name, line.Text) == skip {
			r.misses.Add(1)
			return
		}
	}
	if r.trustedProxyCapture != "" {
		peer, ok := r.matcher.CaptureAddr(r.trustedProxyCapture, line.Text)
		if !ok || r.trustedProxies == nil || !r.trustedProxies.Permit(peer) {
			r.misses.Add(1)
			r.log.Debug().Str("capture", r.trustedProxyCapture).Msg("forwarded client IP rejected: direct peer is missing, invalid, or untrusted")
			return
		}
	}
	if r.allowlistRule != nil && r.allowlistRule.Permit(ip) {
		r.log.Debug().Str("ip", ip.String()).Msg("rule-allowlisted, skipping")
		return
	}
	if r.allowlist != nil && r.allowlist.Permit(ip) {
		r.log.Debug().Str("ip", ip.String()).Msg("allowlisted, skipping")
		return
	}

	eventTime, valid := r.resolveEventTime(timeStr, line.Time)
	if !valid {
		r.dateDrops.Add(1)
		return
	}
	r.hits.Add(1)
	trip := r.tracker.HitAt(ip, eventTime)
	r.log.Debug().Str("ip", ip.String()).Bool("trip", trip).Msg("strike")
	if !trip {
		return
	}
	if err := r.banner.Ban(ctx, ip, r.Name, r.BanTime); err != nil {
		r.log.Error().Err(err).Str("ip", ip.String()).Msg("ban failed")
		return
	}

	// Only confirmed bans clear strike state and increment durable counters.
	r.bans.Add(1)
	r.tracker.Reset(ip)
	now := time.Now().UTC()
	if r.onBan != nil {
		r.onBan(BanEvent{IP: ip.String(), Rule: r.Name, Source: r.SourceName, TTL: r.BanTime, OccurredAt: now})
	}
	r.log.Info().Str("ip", ip.String()).Dur("ttl", r.BanTime).Msg("banned")
}

// resolveEventTime applies a fail-closed timestamp policy. With datepattern
// configured, malformed or implausibly stale timestamps are dropped by
// default rather than being rewritten to "now". source_time is available for
// operators who explicitly prefer receipt-time fallback.
func (r *Rule) resolveEventTime(timeStr string, sourceTime time.Time) (time.Time, bool) {
	now := time.Now()
	fallback := sourceTime
	if fallback.IsZero() {
		fallback = now
	}
	if r.dateLayout == "" {
		return fallback, true
	}
	if timeStr == "" {
		r.dateParseFails.Add(1)
		return r.dateFallback(fallback)
	}

	parsed, err := parseEventTime(r.dateLayout, timeStr, fallback, r.dateLocation)
	if err != nil {
		r.dateParseFails.Add(1)
		return r.dateFallback(fallback)
	}
	delta := now.Sub(parsed)
	if delta > driftPast || delta < -driftFuture {
		r.dateDriftFallbacks.Add(1)
		r.logDriftRateLimited(parsed, delta)
		return r.dateFallback(fallback)
	}
	return parsed, true
}

func (r *Rule) dateFallback(sourceTime time.Time) (time.Time, bool) {
	if r.dateFailurePolicy == "source_time" {
		return sourceTime, true
	}
	return time.Time{}, false
}

// parseEventTime injects the nearest plausible year for traditional syslog
// layouts and parses timezone-less logs in the configured server location.
func parseEventTime(layout, value string, reference time.Time, loc *time.Location) (time.Time, error) {
	if loc == nil {
		loc = time.Local
	}
	if hasYear(layout) {
		return time.ParseInLocation(layout, value, loc)
	}

	best := time.Time{}
	bestDistance := time.Duration(1<<63 - 1)
	for _, year := range []int{reference.Year() - 1, reference.Year(), reference.Year() + 1} {
		candidate, err := time.ParseInLocation("2006 "+layout, fmt.Sprintf("%d %s", year, value), loc)
		if err != nil {
			continue
		}
		d := candidate.Sub(reference)
		if d < 0 {
			d = -d
		}
		if d < bestDistance {
			best = candidate
			bestDistance = d
		}
	}
	if best.IsZero() {
		return time.Time{}, fmt.Errorf("parse %q with layout %q", value, layout)
	}
	return best, nil
}

func hasYear(layout string) bool {
	for i := 0; i+4 <= len(layout); i++ {
		if layout[i:i+4] == "2006" {
			return true
		}
	}
	return false
}

func (r *Rule) logDriftRateLimited(parsed time.Time, delta time.Duration) {
	now := time.Now().UnixNano()
	last := r.lastDriftLogNano.Load()
	if now-last < int64(driftLogInterval) || !r.lastDriftLogNano.CompareAndSwap(last, now) {
		return
	}
	r.log.Warn().Time("parsed", parsed).Dur("delta_past", delta).Msg("datepattern drift exceeded window; event rejected or source-time fallback applied")
}

func (r *Rule) Sweep() int { return r.tracker.Sweep() }

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
	DateDrops          uint64
}

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
		DateDrops:          r.dateDrops.Load(),
	}
}
