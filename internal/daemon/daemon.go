// Package daemon wires sources, rules, firewall enforcement, persistence, and
// the control plane into one supervised lifecycle.
package daemon

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/izm1chael/goban/internal/allowlist"
	"github.com/izm1chael/goban/internal/banner"
	"github.com/izm1chael/goban/internal/config"
	"github.com/izm1chael/goban/internal/control"
	"github.com/izm1chael/goban/internal/rule"
	"github.com/izm1chael/goban/internal/source"
	"github.com/izm1chael/goban/internal/source/docker"
	"github.com/izm1chael/goban/internal/source/file"
	"github.com/izm1chael/goban/internal/source/journal"
)

type ruleInstance struct {
	rule       *rule.Rule
	sourceName string
	sig        string
	input      <-chan source.LogLine
	cancel     context.CancelFunc
	done       chan struct{}

	cutoverMu     sync.Mutex
	cutoverRecord bool
	cutoverCounts map[string]int
}

type sourceInstance struct {
	src      source.Source
	refcount int
}

// RuntimeOverrides are process-lifetime CLI settings that remain authoritative
// across config reloads. They are not serialized into YAML.
type RuntimeOverrides struct {
	LogLevel string
	LogFile  string
}

type Daemon struct {
	cfg     *config.Config
	log     zerolog.Logger
	version string

	cfgPath          string
	rulesDir         string
	runtimeOverrides RuntimeOverrides

	rootCtx    context.Context
	rootCancel context.CancelFunc

	allowlist   *allowlist.Allowlist
	banner      banner.Banner
	control     *control.Server
	audit       *control.Audit
	banMeta     *banMetadataStore
	banMetaPath string

	mu       sync.Mutex
	reloadMu sync.Mutex
	rules    map[string]*ruleInstance
	sources  map[string]*sourceInstance

	wg        sync.WaitGroup
	startedAt time.Time

	sweepInterval time.Duration
	auditCloser   func() error
}

func New(cfg *config.Config, log zerolog.Logger, version, cfgPath, rulesDir string, overrides ...RuntimeOverrides) (*Daemon, error) {
	runtimeOverrides := RuntimeOverrides{}
	if len(overrides) > 0 {
		runtimeOverrides = overrides[0]
	}
	al, err := buildAllowlist(cfg.Allowlist)
	if err != nil {
		return nil, fmt.Errorf("allowlist: %w", err)
	}

	var b banner.Banner
	switch {
	case cfg.DryRun:
		log.Warn().Msg("dry_run enabled — using noop banner (no kernel side-effects)")
		b = banner.NewNoop()
	case cfg.Banner.Backend == "nftables":
		log.Info().Str("backend", "nftables").Str("table", cfg.Banner.Table).Msg("banner backend")
		nft := banner.NewNFTables(cfg.Banner.Table, cfg.Banner.SetV4, cfg.Banner.SetV6, cfg.Banner.Chain, cfg.IPv6)
		nft.SetForwardChain(cfg.Banner.ForwardChain)
		b = nft
	default:
		ipt := banner.NewIPTables(cfg.IPSetNameV4, cfg.IPSetNameV6, cfg.IPv6)
		ipt.SetChains(cfg.Banner.IPTablesChains)
		b = ipt
	}
	if cfg.BatchBans {
		b = banner.NewBatched(b, log, banner.BatchOpts{})
	}

	d := &Daemon{
		cfg:              cfg,
		log:              log,
		version:          version,
		cfgPath:          cfgPath,
		rulesDir:         rulesDir,
		runtimeOverrides: runtimeOverrides,
		allowlist:        al,
		banner:           b,
		banMeta:          newBanMetadataStore(),
		banMetaPath:      banMetadataPathFor(cfg.StatePath),
		rules:            make(map[string]*ruleInstance),
		sources:          make(map[string]*sourceInstance),
		sweepInterval:    time.Minute,
	}

	if cfg.AuditLog != "" {
		a, closer, err := control.NewAuditFile(cfg.AuditLog)
		if err != nil {
			log.Warn().Err(err).Str("path", cfg.AuditLog).Msg("audit log disabled — could not open file")
		} else {
			d.audit = a
			d.auditCloser = closer
			log.Info().Str("path", cfg.AuditLog).Msg("audit log open")
		}
	}

	for _, sc := range cfg.Sources {
		s, err := buildSource(sc, cfg.ReplayOnStart)
		if err != nil {
			d.closeAudit()
			return nil, err
		}
		d.sources[sc.Name] = &sourceInstance{src: s}
	}
	for _, rc := range cfg.Rules {
		ri, err := d.buildRuleInstanceWithAllowlist(rc, al)
		if err != nil {
			d.closeAudit()
			return nil, err
		}
		d.rules[rc.Name] = ri
	}

	// The daemon owns auditing so manual and automatic bans share one
	// authoritative event pipeline; the control transport only delegates.
	d.control = control.New(d, cfg.SocketPath, os.FileMode(cfg.SocketMode), log, cfg.SocketGroup)
	return d, nil
}

func buildAllowlist(cidrs []string) (*allowlist.Allowlist, error) {
	al, err := allowlist.New(cidrs)
	if err != nil {
		return nil, err
	}
	if err := al.AddLocalInterfaces(); err != nil {
		return nil, err
	}
	return al, nil
}

func buildSource(sc config.SourceConfig, replay bool) (source.Source, error) {
	switch sc.Type {
	case "file":
		return file.New(file.Config{Name: sc.Name, Path: sc.Path, Replay: replay, MaxLineLen: config.DefaultMaxLineBytes}), nil
	case "docker":
		s, err := docker.New(docker.Config{Name: sc.Name, Container: sc.Container, Labels: sc.Labels, MaxLineLen: config.DefaultMaxLineBytes})
		if err != nil {
			return nil, fmt.Errorf("source %q: %w", sc.Name, err)
		}
		return s, nil
	case "journal":
		return journal.New(journal.Config{Name: sc.Name, Match: sc.Match, MaxLineLen: config.DefaultMaxLineBytes}), nil
	default:
		return nil, fmt.Errorf("source %q: unknown type %q", sc.Name, sc.Type)
	}
}

func (d *Daemon) buildRuleInstance(rc config.RuleConfig) (*ruleInstance, error) {
	return d.buildRuleInstanceWithAllowlist(rc, d.allowlist)
}

func (d *Daemon) buildRuleInstanceWithAllowlist(rc config.RuleConfig, global *allowlist.Allowlist) (*ruleInstance, error) {
	var ruleAllow *allowlist.Allowlist
	if len(rc.Allowlist) > 0 {
		a, err := allowlist.New(rc.Allowlist)
		if err != nil {
			return nil, fmt.Errorf("rule %q allowlist: %w", rc.Name, err)
		}
		ruleAllow = a
	}
	var trustedProxies *allowlist.Allowlist
	if len(rc.TrustedProxies) > 0 {
		a, err := allowlist.New(rc.TrustedProxies)
		if err != nil {
			return nil, fmt.Errorf("rule %q trusted proxies: %w", rc.Name, err)
		}
		trustedProxies = a
	}
	r, err := rule.New(rule.Config{
		Name:                rc.Name,
		SourceName:          rc.Source,
		Pattern:             rc.Regex,
		MaxRetries:          rc.MaxRetries,
		FindTime:            rc.FindTime,
		BanTime:             rc.BanTime,
		Datepattern:         rc.Datepattern,
		Timezone:            rc.Timezone,
		DateFailurePolicy:   rc.DateFailurePolicy,
		Excludes:            rc.Excludes,
		TrustedProxyCapture: rc.TrustedProxyCapture,
		TrustedProxies:      trustedProxies,
		Allowlist:           global,
		AllowlistRule:       ruleAllow,
		Banner:              d.banner,
		Logger:              d.log,
		OnBan:               d.recordRuleBan,
	})
	if err != nil {
		return nil, fmt.Errorf("rule %q: %w", rc.Name, err)
	}
	return &ruleInstance{rule: r, sourceName: rc.Source, sig: ruleSig(rc)}, nil
}

func (d *Daemon) Start(ctx context.Context) error {
	d.rootCtx, d.rootCancel = context.WithCancel(ctx)
	d.startedAt = time.Now()
	if err := d.banner.Setup(d.rootCtx); err != nil {
		d.rootCancel()
		d.closeAudit()
		return fmt.Errorf("banner setup: %w", err)
	}
	d.loadBanMetadata()

	bufSize := d.bufSize()
	prepared := make([]string, 0, len(d.rules))
	for name, ri := range d.rules {
		if err := prepareRuleInstance(name, ri, d.sources, bufSize); err != nil {
			d.cleanupPrepared(prepared, d.rules, d.sources)
			d.abortStart()
			return err
		}
		prepared = append(prepared, name)
	}

	// Tracker state is restored before any source can publish a line.
	d.loadAllState()

	started := make([]string, 0, len(d.sources))
	for name, si := range d.sources {
		if err := si.src.Start(d.rootCtx); err != nil {
			for _, startedName := range started {
				_ = d.sources[startedName].src.Close()
			}
			d.cleanupPrepared(prepared, d.rules, d.sources)
			d.abortStart()
			return fmt.Errorf("source %q start: %w", name, err)
		}
		started = append(started, name)
	}
	for _, name := range prepared {
		d.launchRuleInstance(d.rules[name])
	}

	d.wg.Add(1)
	go d.runSweeper(d.rootCtx)
	if d.cfg.StatePath != "" && d.cfg.StateSaveInterval > 0 {
		d.wg.Add(1)
		go d.runStateSaver(d.rootCtx)
	}
	if err := d.control.Start(d.rootCtx); err != nil {
		d.abortStart()
		return fmt.Errorf("control start: %w", err)
	}

	d.log.Info().Int("sources", len(d.sources)).Int("rules", len(d.rules)).Msg("daemon started")
	return nil
}

func (d *Daemon) abortStart() {
	if d.rootCancel != nil {
		d.rootCancel()
	}
	for _, ri := range d.rules {
		if ri.cancel != nil {
			ri.cancel()
		}
	}
	for _, si := range d.sources {
		_ = si.src.Close()
	}
	done := make(chan struct{})
	go func() {
		d.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		d.log.Warn().Msg("startup cleanup deadline reached")
	}
	_ = d.banner.Close(context.Background(), false)
	d.closeAudit()
}

func (d *Daemon) bufSize() int {
	if d.cfg.StrikeChanSize > 0 {
		return d.cfg.StrikeChanSize
	}
	return 256
}

func prepareRuleInstance(name string, ri *ruleInstance, sources map[string]*sourceInstance, bufSize int) error {
	si, ok := sources[ri.sourceName]
	if !ok {
		return fmt.Errorf("rule %q: source %q not built", name, ri.sourceName)
	}
	ri.input = si.src.Subscribe(name, bufSize)
	si.refcount++
	return nil
}

func (d *Daemon) launchRuleInstance(ri *ruleInstance) {
	ruleCtx, cancel := context.WithCancel(d.rootCtx)
	ri.cancel = cancel
	ri.done = make(chan struct{})
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		defer close(ri.done)
		for {
			select {
			case <-ruleCtx.Done():
				return
			case line, ok := <-ri.input:
				if !ok {
					return
				}
				ri.recordCutoverLine(line)
				ri.rule.Process(ruleCtx, line)
			}
		}
	}()
}

func (d *Daemon) cleanupPrepared(names []string, rules map[string]*ruleInstance, sources map[string]*sourceInstance) {
	for _, name := range names {
		ri := rules[name]
		if si, ok := sources[ri.sourceName]; ok {
			si.src.Unsubscribe(name)
			if si.refcount > 0 {
				si.refcount--
			}
		}
		ri.input = nil
	}
}

func (d *Daemon) statePathFor(ruleName string) string {
	if d.cfg.StatePath == "" {
		return ""
	}
	dir := filepath.Dir(d.cfg.StatePath)
	base := strings.TrimSuffix(filepath.Base(d.cfg.StatePath), filepath.Ext(d.cfg.StatePath))
	return filepath.Join(dir, fmt.Sprintf("%s-%s.gob", base, ruleName))
}

func (d *Daemon) loadAllState() {
	if d.cfg.StatePath == "" {
		return
	}
	for name, ri := range d.rules {
		d.loadRuleState(name, ri)
	}
}

func (d *Daemon) loadRuleState(name string, ri *ruleInstance) {
	path := d.statePathFor(name)
	f, err := os.Open(path)
	if err != nil {
		if !os.IsNotExist(err) {
			d.log.Warn().Err(err).Str("path", path).Str("rule", name).Msg("state load skipped")
		}
		return
	}
	defer f.Close()
	if err := ri.rule.Tracker().LoadWithFingerprint(f, ri.sig); err != nil {
		d.log.Warn().Err(err).Str("path", path).Str("rule", name).Msg("state load discarded — clean start")
		return
	}
	d.log.Info().Str("path", path).Str("rule", name).Int("tracked", ri.rule.Tracker().Size()).Msg("state loaded")
}

func (d *Daemon) saveAllState() {
	if d.cfg.StatePath == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(d.cfg.StatePath), 0o700); err != nil {
		d.log.Warn().Err(err).Msg("state dir create")
		return
	}
	for name, ri := range d.rules {
		d.saveRuleState(name, ri)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	if bans, err := d.banner.List(ctx); err == nil {
		d.pruneBanMetadata(bans)
	}
	cancel()
	d.saveBanMetadata()
}

func (d *Daemon) saveRuleState(name string, ri *ruleInstance) {
	if d.cfg.StatePath == "" {
		return
	}
	path := d.statePathFor(name)
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		d.log.Warn().Err(err).Str("path", tmp).Msg("state save open failed")
		return
	}
	if err := ri.rule.Tracker().SaveWithFingerprint(f, ri.sig); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		d.log.Warn().Err(err).Str("rule", name).Msg("state save encode failed")
		return
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		d.log.Warn().Err(err).Str("rule", name).Msg("state save close failed")
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		d.log.Warn().Err(err).Msg("state save rename failed")
	}
}

func (d *Daemon) runStateSaver(ctx context.Context) {
	defer d.wg.Done()
	t := time.NewTicker(d.cfg.StateSaveInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.mu.Lock()
			d.saveAllState()
			d.mu.Unlock()
		}
	}
}

func (d *Daemon) Stop(ctx context.Context) error {
	d.reloadMu.Lock()
	defer d.reloadMu.Unlock()
	d.log.Info().Msg("daemon stopping")
	if d.rootCancel != nil {
		d.rootCancel()
	}
	if d.control != nil {
		if err := d.control.Stop(ctx); err != nil {
			d.log.Warn().Err(err).Msg("control stop")
		}
	}

	d.mu.Lock()
	for _, ri := range d.rules {
		if ri.cancel != nil {
			ri.cancel()
		}
	}
	for name, si := range d.sources {
		if err := si.src.Close(); err != nil {
			d.log.Warn().Err(err).Str("source", name).Msg("source close")
		}
	}
	d.mu.Unlock()

	done := make(chan struct{})
	go func() { d.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		d.log.Warn().Msg("shutdown deadline reached, abandoning goroutines")
	}

	d.mu.Lock()
	d.saveAllState()
	d.mu.Unlock()
	_ = d.banner.Close(ctx, d.cfg.FlushOnExit)
	d.closeAudit()
	d.log.Info().Msg("daemon stopped")
	return nil
}

func (d *Daemon) closeAudit() {
	if d.auditCloser != nil {
		_ = d.auditCloser()
		d.auditCloser = nil
	}
}

func (d *Daemon) runSweeper(ctx context.Context) {
	defer d.wg.Done()
	t := time.NewTicker(d.sweepInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.mu.Lock()
			for name, ri := range d.rules {
				if n := ri.rule.Sweep(); n > 0 {
					d.log.Debug().Str("rule", name).Int("dropped", n).Msg("tracker sweep")
				}
			}
			d.mu.Unlock()
		}
	}
}

// ---- control.State implementation ----

func (d *Daemon) Status() control.StatusResp {
	listCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	bans, bannerErr := d.banner.List(listCtx)
	cancel()
	d.mu.Lock()
	defer d.mu.Unlock()
	degraded, dropped := 0, uint64(0)
	for _, si := range d.sources {
		h := si.src.Health()
		if h.Status == "degraded" || (h.Status == "stopped" && d.rootCtx != nil && d.rootCtx.Err() == nil) {
			degraded++
		}
		dropped += h.Dropped
	}
	resp := control.StatusResp{
		Version:         d.version,
		Uptime:          time.Since(d.startedAt).Truncate(time.Second).String(),
		StartedAt:       d.startedAt,
		Watchers:        len(d.sources),
		TotalBans:       len(bans),
		NumRules:        len(d.rules),
		NumSources:      len(d.sources),
		DegradedSources: degraded,
		DroppedLines:    dropped,
	}
	if bannerErr != nil {
		resp.BannerError = bannerErr.Error()
	}
	return resp
}

func (d *Daemon) Sources() []control.SourceInfo {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]control.SourceInfo, 0, len(d.sources))
	for _, si := range d.sources {
		h := si.src.Health()
		out = append(out, control.SourceInfo{
			Name: h.Name, Status: h.Status, StartedAt: h.StartedAt, LastEventAt: h.LastEventAt,
			LastErrorAt: h.LastErrorAt, LastError: h.LastError, Reconnects: h.Reconnects,
			Subscribers: h.Subscribers, Delivered: h.Delivered, Dropped: h.Dropped, MaxQueueDepth: h.MaxQueueDepth,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (d *Daemon) Rules() []control.RuleInfo {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]control.RuleInfo, 0, len(d.rules))
	for name, ri := range d.rules {
		s := ri.rule.Stats()
		strikes := make(map[string]int)
		for ip, count := range ri.rule.Tracker().Snapshot() {
			strikes[ip.String()] = count
		}
		out = append(out, control.RuleInfo{
			Name: name, Source: ri.sourceName, Regex: ri.rule.Pattern(), Threshold: s.Threshold,
			FindTime: s.FindTime, BanTime: s.BanTime, Tracked: s.Tracked, Hits: s.Hits, Bans: s.Bans,
			Misses: s.Misses, Strikes: strikes, Datepattern: ri.rule.Datepattern(), Timezone: ri.rule.Timezone(),
			DateFailurePolicy: ri.rule.DateFailurePolicy(), Excludes: ri.rule.Excludes(), Allowlist: ri.rule.RuleAllowlist(), GlobalAllowlist: ri.rule.GlobalAllowlist(),
			TrustedProxyCapture: ri.rule.TrustedProxyCapture(), TrustedProxies: ri.rule.TrustedProxies(),
			DateParseFails: s.DateParseFails, DateDriftFallbacks: s.DateDriftFallbacks, DateDrops: s.DateDrops,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (d *Daemon) Banned(ctx context.Context) ([]control.BanInfo, error) {
	bans, err := d.banner.List(ctx)
	if err != nil {
		return nil, err
	}
	if d.pruneBanMetadata(bans) {
		d.saveBanMetadata()
	}
	out := make([]control.BanInfo, 0, len(bans))
	for _, b := range bans {
		meta := d.overlayBanMetadata(b.IP, b.Rule)
		out = append(out, control.BanInfo{
			DecisionID: meta.DecisionID, IP: b.IP.String(), Rule: meta.Rule, Source: meta.Source, Origin: meta.Origin, BannedAt: meta.BannedAt,
			TTL: b.TTL, ExpiresAt: b.ExpiresAt, EvidenceCount: meta.EvidenceCount, FirstSeen: meta.FirstSeen, LastSeen: meta.LastSeen,
		})
	}
	return out, nil
}

func (d *Daemon) Unban(ctx context.Context, ip netip.Addr) error {
	if err := d.banner.Unban(ctx, ip); err != nil {
		return err
	}
	d.recordUnban(ip, "manual")
	return nil
}

func (d *Daemon) BanManual(ctx context.Context, ip netip.Addr, ruleName string, ttl time.Duration) error {
	if err := d.banner.Ban(ctx, ip, ruleName, ttl); err != nil {
		return err
	}
	d.recordBan(banMetadata{DecisionID: newDecisionID(), IP: ip.String(), Rule: ruleName, Source: "manual", Origin: "manual", BannedAt: time.Now().UTC(), TTL: ttl.String()})
	return nil
}
