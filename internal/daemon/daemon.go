// Package daemon wires sources, rules, the banner and the control server
// into a single supervised lifecycle. Supports hot config reload via
// Reload(ctx) — see internal/daemon/reload.go for the diff-and-swap logic.
package daemon

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
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

// ruleInstance holds a running rule plus the lifecycle handles needed to
// stop it individually during a reload.
type ruleInstance struct {
	rule       *rule.Rule
	sourceName string
	sig        string             // hash of semantically-significant config fields; used by Reload diff
	cancel     context.CancelFunc // per-rule cancel; cancelling unblocks the rule's Run goroutine
	done       chan struct{}      // closed when the rule's Run goroutine exits
}

// sourceInstance holds a running source plus a refcount of how many rules
// subscribe to it. When refcount drops to zero during reload, the source
// is closed.
type sourceInstance struct {
	src      source.Source
	refcount int
}

// Daemon is the top-level supervisor.
type Daemon struct {
	cfg     *config.Config
	log     zerolog.Logger
	version string

	// Paths used by Reload to re-read config from disk.
	cfgPath  string
	rulesDir string

	// rootCtx is the long-lived context tied to the process lifetime; passed
	// to sources at Start and to per-rule contexts as their parent.
	rootCtx context.Context

	allowlist *allowlist.Allowlist
	banner    banner.Banner
	control   *control.Server

	// mu guards rules + sources during Reload. Hot path (rule goroutines,
	// banner calls) does not acquire mu.
	mu      sync.Mutex
	rules   map[string]*ruleInstance
	sources map[string]*sourceInstance

	wg        sync.WaitGroup
	startedAt time.Time

	sweepInterval time.Duration
	auditCloser   func() error
}

// New builds a Daemon from a validated Config. It does NOT start any
// goroutines. cfgPath + rulesDir are remembered for Reload's use of the
// same load path on SIGHUP / POST /reload.
func New(cfg *config.Config, log zerolog.Logger, version, cfgPath, rulesDir string) (*Daemon, error) {
	al, err := allowlist.New(cfg.Allowlist)
	if err != nil {
		return nil, fmt.Errorf("allowlist: %w", err)
	}
	if err := al.AddLocalInterfaces(); err != nil {
		log.Warn().Err(err).Msg("could not enumerate local interfaces for allowlist")
	}

	var b banner.Banner
	switch {
	case cfg.DryRun:
		log.Warn().Msg("dry_run enabled — using noop banner (no kernel side-effects)")
		b = banner.NewNoop()
	case cfg.Banner.Backend == "nftables":
		log.Info().Str("backend", "nftables").Str("table", cfg.Banner.Table).Msg("banner backend")
		b = banner.NewNFTables(cfg.Banner.Table, cfg.Banner.SetV4, cfg.Banner.SetV6, cfg.Banner.Chain, cfg.IPv6)
	default:
		// "" or "iptables" — default
		b = banner.NewIPTables(cfg.IPSetNameV4, cfg.IPSetNameV6, cfg.IPv6)
	}
	if cfg.BatchBans {
		b = banner.NewBatched(b, log, banner.BatchOpts{})
	}

	d := &Daemon{
		cfg:           cfg,
		log:           log,
		version:       version,
		cfgPath:       cfgPath,
		rulesDir:      rulesDir,
		allowlist:     al,
		banner:        b,
		rules:         make(map[string]*ruleInstance),
		sources:       make(map[string]*sourceInstance),
		sweepInterval: time.Minute,
	}
	for _, sc := range cfg.Sources {
		s, err := buildSource(sc, cfg.ReplayOnStart)
		if err != nil {
			return nil, err
		}
		d.sources[sc.Name] = &sourceInstance{src: s}
	}
	for _, rc := range cfg.Rules {
		ri, err := d.buildRuleInstance(rc)
		if err != nil {
			return nil, err
		}
		d.rules[rc.Name] = ri
	}

	var audit *control.Audit
	if cfg.AuditLog != "" {
		a, closer, err := control.NewAuditFile(cfg.AuditLog)
		if err != nil {
			log.Warn().Err(err).Str("path", cfg.AuditLog).Msg("audit log disabled — could not open file")
		} else {
			audit = a
			d.auditCloser = closer
			log.Info().Str("path", cfg.AuditLog).Msg("audit log open")
		}
	}
	d.control = control.New(d, cfg.SocketPath, os.FileMode(cfg.SocketMode), log, audit)
	return d, nil
}

// buildSource constructs a Source from its config. Stateless; called by
// both New and Reload.
func buildSource(sc config.SourceConfig, replay bool) (source.Source, error) {
	switch sc.Type {
	case "file":
		return file.New(file.Config{
			Name:       sc.Name,
			Path:       sc.Path,
			Replay:     replay,
			MaxLineLen: config.DefaultMaxLineBytes,
		}), nil
	case "docker":
		s, err := docker.New(docker.Config{
			Name:       sc.Name,
			Container:  sc.Container,
			Labels:     sc.Labels,
			MaxLineLen: config.DefaultMaxLineBytes,
		})
		if err != nil {
			return nil, fmt.Errorf("source %q: %w", sc.Name, err)
		}
		return s, nil
	case "journal":
		return journal.New(journal.Config{
			Name:       sc.Name,
			Match:      sc.Match,
			MaxLineLen: config.DefaultMaxLineBytes,
		}), nil
	default:
		return nil, fmt.Errorf("source %q: unknown type %q", sc.Name, sc.Type)
	}
}

// buildRuleInstance constructs a ruleInstance (rule + signature + lifecycle
// handles unset) from a RuleConfig. Called by both New and Reload.
func (d *Daemon) buildRuleInstance(rc config.RuleConfig) (*ruleInstance, error) {
	var ruleAllow *allowlist.Allowlist
	if len(rc.Allowlist) > 0 {
		a, err := allowlist.New(rc.Allowlist)
		if err != nil {
			return nil, fmt.Errorf("rule %q allowlist: %w", rc.Name, err)
		}
		ruleAllow = a
	}
	r, err := rule.New(rule.Config{
		Name:          rc.Name,
		SourceName:    rc.Source,
		Pattern:       rc.Regex,
		MaxRetries:    rc.MaxRetries,
		FindTime:      rc.FindTime,
		BanTime:       rc.BanTime,
		Datepattern:   rc.Datepattern,
		Excludes:      rc.Excludes,
		Allowlist:     d.allowlist,
		AllowlistRule: ruleAllow,
		Banner:        d.banner,
		Logger:        d.log,
	})
	if err != nil {
		return nil, fmt.Errorf("rule %q: %w", rc.Name, err)
	}
	return &ruleInstance{
		rule:       r,
		sourceName: rc.Source,
		sig:        ruleSig(rc),
	}, nil
}

// Start brings up the banner, all sources, all rule goroutines, and the
// control server. Returns once everything is wired and running.
func (d *Daemon) Start(ctx context.Context) error {
	d.rootCtx = ctx
	d.startedAt = time.Now()
	if err := d.banner.Setup(ctx); err != nil {
		return fmt.Errorf("banner setup: %w", err)
	}
	for name, si := range d.sources {
		if err := si.src.Start(ctx); err != nil {
			return fmt.Errorf("source %q start: %w", name, err)
		}
	}
	bufSize := d.bufSize()
	for name, ri := range d.rules {
		if err := d.startRuleInstance(name, ri, bufSize); err != nil {
			return err
		}
	}
	d.wg.Add(1)
	go d.runSweeper(ctx)

	// Load any persisted strike state into each rule's tracker BEFORE
	// load starts flowing. Failures are logged but non-fatal.
	d.loadAllState()

	if d.cfg.StatePath != "" && d.cfg.StateSaveInterval > 0 {
		d.wg.Add(1)
		go d.runStateSaver(ctx)
	}

	if err := d.control.Start(ctx); err != nil {
		return fmt.Errorf("control start: %w", err)
	}

	d.log.Info().
		Int("sources", len(d.sources)).
		Int("rules", len(d.rules)).
		Msg("daemon started")
	return nil
}

func (d *Daemon) bufSize() int {
	bufSize := d.cfg.StrikeChanSize
	if bufSize <= 0 {
		bufSize = 256
	}
	return bufSize
}

// startRuleInstance subscribes the rule to its source, increments the
// source's refcount, spawns the rule's Run goroutine, and stores the
// per-rule cancel func + done channel on the instance.
func (d *Daemon) startRuleInstance(name string, ri *ruleInstance, bufSize int) error {
	si, ok := d.sources[ri.sourceName]
	if !ok {
		return fmt.Errorf("rule %q: source %q not built", name, ri.sourceName)
	}
	in := si.src.Subscribe(name, bufSize)
	si.refcount++
	ruleCtx, cancel := context.WithCancel(d.rootCtx)
	ri.cancel = cancel
	ri.done = make(chan struct{})
	d.wg.Add(1)
	go func(r *rule.Rule, in <-chan source.LogLine, ctx context.Context, done chan struct{}) {
		defer d.wg.Done()
		defer close(done)
		r.Run(ctx, in)
	}(ri.rule, in, ruleCtx, ri.done)
	return nil
}

// statePathFor returns the on-disk path for a specific rule's tracker state.
// We store one file per rule rather than one big bundle so adding/removing a
// rule doesn't invalidate the others' state.
func (d *Daemon) statePathFor(ruleName string) string {
	if d.cfg.StatePath == "" {
		return ""
	}
	dir := filepath.Dir(d.cfg.StatePath)
	base := strings.TrimSuffix(filepath.Base(d.cfg.StatePath), filepath.Ext(d.cfg.StatePath))
	return filepath.Join(dir, fmt.Sprintf("%s-%s.gob", base, ruleName))
}

// loadAllState reads each rule's persisted tracker state. Missing files and
// load errors are logged but never fatal.
func (d *Daemon) loadAllState() {
	if d.cfg.StatePath == "" {
		return
	}
	for name, ri := range d.rules {
		path := d.statePathFor(name)
		f, err := os.Open(path)
		if err != nil {
			if !os.IsNotExist(err) {
				d.log.Warn().Err(err).Str("path", path).Str("rule", name).Msg("state load skipped")
			}
			continue
		}
		if err := ri.rule.Tracker().Load(f); err != nil {
			d.log.Warn().Err(err).Str("path", path).Str("rule", name).Msg("state load discarded — clean start")
		} else {
			d.log.Info().Str("path", path).Str("rule", name).Int("tracked", ri.rule.Tracker().Size()).Msg("state loaded")
		}
		_ = f.Close()
	}
}

// saveAllState dumps each rule's tracker state to disk via temp file +
// atomic rename. Called periodically and on Stop.
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
}

// saveRuleState dumps a single rule's tracker state. Used by saveAllState
// and by Reload when stopping a rule (to ensure its strike state is
// preserved across the swap).
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
	if err := ri.rule.Tracker().Save(f); err != nil {
		_ = f.Close()
		d.log.Warn().Err(err).Str("rule", name).Msg("state save encode failed")
		_ = os.Remove(tmp)
		return
	}
	_ = f.Close()
	if err := os.Rename(tmp, path); err != nil {
		d.log.Warn().Err(err).Msg("state save rename failed")
		_ = os.Remove(tmp)
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

// Stop shuts the daemon down. It cancels the parent context (the caller is
// responsible for that), waits for goroutines, stops the control server, and
// closes sources.
func (d *Daemon) Stop(ctx context.Context) error {
	d.log.Info().Msg("daemon stopping")
	if err := d.control.Stop(ctx); err != nil {
		d.log.Warn().Err(err).Msg("control stop")
	}
	done := make(chan struct{})
	go func() {
		d.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		d.log.Warn().Msg("shutdown deadline reached, abandoning goroutines")
	}
	d.mu.Lock()
	for name, si := range d.sources {
		if err := si.src.Close(); err != nil {
			d.log.Warn().Err(err).Str("source", name).Msg("source close")
		}
	}
	// One last state snapshot so an immediate restart sees the latest
	// counters. Best effort — log on failure but don't block shutdown.
	d.saveAllState()
	d.mu.Unlock()
	_ = d.banner.Close(ctx, d.cfg.FlushOnExit)
	if d.auditCloser != nil {
		_ = d.auditCloser()
	}
	d.log.Info().Msg("daemon stopped")
	return nil
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

// Status returns daemon-wide status information.
func (d *Daemon) Status() control.StatusResp {
	bans, _ := d.banner.List(context.Background())
	d.mu.Lock()
	defer d.mu.Unlock()
	return control.StatusResp{
		Version:    d.version,
		Uptime:     time.Since(d.startedAt).Truncate(time.Second).String(),
		StartedAt:  d.startedAt,
		Watchers:   len(d.sources),
		TotalBans:  len(bans),
		NumRules:   len(d.rules),
		NumSources: len(d.sources),
	}
}

// Rules returns per-rule introspection.
func (d *Daemon) Rules() []control.RuleInfo {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]control.RuleInfo, 0, len(d.rules))
	for name, ri := range d.rules {
		s := ri.rule.Stats()
		out = append(out, control.RuleInfo{
			Name:      name,
			Source:    ri.sourceName,
			Regex:     ri.rule.Pattern(),
			Threshold: s.Threshold,
			FindTime:  s.FindTime,
			BanTime:   s.BanTime,
			Tracked:   s.Tracked,
			Hits:      s.Hits,
			Bans:      s.Bans,
			Misses:    s.Misses,
		})
	}
	return out
}

// Banned returns the currently-active bans as seen by the banner.
func (d *Daemon) Banned(ctx context.Context) ([]control.BanInfo, error) {
	bans, err := d.banner.List(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]control.BanInfo, 0, len(bans))
	for _, b := range bans {
		out = append(out, control.BanInfo{
			IP:        b.IP.String(),
			Rule:      b.Rule,
			TTL:       b.TTL,
			ExpiresAt: b.ExpiresAt,
		})
	}
	return out, nil
}

// Unban removes ip from the banner.
func (d *Daemon) Unban(ctx context.Context, ip netip.Addr) error {
	return d.banner.Unban(ctx, ip)
}

// BanManual is invoked by POST /ban; uses the operator-supplied rule label.
func (d *Daemon) BanManual(ctx context.Context, ip netip.Addr, ruleName string, ttl time.Duration) error {
	return d.banner.Ban(ctx, ip, ruleName, ttl)
}
