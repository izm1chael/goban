package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/izm1chael/goban/internal/allowlist"
	"github.com/izm1chael/goban/internal/config"
)

// Reload reloads the daemon's config from disk and applies the diff atomically.
// Triggered by SIGHUP or POST /reload. On any validation or runtime failure,
// the running daemon is unchanged and the error is returned.
//
// Reloadable: rules (add/remove/change), sources (add/remove), global +
// per-rule allowlists, defaults (apply to NEW rules only).
//
// Restart-only (refused with a clear error): sock_path, state_path,
// audit_log, ipset_name_v4/v6, ipv6, dry_run, batch_bans, socket_mode/group.
// Listed by assertImmutableFieldsUnchanged below.
func (d *Daemon) Reload(_ context.Context) error {
	// 1. Load + validate new config from disk
	newCfg, err := loadFreshConfig(d.cfgPath, d.rulesDir)
	if err != nil {
		return fmt.Errorf("reload load: %w", err)
	}
	if err := newCfg.Validate(); err != nil {
		return fmt.Errorf("reload validate: %w", err)
	}
	if err := assertImmutableFieldsUnchanged(d.cfg, newCfg); err != nil {
		return fmt.Errorf("reload refused: %w", err)
	}

	// 2. Compute diff under the lock.
	d.mu.Lock()
	defer d.mu.Unlock()

	plan := d.computeReloadPlan(newCfg)

	// 3a. Stop removed/changed rules. Each rule's strike state is persisted
	// before the rule disappears so a future re-add (or daemon restart)
	// could resurrect it. The strike state is then released — the rule is
	// completely gone from in-memory state.
	for _, name := range plan.stopRules {
		ri := d.rules[name]
		d.saveRuleState(name, ri) // persist tracker for posterity
		// Cancel the rule's context so its goroutine exits.
		ri.cancel()
		// Unsubscribe from its source, closing the channel; the rule's
		// `range in` loop also terminates this way.
		if si, ok := d.sources[ri.sourceName]; ok {
			si.src.Unsubscribe(name)
			si.refcount--
		}
		// Wait for the goroutine to actually exit before continuing —
		// otherwise we could leak it past a reload cycle.
		select {
		case <-ri.done:
		case <-time.After(5 * time.Second):
			d.log.Warn().Str("rule", name).Msg("rule goroutine did not exit within 5s — proceeding anyway (likely goroutine leak)")
		}
		delete(d.rules, name)
	}

	// 3b. Close sources whose refcount dropped to zero.
	for name, si := range d.sources {
		if si.refcount == 0 && !plan.keepSource[name] {
			if err := si.src.Close(); err != nil {
				d.log.Warn().Err(err).Str("source", name).Msg("source close during reload")
			}
			delete(d.sources, name)
		}
	}

	// 3c. Rebuild global allowlist if changed.
	if plan.allowlistChanged {
		al, err := allowlist.New(newCfg.Allowlist)
		if err != nil {
			return fmt.Errorf("reload allowlist: %w", err)
		}
		_ = al.AddLocalInterfaces()
		d.allowlist = al
	}

	// 3d. Open new sources (those referenced by new/added rules but not
	// already running).
	for _, sc := range plan.addSources {
		s, err := buildSource(sc, newCfg.ReplayOnStart)
		if err != nil {
			return fmt.Errorf("reload build source %q: %w", sc.Name, err)
		}
		if err := s.Start(d.rootCtx); err != nil {
			return fmt.Errorf("reload start source %q: %w", sc.Name, err)
		}
		d.sources[sc.Name] = &sourceInstance{src: s}
	}

	// 3e. Start new/changed rules. If any fails, log and continue — we've
	// already torn down the old version, so partial application is the
	// least-bad outcome.
	bufSize := newCfg.StrikeChanSize
	if bufSize <= 0 {
		bufSize = 256
	}
	for _, rc := range plan.addRules {
		ri, err := d.buildRuleInstance(rc)
		if err != nil {
			d.log.Error().Err(err).Str("rule", rc.Name).Msg("reload: failed to build new rule")
			continue
		}
		d.rules[rc.Name] = ri
		if err := d.startRuleInstance(rc.Name, ri, bufSize); err != nil {
			d.log.Error().Err(err).Str("rule", rc.Name).Msg("reload: failed to start new rule")
			delete(d.rules, rc.Name)
			continue
		}
		// Try to restore prior strike state if a save file exists from a
		// previous run of this rule (e.g. the rule was just stopped and
		// re-added with a new signature — the operator probably wants the
		// strike state preserved, not just reset).
		if d.cfg.StatePath != "" {
			path := d.statePathFor(rc.Name)
			if f, err := os.Open(path); err == nil {
				_ = ri.rule.Tracker().Load(f)
				_ = f.Close()
			}
		}
	}

	d.cfg = newCfg
	d.log.Info().
		Int("added", len(plan.addRules)).
		Int("stopped", len(plan.stopRules)).
		Int("sources_added", len(plan.addSources)).
		Msg("config reloaded")
	return nil
}

// reloadPlan is the diff between the running state and the new config.
type reloadPlan struct {
	stopRules        []string            // rule names to tear down (removed OR changed)
	addRules         []config.RuleConfig // rules to construct (added OR changed)
	addSources       []config.SourceConfig
	keepSource       map[string]bool // source names still referenced
	allowlistChanged bool
}

// computeReloadPlan walks the new config and decides which rules/sources
// need adding, removing, or restarting. Called under d.mu.
func (d *Daemon) computeReloadPlan(newCfg *config.Config) reloadPlan {
	plan := reloadPlan{keepSource: make(map[string]bool)}

	// Build a map of new rules keyed by name for O(1) lookup.
	newRuleByName := make(map[string]config.RuleConfig)
	for _, rc := range newCfg.Rules {
		newRuleByName[rc.Name] = rc
		plan.keepSource[rc.Source] = true
	}

	// Existing rules: STOP if removed, STOP+ADD if changed.
	for name, ri := range d.rules {
		newRc, stillExists := newRuleByName[name]
		if !stillExists {
			plan.stopRules = append(plan.stopRules, name)
			continue
		}
		if ruleSig(newRc) != ri.sig {
			// Signature changed: treat as remove + add.
			plan.stopRules = append(plan.stopRules, name)
			plan.addRules = append(plan.addRules, newRc)
		}
	}

	// New rules: ADD.
	for _, rc := range newCfg.Rules {
		if _, exists := d.rules[rc.Name]; !exists {
			plan.addRules = append(plan.addRules, rc)
		}
	}

	// Sources to add: referenced by some rule, not currently in d.sources.
	seenSource := make(map[string]bool)
	for _, sc := range newCfg.Sources {
		if !plan.keepSource[sc.Name] {
			continue // unreferenced; ignore
		}
		if _, exists := d.sources[sc.Name]; exists {
			continue
		}
		if seenSource[sc.Name] {
			continue
		}
		seenSource[sc.Name] = true
		plan.addSources = append(plan.addSources, sc)
	}

	plan.allowlistChanged = !sameAllowlist(d.cfg.Allowlist, newCfg.Allowlist)

	// Sort for deterministic ordering (helps tests assert on the plan).
	sort.Strings(plan.stopRules)
	sort.Slice(plan.addRules, func(i, j int) bool { return plan.addRules[i].Name < plan.addRules[j].Name })
	sort.Slice(plan.addSources, func(i, j int) bool { return plan.addSources[i].Name < plan.addSources[j].Name })
	return plan
}

// assertImmutableFieldsUnchanged returns a non-nil error if any field that
// requires a full restart was changed between old and new config.
func assertImmutableFieldsUnchanged(oldCfg, newCfg *config.Config) error {
	check := func(name string, ok bool) error {
		if !ok {
			return fmt.Errorf("%s is restart-only and cannot be hot-reloaded", name)
		}
		return nil
	}
	if err := check("sock_path", oldCfg.SocketPath == newCfg.SocketPath); err != nil {
		return err
	}
	if err := check("socket_mode", oldCfg.SocketMode == newCfg.SocketMode); err != nil {
		return err
	}
	if err := check("socket_group", oldCfg.SocketGroup == newCfg.SocketGroup); err != nil {
		return err
	}
	if err := check("ipset_name_v4", oldCfg.IPSetNameV4 == newCfg.IPSetNameV4); err != nil {
		return err
	}
	if err := check("ipset_name_v6", oldCfg.IPSetNameV6 == newCfg.IPSetNameV6); err != nil {
		return err
	}
	if err := check("ipv6", oldCfg.IPv6 == newCfg.IPv6); err != nil {
		return err
	}
	if err := check("dry_run", oldCfg.DryRun == newCfg.DryRun); err != nil {
		return err
	}
	if err := check("batch_bans", oldCfg.BatchBans == newCfg.BatchBans); err != nil {
		return err
	}
	if err := check("state_path", oldCfg.StatePath == newCfg.StatePath); err != nil {
		return err
	}
	if err := check("audit_log", oldCfg.AuditLog == newCfg.AuditLog); err != nil {
		return err
	}
	return nil
}

// ruleSig hashes the semantically-significant fields of a RuleConfig so
// Reload can tell whether an existing rule is unchanged (keep) or modified
// (stop + start fresh).
func ruleSig(rc config.RuleConfig) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%s|%d|%s|%s|", rc.Name, rc.Source, rc.Regex, rc.MaxRetries, rc.FindTime, rc.BanTime)
	// Per-rule allowlist contributes; sort for stability.
	cidrs := append([]string(nil), rc.Allowlist...)
	sort.Strings(cidrs)
	for _, c := range cidrs {
		h.Write([]byte(c))
		h.Write([]byte("|"))
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// sameAllowlist compares two CIDR slices order-insensitively.
func sameAllowlist(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	aa := append([]string(nil), a...)
	bb := append([]string(nil), b...)
	sort.Strings(aa)
	sort.Strings(bb)
	for i := range aa {
		if aa[i] != bb[i] {
			return false
		}
	}
	return true
}

// loadFreshConfig reads cfgPath, applies the same env overrides and
// rules-dir merging that goban-daemon's main does, validates the result,
// and returns it. Mirrors cmd/goban-daemon/main.go:loadConfig but lives in
// the daemon package so Reload can call it without pulling cmd code.
func loadFreshConfig(cfgPath, rulesDir string) (*config.Config, error) {
	cfg, err := config.LoadConfigFromFile(cfgPath)
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	if err := config.ApplyEnvOverrides(cfg); err != nil {
		return nil, fmt.Errorf("env overrides: %w", err)
	}
	dir := rulesDir
	if dir == "" {
		dir = cfg.RulesDir
	}
	if dir != "" {
		extra, err := loadFreshRulesDir(dir)
		if err != nil {
			return nil, fmt.Errorf("load rules dir %s: %w", dir, err)
		}
		cfg.Rules = append(cfg.Rules, extra...)
	}
	cfg.ApplyRuleDefaults()
	return cfg, nil
}

func loadFreshRulesDir(dir string) ([]config.RuleConfig, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []config.RuleConfig
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		ext := strings.ToLower(filepath.Ext(name))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		rules, err := config.LoadRulesFile(filepath.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		out = append(out, rules...)
	}
	return out, nil
}
