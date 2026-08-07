package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"time"

	"github.com/rs/zerolog"

	"github.com/izm1chael/goban/internal/banner"
	"github.com/izm1chael/goban/internal/config"
	"github.com/izm1chael/goban/internal/source"
)

// Reload builds a complete candidate graph before pausing the active rule
// consumers. Candidate sources start while the old sources remain attached.
// At cutover, both bounded queues are reconciled as multisets: every event
// buffered by the old graph is processed once, and equivalent events already
// present in the candidate queues are discarded only when they were received
// before the corresponding old source stopped. This closes both sides of the
// hand-off: events cannot fall into a seek/start gap, and overlap cannot
// double-count.
//
// If any candidate source fails to start, already-started candidates are
// closed while the old graph keeps consuming throughout. The active config,
// consumers, and sources therefore remain unchanged.
func (d *Daemon) Reload(requestCtx context.Context) error {
	// A control-client disconnect must not cancel a cutover after it has begun.
	// The daemon lifecycle context remains authoritative; requestCtx is used only
	// to reject a request that was already cancelled before work started.
	if err := requestCtx.Err(); err != nil {
		return err
	}
	d.reloadMu.Lock()
	defer d.reloadMu.Unlock()

	newCfg, err := loadFreshConfig(d.cfgPath, d.rulesDir)
	if err != nil {
		return fmt.Errorf("reload load: %w", err)
	}
	applyRuntimeOverrides(newCfg, d.runtimeOverrides)
	if err := newCfg.Validate(); err != nil {
		return fmt.Errorf("reload validate: %w", err)
	}
	if err := assertImmutableFieldsUnchanged(d.cfg, newCfg); err != nil {
		return fmt.Errorf("reload refused: %w", err)
	}
	if d.rootCtx != nil {
		if err := d.rootCtx.Err(); err != nil {
			return err
		}
	}

	candidateAllowlist, err := buildAllowlist(newCfg.Allowlist)
	if err != nil {
		return fmt.Errorf("reload allowlist: %w", err)
	}
	candidateSources := make(map[string]*sourceInstance, len(newCfg.Sources))
	for _, sc := range newCfg.Sources {
		// replay_on_start is intentionally startup-only. Replaying an entire
		// historical file on every SIGHUP would double-count old attacks and
		// can trigger false bans during an otherwise unrelated rule reload.
		src, err := buildSource(sc, false)
		if err != nil {
			closeSourceGraph(candidateSources)
			return fmt.Errorf("reload build source %q: %w", sc.Name, err)
		}
		candidateSources[sc.Name] = &sourceInstance{src: src}
	}
	candidateRules := make(map[string]*ruleInstance, len(newCfg.Rules))
	for _, rc := range newCfg.Rules {
		ri, err := d.buildRuleInstanceWithAllowlist(rc, candidateAllowlist)
		if err != nil {
			closeSourceGraph(candidateSources)
			return fmt.Errorf("reload build rule %q: %w", rc.Name, err)
		}
		candidateRules[rc.Name] = ri
	}

	bufSize := newCfg.StrikeChanSize
	if bufSize <= 0 {
		bufSize = 256
	}
	prepared := make([]string, 0, len(candidateRules))
	for name, ri := range candidateRules {
		if err := prepareRuleInstance(name, ri, candidateSources, bufSize); err != nil {
			d.cleanupPrepared(prepared, candidateRules, candidateSources)
			closeSourceGraph(candidateSources)
			return fmt.Errorf("reload prepare rule %q: %w", name, err)
		}
		prepared = append(prepared, name)
	}

	// Durable state is loaded before any candidate source can publish. An
	// unchanged active rule's newer in-memory state replaces it at cutover.
	for name, ri := range candidateRules {
		d.loadRuleState(name, ri)
	}

	d.mu.Lock()
	oldRules := d.rules
	oldSources := d.sources
	for _, ri := range oldRules {
		ri.beginCutoverRecording()
	}

	// Candidate producers start while the entire old graph remains live and
	// consuming. Each active old rule records a multiset of lines processed
	// during this overlap. If candidate startup fails, recording is disabled
	// and the old graph has never been paused, cancelled, or replaced.
	started := make([]string, 0, len(candidateSources))
	for name, si := range candidateSources {
		if err := si.src.Start(d.rootCtx); err != nil {
			for _, oldRI := range oldRules {
				oldRI.endCutoverRecording()
			}
			for _, startedName := range started {
				_ = candidateSources[startedName].src.Close()
			}
			d.cleanupPrepared(prepared, candidateRules, candidateSources)
			closeSourceGraph(candidateSources)
			d.mu.Unlock()
			return fmt.Errorf("reload start source %q: %w", name, err)
		}
		started = append(started, name)
	}
	if err := drainReloadSources(d.rootCtx, oldSources); err != nil {
		d.log.Warn().Err(err).Msg("source drain incomplete before reload cutover")
	}

	// Split mode maintains an independent allowlist policy in the privileged
	// helper. Refresh it only after every candidate source has started, but
	// before the old consumers are cancelled. If root-side policy loading or
	// fingerprint verification fails, the old graph is still fully alive and
	// this reload can abort without a protection gap. Rebuild the helper policy
	// on every reload: exact local-interface protections can change because of
	// DHCP, IPv6 privacy addresses, or interface changes without changing YAML.
	if reloader, ok := d.banner.(banner.PolicyReloader); newCfg.Enforcer.Mode == "split" && ok {
		newPolicy := config.EnforcementPolicyFingerprint(newCfg)
		policyCtx, cancel := context.WithTimeout(d.rootCtx, 8*time.Second)
		err := reloader.ReloadPolicy(policyCtx, newPolicy)
		cancel()
		if err != nil {
			for _, oldRI := range oldRules {
				oldRI.endCutoverRecording()
			}
			for _, startedName := range started {
				_ = candidateSources[startedName].src.Close()
			}
			d.cleanupPrepared(prepared, candidateRules, candidateSources)
			closeSourceGraph(candidateSources)
			d.mu.Unlock()
			return fmt.Errorf("reload privileged enforcement policy: %w", err)
		}
	}

	// Candidate startup succeeded. Pause the old consumers only now, after
	// every candidate source is receiving. A slow candidate startup therefore
	// cannot overflow an artificially paused old queue.
	for _, ri := range oldRules {
		if ri.cancel != nil {
			ri.cancel()
		}
	}
	waitForRules(d.log, oldRules)

	for name, oldRI := range oldRules {
		newRI, ok := candidateRules[name]
		if !ok || oldRI.sig != newRI.sig {
			continue
		}
		if err := cloneTrackerState(oldRI, newRI); err != nil {
			d.log.Warn().Err(err).Str("rule", name).Msg("could not transfer live tracker state; durable snapshot retained")
		}
	}

	// Stop old producers, then drain their now-closed subscriber queues. The
	// dedupe multiset includes both lines processed by the live old consumers
	// during candidate startup and lines transferred from the old queues.
	oldClosedAt := make(map[string]time.Time, len(oldSources))
	for name, si := range oldSources {
		_ = si.src.Close()
		oldClosedAt[name] = time.Now()
	}
	oldCounts := make(map[string]map[string]int, len(oldRules))
	for name, oldRI := range oldRules {
		counts := oldRI.endCutoverRecording()
		newRI, ok := candidateRules[name]
		if !ok || oldRI.sourceName != newRI.sourceName || oldRI.input == nil {
			continue
		}
		for line := range oldRI.input {
			newRI.rule.Process(d.rootCtx, line)
			counts[reloadLineKey(line)]++
		}
		oldCounts[name] = counts
	}

	// Drain the candidate queues that accumulated during the overlap. A
	// candidate receipt timestamped after oldClosedAt cannot have come from
	// both generations and is always processed. Before that boundary, skip at
	// most the matching number of events already consumed from the old queue.
	for name, newRI := range candidateRules {
		counts := oldCounts[name]
		drainCandidateQueue(newRI, oldClosedAt[newRI.sourceName], counts, d.rootCtx)
	}

	d.cfg = newCfg
	d.allowlist = candidateAllowlist
	d.sources = candidateSources
	d.rules = candidateRules
	for _, name := range prepared {
		d.launchRuleInstance(candidateRules[name])
	}
	d.mu.Unlock()

	d.log.Info().
		Int("rules", len(candidateRules)).
		Int("sources", len(candidateSources)).
		Msg("config reloaded with transactional source cutover")
	return nil
}

type reloadDrainable interface {
	Drain(context.Context) error
}

func drainReloadSources(parent context.Context, sources map[string]*sourceInstance) error {
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	for name, si := range sources {
		drainable, ok := si.src.(reloadDrainable)
		if !ok {
			continue
		}
		if err := drainable.Drain(ctx); err != nil {
			return fmt.Errorf("drain source %q: %w", name, err)
		}
	}
	return nil
}

func reloadLineKey(line source.LogLine) string {
	// Length-prefix variable fields so arbitrary log content cannot create an
	// ambiguous concatenation. Event timestamps are intentionally excluded:
	// file and Docker generations can observe the same record at slightly
	// different times during overlap.
	return fmt.Sprintf("%d:%s%d:%s%d:%s%s", len(line.Source), line.Source, len(line.Container), line.Container, len(line.Unit), line.Unit, line.Text)
}

func (ri *ruleInstance) beginCutoverRecording() {
	ri.cutoverMu.Lock()
	ri.cutoverCounts = make(map[string]int)
	ri.cutoverRecord = true
	ri.cutoverMu.Unlock()
}

func (ri *ruleInstance) recordCutoverLine(line source.LogLine) {
	ri.cutoverMu.Lock()
	if ri.cutoverRecord {
		ri.cutoverCounts[reloadLineKey(line)]++
	}
	ri.cutoverMu.Unlock()
}

func (ri *ruleInstance) endCutoverRecording() map[string]int {
	ri.cutoverMu.Lock()
	counts := ri.cutoverCounts
	ri.cutoverRecord = false
	ri.cutoverCounts = nil
	ri.cutoverMu.Unlock()
	if counts == nil {
		counts = make(map[string]int)
	}
	return counts
}

func drainCandidateQueue(ri *ruleInstance, oldClosedAt time.Time, oldCounts map[string]int, ctx context.Context) {
	if ri == nil || ri.input == nil {
		return
	}
	for {
		select {
		case line, ok := <-ri.input:
			if !ok {
				return
			}
			received := line.ReceivedAt
			if received.IsZero() {
				received = line.Time
			}
			key := reloadLineKey(line)
			if !received.After(oldClosedAt) && oldCounts[key] > 0 {
				oldCounts[key]--
				continue
			}
			ri.rule.Process(ctx, line)
		default:
			return
		}
	}
}

func waitForRules(log zerolog.Logger, rules map[string]*ruleInstance) {
	for name, ri := range rules {
		if ri.done == nil {
			continue
		}
		timer := time.NewTimer(5 * time.Second)
		select {
		case <-ri.done:
			if !timer.Stop() {
				<-timer.C
			}
		case <-timer.C:
			// Do not return a failed reload while a cancelled consumer can
			// still stop later and leave the supposedly unchanged graph
			// unprotected. Continue waiting after surfacing the stall.
			log.Warn().Str("rule", name).Msg("rule stop exceeded 5s during reload cutover; waiting for safe hand-off")
			<-ri.done
		}
	}
}

func closeSourceGraph(sources map[string]*sourceInstance) {
	for _, si := range sources {
		_ = si.src.Close()
	}
}

func cloneTrackerState(oldRI, newRI *ruleInstance) error {
	var buf bytes.Buffer
	if err := oldRI.rule.Tracker().SaveWithFingerprint(&buf, oldRI.sig); err != nil {
		return err
	}
	return newRI.rule.Tracker().LoadWithFingerprint(&buf, newRI.sig)
}

// assertImmutableFieldsUnchanged allows only rules, sources, defaults and the
// global allowlist to change live. Every other field affects a long-lived
// component, ticker, socket, persistence path, or firewall graph and therefore
// requires a process restart rather than a misleading partial reload.
func assertImmutableFieldsUnchanged(oldCfg, newCfg *config.Config) error {
	oldStatic := *oldCfg
	newStatic := *newCfg
	oldStatic.Rules, newStatic.Rules = nil, nil
	oldStatic.Sources, newStatic.Sources = nil, nil
	oldStatic.Allowlist, newStatic.Allowlist = nil, nil
	oldStatic.Defaults, newStatic.Defaults = config.RuleDefaults{}, config.RuleDefaults{}
	if !reflect.DeepEqual(oldStatic, newStatic) {
		return fmt.Errorf("a restart-only setting changed (only rules, sources, defaults, and allowlist support hot reload)")
	}
	return nil
}

// ruleSig fingerprints every processing-semantic field. State from a rule is
// restored only when this fingerprint still matches.
func ruleSig(rc config.RuleConfig) string {
	normalized := rc
	normalized.Allowlist = append([]string(nil), rc.Allowlist...)
	sort.Strings(normalized.Allowlist)
	normalized.TrustedProxies = append([]string(nil), rc.TrustedProxies...)
	sort.Strings(normalized.TrustedProxies)
	data, _ := json.Marshal(normalized) // RuleConfig contains JSON-safe values.
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func applyRuntimeOverrides(cfg *config.Config, overrides RuntimeOverrides) {
	if overrides.LogLevel != "" {
		cfg.LogLevel = overrides.LogLevel
	}
	if overrides.LogFile != "" {
		cfg.LogFile = overrides.LogFile
	}
	if overrides.EnforcerMode != "" {
		cfg.Enforcer.Mode = overrides.EnforcerMode
	}
}

func loadFreshConfig(cfgPath, rulesDir string) (*config.Config, error) {
	return config.LoadEffective(cfgPath, rulesDir)
}
