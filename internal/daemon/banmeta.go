package daemon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/izm1chael/goban/internal/banner"
	"github.com/izm1chael/goban/internal/control"
	"github.com/izm1chael/goban/internal/rule"
)

type banMetadata struct {
	DecisionID    string    `json:"decision_id"`
	IP            string    `json:"ip"`
	Rule          string    `json:"rule"`
	Source        string    `json:"source"`
	Origin        string    `json:"origin"`
	BannedAt      time.Time `json:"banned_at"`
	TTL           string    `json:"ttl"`
	EvidenceCount int       `json:"evidence_count,omitempty"`
	FirstSeen     time.Time `json:"first_seen,omitempty"`
	LastSeen      time.Time `json:"last_seen,omitempty"`
	// Enforced distinguishes kernel-confirmed decisions from dry-run observations.
	// Pointer form is intentional: metadata written by older GoBan versions has
	// no value and is therefore never replayed after a reboot.
	Enforced *bool `json:"enforced,omitempty"`
}

type banMetadataStore struct {
	mu        sync.Mutex
	persistMu sync.Mutex
	records   map[netip.Addr]banMetadata
}

func newBanMetadataStore() *banMetadataStore {
	return &banMetadataStore{records: make(map[netip.Addr]banMetadata)}
}

func (s *banMetadataStore) put(meta banMetadata) {
	ip, err := netip.ParseAddr(meta.IP)
	if err != nil {
		return
	}
	s.mu.Lock()
	s.records[ip.Unmap()] = meta
	s.mu.Unlock()
}

func (s *banMetadataStore) del(ip netip.Addr) {
	s.mu.Lock()
	delete(s.records, ip.Unmap())
	s.mu.Unlock()
}

func (s *banMetadataStore) get(ip netip.Addr) (banMetadata, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.records[ip.Unmap()]
	return m, ok
}

func (s *banMetadataStore) retain(active map[netip.Addr]struct{}, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := false
	for ip, meta := range s.records {
		if _, ok := active[ip.Unmap()]; ok {
			continue
		}
		// Explicitly-enforced, unexpired decisions are durable intent. Keep
		// them even if a firewall reload temporarily removed the kernel entry;
		// startup can restore them and doctor can report the drift. Legacy
		// metadata (Enforced=nil) and dry-run observations are never replayed.
		if metadataRestorable(meta, now) {
			continue
		}
		delete(s.records, ip)
		changed = true
	}
	return changed
}

func (s *banMetadataStore) snapshot() []banMetadata {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]banMetadata, 0, len(s.records))
	for _, m := range s.records {
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP < out[j].IP })
	return out
}

func banMetadataPathFor(statePath string) string {
	if statePath == "" {
		return ""
	}
	dir := filepath.Dir(statePath)
	base := strings.TrimSuffix(filepath.Base(statePath), filepath.Ext(statePath))
	return filepath.Join(dir, base+"-bans.json")
}

func (d *Daemon) recordRuleBan(ev rule.BanEvent) {
	d.recordBan(banMetadata{
		DecisionID: newDecisionID(),
		IP:         ev.IP, Rule: ev.Rule, Source: ev.Source, Origin: "automatic",
		BannedAt: time.Now().UTC(), TTL: ev.TTL.String(),
		EvidenceCount: ev.EvidenceCount, FirstSeen: ev.FirstSeen.UTC(), LastSeen: ev.LastSeen.UTC(),
	})
}

func (d *Daemon) recordBan(meta banMetadata) {
	if meta.Enforced == nil {
		enforced := d.cfg == nil || !d.cfg.DryRun
		meta.Enforced = &enforced
	}
	if meta.DecisionID == "" {
		meta.DecisionID = newDecisionID()
	}
	if meta.BannedAt.IsZero() {
		meta.BannedAt = time.Now().UTC()
	}
	d.banMeta.put(meta)
	if d.audit != nil {
		if err := d.audit.Log(control.AuditEvent{
			Time: meta.BannedAt, Action: "ban", IP: meta.IP, Rule: meta.Rule, TTL: meta.TTL, Source: meta.Source, Origin: meta.Origin,
			DecisionID: meta.DecisionID, EvidenceCount: meta.EvidenceCount, FirstSeen: meta.FirstSeen, LastSeen: meta.LastSeen,
		}); err != nil {
			d.log.Error().Err(err).Msg("confirmed ban applied but audit write failed")
		}
	}
	d.saveBanMetadata()
}

func (d *Daemon) recordUnban(ip netip.Addr, source string) {
	meta, _ := d.banMeta.get(ip)
	d.banMeta.del(ip)
	if d.audit != nil {
		if err := d.audit.Log(control.AuditEvent{
			Action: "unban", IP: ip.String(), Rule: meta.Rule, Source: source, Origin: source, DecisionID: meta.DecisionID,
		}); err != nil {
			d.log.Error().Err(err).Msg("unban applied but audit write failed")
		}
	}
	d.saveBanMetadata()
}

func (d *Daemon) loadBanMetadata() {
	path := d.banMetaPath
	if path == "" {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			d.log.Warn().Err(err).Str("path", path).Msg("ban metadata load skipped")
		}
		return
	}
	var records []banMetadata
	if err := json.Unmarshal(data, &records); err != nil {
		d.log.Warn().Err(err).Str("path", path).Msg("ban metadata discarded")
		return
	}
	for _, m := range records {
		d.banMeta.put(m)
	}
}

func (d *Daemon) saveBanMetadata() {
	d.banMeta.persistMu.Lock()
	defer d.banMeta.persistMu.Unlock()
	path := d.banMetaPath
	if path == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		d.log.Warn().Err(err).Msg("ban metadata dir create")
		return
	}
	data, err := json.MarshalIndent(d.banMeta.snapshot(), "", "  ")
	if err != nil {
		d.log.Warn().Err(err).Msg("ban metadata encode")
		return
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		d.log.Warn().Err(err).Str("path", tmp).Msg("ban metadata write")
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		d.log.Warn().Err(err).Str("path", path).Msg("ban metadata rename")
	}
}

func (d *Daemon) pruneBanMetadata(bans []banner.BanInfo) bool {
	active := make(map[netip.Addr]struct{}, len(bans))
	for _, b := range bans {
		active[b.IP.Unmap()] = struct{}{}
	}
	return d.banMeta.retain(active, time.Now().UTC())
}

func metadataRestorable(meta banMetadata, now time.Time) bool {
	if meta.Enforced == nil || !*meta.Enforced || meta.BannedAt.IsZero() {
		return false
	}
	ttl, err := time.ParseDuration(meta.TTL)
	if err != nil || ttl < time.Second {
		return false
	}
	return meta.BannedAt.Add(ttl).After(now)
}

// restorePersistedBans re-applies kernel-confirmed decisions that were still
// live when the host went down. This makes reboot persistence backend-native:
// GoBan does not need to shell out to ipset/nft save/restore for new metadata.
// Older metadata is deliberately attribution-only because it cannot prove the
// decision came from real enforcement rather than dry-run mode.
func (d *Daemon) restorePersistedBans(ctx context.Context) {
	if d.cfg == nil || d.cfg.DryRun || d.banMeta == nil {
		return
	}
	bans, err := d.banner.List(ctx)
	if err != nil {
		d.log.Warn().Err(err).Msg("persisted ban restore skipped — backend list failed")
		return
	}
	active := make(map[netip.Addr]struct{}, len(bans))
	for _, b := range bans {
		active[b.IP.Unmap()] = struct{}{}
	}
	now := time.Now().UTC()
	changed := false
	for _, meta := range d.banMeta.snapshot() {
		ip, err := netip.ParseAddr(meta.IP)
		if err != nil {
			d.log.Warn().Str("ip", meta.IP).Msg("persisted ban metadata discarded — invalid address")
			// put() only accepts valid addresses, so malformed entries can only
			// originate from an older/on-disk file and will disappear on save.
			changed = true
			continue
		}
		ip = ip.Unmap()
		if _, ok := active[ip]; ok {
			continue
		}
		if !metadataRestorable(meta, now) {
			d.banMeta.del(ip)
			changed = true
			continue
		}
		if d.allowlist != nil && d.allowlist.Permit(ip) {
			d.log.Warn().Str("ip", ip.String()).Str("rule", meta.Rule).Msg("persisted ban not restored — address is now allowlisted")
			d.banMeta.del(ip)
			changed = true
			continue
		}
		ttl, _ := time.ParseDuration(meta.TTL)
		remaining := meta.BannedAt.Add(ttl).Sub(now)
		if remaining < time.Second {
			d.banMeta.del(ip)
			changed = true
			continue
		}
		if err := d.banner.Ban(ctx, ip, meta.Rule, remaining); err != nil {
			d.log.Error().Err(err).Str("ip", ip.String()).Str("rule", meta.Rule).Dur("remaining", remaining).Msg("persisted ban restore failed")
			continue
		}
		active[ip] = struct{}{}
		d.log.Info().Str("ip", ip.String()).Str("rule", meta.Rule).Dur("remaining", remaining).Msg("persisted ban restored")
	}
	if changed {
		d.saveBanMetadata()
	}
}

func (d *Daemon) missingPersistedBans(activeBans []banner.BanInfo, now time.Time) int {
	if d.banMeta == nil {
		return 0
	}
	active := make(map[netip.Addr]struct{}, len(activeBans))
	for _, b := range activeBans {
		active[b.IP.Unmap()] = struct{}{}
	}
	missing := 0
	for _, meta := range d.banMeta.snapshot() {
		if !metadataRestorable(meta, now) {
			continue
		}
		ip, err := netip.ParseAddr(meta.IP)
		if err != nil {
			continue
		}
		if _, ok := active[ip.Unmap()]; !ok {
			missing++
		}
	}
	return missing
}

func (d *Daemon) overlayBanMetadata(ip netip.Addr, ruleName string) banMetadata {
	m, ok := d.banMeta.get(ip)
	if !ok {
		return banMetadata{IP: ip.String(), Rule: ruleName}
	}
	if ruleName != "" {
		m.Rule = ruleName
	}
	return m
}

func newDecisionID() string {
	var raw [12]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return fmt.Sprintf("decision-%d", time.Now().UTC().UnixNano())
	}
	return "dec-" + hex.EncodeToString(raw[:])
}
