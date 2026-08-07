package daemon

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/izm1chael/goban/internal/allowlist"
	"github.com/izm1chael/goban/internal/banner"
	"github.com/izm1chael/goban/internal/config"
	"github.com/izm1chael/goban/internal/control"
)

func TestDecisionPipelineAuditsManualActionsExactlyOnce(t *testing.T) {
	var out bytes.Buffer
	d := &Daemon{
		log:     zerolog.Nop(),
		audit:   control.NewAuditWriter(&out),
		banMeta: newBanMetadataStore(),
	}
	d.recordBan(banMetadata{
		IP: "198.51.100.20", Rule: "manual", Source: "manual", Origin: "manual",
		BannedAt: time.Unix(100, 0).UTC(), TTL: time.Hour.String(),
	})
	d.recordUnban(netip.MustParseAddr("198.51.100.20"), "manual")

	scanner := bufio.NewScanner(bytes.NewReader(out.Bytes()))
	var events []control.AuditEvent
	for scanner.Scan() {
		var event control.AuditEvent
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatal(err)
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("audit events=%d, want 2: %s", len(events), out.String())
	}
	if events[0].Action != "ban" || events[0].DecisionID == "" || events[0].IP != "198.51.100.20" {
		t.Fatalf("ban event=%+v", events[0])
	}
	if events[1].Action != "unban" || events[1].IP != "198.51.100.20" || events[1].DecisionID != events[0].DecisionID || events[1].Rule != "manual" {
		t.Fatalf("unban event=%+v; ban event=%+v", events[1], events[0])
	}
}

func TestRestorePersistedBansRestoresOnlyConfirmedUnexpiredDecisions(t *testing.T) {
	now := time.Now().UTC()
	enforced := true
	dryRun := false
	al, err := allowlist.New([]string{"203.0.113.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	b := banner.NewNoop()
	d := &Daemon{
		cfg:       &config.Config{},
		log:       zerolog.Nop(),
		banner:    b,
		allowlist: al,
		banMeta:   newBanMetadataStore(),
	}
	d.banMeta.put(banMetadata{IP: "198.51.100.10", Rule: "sshd", BannedAt: now.Add(-10 * time.Minute), TTL: time.Hour.String(), Enforced: &enforced})
	d.banMeta.put(banMetadata{IP: "198.51.100.11", Rule: "sshd", BannedAt: now.Add(-2 * time.Hour), TTL: time.Hour.String(), Enforced: &enforced})
	d.banMeta.put(banMetadata{IP: "198.51.100.12", Rule: "sshd", BannedAt: now.Add(-10 * time.Minute), TTL: time.Hour.String(), Enforced: &dryRun})
	d.banMeta.put(banMetadata{IP: "198.51.100.13", Rule: "sshd", BannedAt: now.Add(-10 * time.Minute), TTL: time.Hour.String()}) // legacy attribution only
	d.banMeta.put(banMetadata{IP: "203.0.113.8", Rule: "sshd", BannedAt: now.Add(-10 * time.Minute), TTL: time.Hour.String(), Enforced: &enforced})

	d.restorePersistedBans(context.Background())
	got, err := b.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].IP != netip.MustParseAddr("198.51.100.10") {
		t.Fatalf("restored bans=%+v, want only 198.51.100.10", got)
	}
	if got[0].TTL < 49*time.Minute || got[0].TTL > 51*time.Minute {
		t.Fatalf("restored ttl=%s, want about 50m", got[0].TTL)
	}
	if missing := d.missingPersistedBans(got, time.Now().UTC()); missing != 0 {
		t.Fatalf("missing persisted bans=%d, want 0", missing)
	}
	for _, ip := range []string{"198.51.100.11", "198.51.100.12", "198.51.100.13", "203.0.113.8"} {
		if _, ok := d.banMeta.get(netip.MustParseAddr(ip)); ok {
			t.Fatalf("metadata for %s should have been pruned", ip)
		}
	}
}

func TestPruneKeepsMissingConfirmedDecisionUntilExpiry(t *testing.T) {
	enforced := true
	d := &Daemon{banMeta: newBanMetadataStore()}
	ip := netip.MustParseAddr("198.51.100.40")
	d.banMeta.put(banMetadata{IP: ip.String(), Rule: "sshd", BannedAt: time.Now().UTC(), TTL: time.Hour.String(), Enforced: &enforced})
	if changed := d.pruneBanMetadata(nil); changed {
		t.Fatal("unexpired confirmed metadata was pruned after kernel drift")
	}
	if _, ok := d.banMeta.get(ip); !ok {
		t.Fatal("confirmed metadata missing after prune")
	}
}

func TestRecordBanMarksDryRunDecisionAsNotEnforced(t *testing.T) {
	d := &Daemon{cfg: &config.Config{DryRun: true}, log: zerolog.Nop(), banMeta: newBanMetadataStore()}
	d.recordBan(banMetadata{IP: "198.51.100.50", Rule: "sshd", TTL: time.Hour.String(), BannedAt: time.Now().UTC()})
	meta, ok := d.banMeta.get(netip.MustParseAddr("198.51.100.50"))
	if !ok || meta.Enforced == nil || *meta.Enforced {
		t.Fatalf("dry-run metadata enforcement marker=%v, want false", meta.Enforced)
	}
}
