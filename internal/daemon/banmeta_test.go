package daemon

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/rs/zerolog"

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
