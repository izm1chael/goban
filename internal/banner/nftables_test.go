package banner

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/izm1chael/goban/internal/nftables"
)

// mockNFTablesCommander records every call so tests can assert that Banner
// methods delegate correctly without opening a real netlink socket.
type mockNFTablesCommander struct {
	setupCalls []nftables.SetupConfig
	adds       []nftAdd
	dels       []nftDel
	listsFor   []string
	destroyed  []string
	closed     int
	stored     map[string]map[netip.Addr]nftables.ListedEntry // setName → addr → entry
}

type nftAdd struct {
	table, set string
	family     nftables.EntryFamily
	ip         netip.Addr
	ttl        time.Duration
}

type nftDel struct {
	table, set string
	family     nftables.EntryFamily
	ip         netip.Addr
}

func newMockNFT() *mockNFTablesCommander {
	return &mockNFTablesCommander{
		stored: make(map[string]map[netip.Addr]nftables.ListedEntry),
	}
}

func (m *mockNFTablesCommander) Setup(ctx context.Context, cfg nftables.SetupConfig) error {
	m.setupCalls = append(m.setupCalls, cfg)
	return nil
}

func (m *mockNFTablesCommander) AddElement(ctx context.Context, table, set string, family nftables.EntryFamily, ip netip.Addr, ttl time.Duration) error {
	m.adds = append(m.adds, nftAdd{table, set, family, ip, ttl})
	if m.stored[set] == nil {
		m.stored[set] = make(map[netip.Addr]nftables.ListedEntry)
	}
	m.stored[set][ip] = nftables.ListedEntry{IP: ip, Timeout: ttl, ExpiresIn: ttl}
	return nil
}

func (m *mockNFTablesCommander) DelElement(ctx context.Context, table, set string, family nftables.EntryFamily, ip netip.Addr) error {
	m.dels = append(m.dels, nftDel{table, set, family, ip})
	if m.stored[set] != nil {
		delete(m.stored[set], ip)
	}
	return nil
}

func (m *mockNFTablesCommander) ListElements(ctx context.Context, table, set string) ([]nftables.ListedEntry, error) {
	m.listsFor = append(m.listsFor, set)
	out := make([]nftables.ListedEntry, 0, len(m.stored[set]))
	for _, e := range m.stored[set] {
		out = append(out, e)
	}
	return out, nil
}

func (m *mockNFTablesCommander) DestroyTable(ctx context.Context, name string) error {
	m.destroyed = append(m.destroyed, name)
	return nil
}

func (m *mockNFTablesCommander) Close() error {
	m.closed++
	return nil
}

func TestNFTables_SetupDelegatesConfig(t *testing.T) {
	b := NewNFTables("goban", "goban-ban-v4", "goban-ban-v6", "input", true)
	mock := newMockNFT()
	b.SetCommander(mock)

	if err := b.Setup(context.Background()); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if len(mock.setupCalls) != 1 {
		t.Fatalf("Setup called %d times, want 1", len(mock.setupCalls))
	}
	got := mock.setupCalls[0]
	if got.Table != "goban" || got.SetV4 != "goban-ban-v4" || got.SetV6 != "goban-ban-v6" || got.Chain != "input" || !got.IPv6 {
		t.Errorf("Setup config mismatch: got %+v", got)
	}
}

func TestNFTables_BanRoutesByFamily(t *testing.T) {
	b := NewNFTables("goban", "goban-ban-v4", "goban-ban-v6", "input", true)
	mock := newMockNFT()
	b.SetCommander(mock)

	v4 := netip.MustParseAddr("198.51.100.7")
	v6 := netip.MustParseAddr("2001:db8::1")
	ctx := context.Background()

	if err := b.Ban(ctx, v4, "sshd", time.Hour); err != nil {
		t.Fatalf("Ban v4: %v", err)
	}
	if err := b.Ban(ctx, v6, "nginx", time.Minute); err != nil {
		t.Fatalf("Ban v6: %v", err)
	}
	if len(mock.adds) != 2 {
		t.Fatalf("len(adds) = %d, want 2", len(mock.adds))
	}
	if mock.adds[0].set != "goban-ban-v4" || mock.adds[0].family != nftables.IPv4 || mock.adds[0].ip != v4 {
		t.Errorf("v4 add wrong: %+v", mock.adds[0])
	}
	if mock.adds[1].set != "goban-ban-v6" || mock.adds[1].family != nftables.IPv6 || mock.adds[1].ip != v6 {
		t.Errorf("v6 add wrong: %+v", mock.adds[1])
	}
}

func TestNFTables_BanRejectsIPv6WhenDisabled(t *testing.T) {
	b := NewNFTables("goban", "v4", "v6", "input", false)
	b.SetCommander(newMockNFT())
	v6 := netip.MustParseAddr("2001:db8::1")
	if err := b.Ban(context.Background(), v6, "test", time.Minute); err == nil {
		t.Fatal("expected error banning IPv6 when ipv6 is disabled")
	}
}

func TestNFTables_UnbanDelegates(t *testing.T) {
	b := NewNFTables("goban", "v4", "v6", "input", true)
	mock := newMockNFT()
	b.SetCommander(mock)
	ip := netip.MustParseAddr("198.51.100.7")
	if err := b.Ban(context.Background(), ip, "sshd", time.Hour); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	if err := b.Unban(context.Background(), ip); err != nil {
		t.Fatalf("Unban: %v", err)
	}
	if len(mock.dels) != 1 || mock.dels[0].ip != ip {
		t.Errorf("expected one del for %v, got %v", ip, mock.dels)
	}
}

func TestNFTables_ListIncludesRuleAttribution(t *testing.T) {
	b := NewNFTables("goban", "v4", "v6", "input", false)
	mock := newMockNFT()
	b.SetCommander(mock)
	ip := netip.MustParseAddr("198.51.100.7")
	ctx := context.Background()
	if err := b.Ban(ctx, ip, "sshd", time.Hour); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	bans, err := b.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(bans) != 1 {
		t.Fatalf("len(bans) = %d, want 1", len(bans))
	}
	if bans[0].IP != ip {
		t.Errorf("IP = %v, want %v", bans[0].IP, ip)
	}
	if bans[0].Rule != "sshd" {
		t.Errorf("Rule = %q, want sshd", bans[0].Rule)
	}
	if bans[0].TTL != time.Hour {
		t.Errorf("TTL = %v, want 1h", bans[0].TTL)
	}
}

func TestNFTables_CloseDestroysOnFlush(t *testing.T) {
	b := NewNFTables("goban", "v4", "v6", "input", false)
	mock := newMockNFT()
	b.SetCommander(mock)
	if err := b.Close(context.Background(), true); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if len(mock.destroyed) != 1 || mock.destroyed[0] != "goban" {
		t.Errorf("expected DestroyTable(goban), got %v", mock.destroyed)
	}
}

func TestNFTables_CloseNoFlushPreservesTable(t *testing.T) {
	b := NewNFTables("goban", "v4", "v6", "input", false)
	mock := newMockNFT()
	b.SetCommander(mock)
	if err := b.Close(context.Background(), false); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if len(mock.destroyed) != 0 {
		t.Errorf("Close(flush=false) should NOT destroy; got destroys=%v", mock.destroyed)
	}
}
