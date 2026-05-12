package banner

import (
	"context"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/izm1chael/goban/internal/ipset"
)

// recordingRunner captures iptables/ip6tables invocations for tests that
// exercise the chain-rule install code.
type recordingRunner struct {
	mu      sync.Mutex
	calls   [][]string
	respond func(name string, args []string) (stdout, stderr []byte, err error)
}

func (r *recordingRunner) Run(_ context.Context, name string, args ...string) ([]byte, []byte, error) {
	r.mu.Lock()
	r.calls = append(r.calls, append([]string{name}, args...))
	r.mu.Unlock()
	if r.respond != nil {
		return r.respond(name, args)
	}
	return nil, nil, nil
}

// fakeIPSet records ipset.Client calls and returns canned data. Lets the
// banner tests run without CAP_NET_ADMIN.
type fakeIPSet struct {
	mu       sync.Mutex
	creates  []ipset.CreateOptions
	adds     []addRec
	addBatch []batchRec
	dels     []delRec
	flushes  []string
	entries  map[string][]ipset.Entry // keyed by set name
}

type addRec struct {
	set    string
	family ipset.Family
	ip     netip.Addr
	ttl    time.Duration
}

type batchRec struct {
	set     string
	family  ipset.Family
	entries []ipset.Entry
}

type delRec struct {
	set    string
	family ipset.Family
	ip     netip.Addr
}

func newFakeIPSet() *fakeIPSet { return &fakeIPSet{entries: make(map[string][]ipset.Entry)} }

func (f *fakeIPSet) Create(_ context.Context, opts ipset.CreateOptions) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.creates = append(f.creates, opts)
	return nil
}

func (f *fakeIPSet) Add(_ context.Context, set string, family ipset.Family, ip netip.Addr, ttl time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.adds = append(f.adds, addRec{set, family, ip, ttl})
	return nil
}

func (f *fakeIPSet) AddBatch(_ context.Context, set string, family ipset.Family, entries []ipset.Entry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := make([]ipset.Entry, len(entries))
	copy(cp, entries)
	f.addBatch = append(f.addBatch, batchRec{set, family, cp})
	return nil
}

func (f *fakeIPSet) Del(_ context.Context, set string, family ipset.Family, ip netip.Addr) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dels = append(f.dels, delRec{set, family, ip})
	return nil
}

func (f *fakeIPSet) List(_ context.Context, set string) ([]ipset.Entry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]ipset.Entry, len(f.entries[set]))
	copy(out, f.entries[set])
	return out, nil
}

func (f *fakeIPSet) Flush(_ context.Context, set string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.flushes = append(f.flushes, set)
	delete(f.entries, set)
	return nil
}

func (f *fakeIPSet) Close() error { return nil }

func newTestBanner(t *testing.T, useIPv6 bool) (*IPTables, *fakeIPSet) {
	t.Helper()
	b := NewIPTables("goban-v4", "goban-v6", useIPv6)
	f := newFakeIPSet()
	b.SetIPSetCommander(f)
	return b, f
}

func TestBan_V4UsesIPv4Set(t *testing.T) {
	b, f := newTestBanner(t, true)
	if err := b.Ban(context.Background(), netip.MustParseAddr("1.2.3.4"), "sshd", 30*time.Second); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	if len(f.adds) != 1 {
		t.Fatalf("adds=%d, want 1", len(f.adds))
	}
	got := f.adds[0]
	if got.set != "goban-v4" || got.family != ipset.IPv4 || got.ip.String() != "1.2.3.4" || got.ttl != 30*time.Second {
		t.Errorf("add = %+v, want goban-v4/v4/1.2.3.4/30s", got)
	}
}

func TestBan_V6UsesIPv6Set(t *testing.T) {
	b, f := newTestBanner(t, true)
	if err := b.Ban(context.Background(), netip.MustParseAddr("2001:db8::1"), "sshd", time.Minute); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	if len(f.adds) != 1 || f.adds[0].set != "goban-v6" || f.adds[0].family != ipset.IPv6 {
		t.Errorf("v6 ban did not target goban-v6: %+v", f.adds)
	}
}

func TestBan_V6RejectedWhenDisabled(t *testing.T) {
	b, _ := newTestBanner(t, false)
	err := b.Ban(context.Background(), netip.MustParseAddr("2001:db8::1"), "sshd", time.Minute)
	if err == nil {
		t.Fatal("expected error banning v6 with ipv6 disabled")
	}
}

func TestBan_RejectsInvalidIP(t *testing.T) {
	b, _ := newTestBanner(t, false)
	if err := b.Ban(context.Background(), netip.Addr{}, "sshd", time.Minute); err == nil {
		t.Fatal("expected error for zero Addr")
	}
}

func TestBan_RejectsUnspecified(t *testing.T) {
	b, _ := newTestBanner(t, false)
	if err := b.Ban(context.Background(), netip.MustParseAddr("0.0.0.0"), "sshd", time.Minute); err == nil {
		t.Fatal("expected error for unspecified address")
	}
}

func TestBanBatch_SplitsByFamily(t *testing.T) {
	b, f := newTestBanner(t, true)
	reqs := []BanRequest{
		{IP: netip.MustParseAddr("1.2.3.4"), Rule: "sshd", TTL: time.Hour},
		{IP: netip.MustParseAddr("5.6.7.8"), Rule: "sshd", TTL: time.Hour},
		{IP: netip.MustParseAddr("2001:db8::1"), Rule: "sshd", TTL: time.Hour},
	}
	if err := b.BanBatch(context.Background(), reqs); err != nil {
		t.Fatalf("BanBatch: %v", err)
	}
	// BanBatch now sends one Add per entry (the IPSET_ATTR_ADT batched
	// encoding was rejected by some kernel versions). All three IPs should
	// have been Add()'d, split into the right ipset by family.
	if len(f.adds) != 3 {
		t.Fatalf("adds = %d, want 3", len(f.adds))
	}
	v4Count, v6Count := 0, 0
	for _, a := range f.adds {
		switch a.family {
		case ipset.IPv4:
			v4Count++
			if a.set != "goban-v4" {
				t.Errorf("v4 add targeted %q, want goban-v4", a.set)
			}
		case ipset.IPv6:
			v6Count++
			if a.set != "goban-v6" {
				t.Errorf("v6 add targeted %q, want goban-v6", a.set)
			}
		}
	}
	if v4Count != 2 || v6Count != 1 {
		t.Errorf("v4=%d v6=%d, want 2/1", v4Count, v6Count)
	}
}

func TestUnban_Plumbing(t *testing.T) {
	b, f := newTestBanner(t, true)
	ctx := context.Background()
	_ = b.Ban(ctx, netip.MustParseAddr("1.2.3.4"), "sshd", time.Hour)
	if err := b.Unban(ctx, netip.MustParseAddr("1.2.3.4")); err != nil {
		t.Fatalf("Unban: %v", err)
	}
	if len(f.dels) != 1 {
		t.Errorf("dels = %d, want 1", len(f.dels))
	}
}

func TestList_JoinsRuleAttribution(t *testing.T) {
	b, f := newTestBanner(t, false)
	// Pre-populate the fake ipset with two entries
	f.entries["goban-v4"] = []ipset.Entry{
		{IP: netip.MustParseAddr("1.2.3.4"), Timeout: 3589},
		{IP: netip.MustParseAddr("5.6.7.8"), Timeout: 0},
	}
	// Ban only attaches rule attribution for one IP
	_ = b.Ban(context.Background(), netip.MustParseAddr("1.2.3.4"), "sshd", time.Hour)
	bans, err := b.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(bans) != 2 {
		t.Fatalf("len(bans) = %d, want 2", len(bans))
	}
	// The first ban (1.2.3.4) was added through Ban, so it has rule attribution.
	// The second (5.6.7.8) only exists in the fake set; no attribution.
	gotForOne := ""
	gotForTwo := ""
	for _, b := range bans {
		switch b.IP.String() {
		case "1.2.3.4":
			gotForOne = b.Rule
		case "5.6.7.8":
			gotForTwo = b.Rule
		}
	}
	if gotForOne != "sshd" {
		t.Errorf("attribution for 1.2.3.4 = %q, want sshd", gotForOne)
	}
	if gotForTwo != "" {
		t.Errorf("attribution for 5.6.7.8 = %q, want empty", gotForTwo)
	}
}

func TestEnsureRule_IdempotentRule(t *testing.T) {
	rr := &recordingRunner{
		respond: func(name string, args []string) ([]byte, []byte, error) {
			if len(args) > 0 && args[0] == "-C" {
				return nil, nil, nil
			}
			return nil, nil, nil
		},
	}
	b := NewIPTables("v4", "v6", false)
	b.SetRunner(rr)
	if err := b.ensureRule(context.Background(), "iptables", "v4"); err != nil {
		t.Fatalf("ensureRule: %v", err)
	}
	if len(rr.calls) != 1 {
		t.Errorf("calls=%d, want 1 (only -C)", len(rr.calls))
	}
	if rr.calls[0][1] != "-C" {
		t.Errorf("first call wasn't -C: %v", rr.calls[0])
	}
}

func TestEnsureRule_InsertsWhenMissing(t *testing.T) {
	rr := &recordingRunner{
		respond: func(name string, args []string) ([]byte, []byte, error) {
			if len(args) > 0 && args[0] == "-C" {
				return nil, []byte("rule not found"), &mockErr{"check failed"}
			}
			return nil, nil, nil
		},
	}
	b := NewIPTables("v4", "v6", false)
	b.SetRunner(rr)
	if err := b.ensureRule(context.Background(), "iptables", "v4"); err != nil {
		t.Fatalf("ensureRule: %v", err)
	}
	if len(rr.calls) != 2 {
		t.Fatalf("calls=%d, want 2 (-C then -I)", len(rr.calls))
	}
	if rr.calls[1][1] != "-I" {
		t.Errorf("second call wasn't -I: %v", rr.calls[1])
	}
}

type mockErr struct{ msg string }

func (e *mockErr) Error() string { return e.msg }

func TestNoopBanner_RoundTrip(t *testing.T) {
	n := NewNoop()
	ctx := context.Background()
	ip := netip.MustParseAddr("1.2.3.4")
	if err := n.Ban(ctx, ip, "sshd", time.Hour); err != nil {
		t.Fatal(err)
	}
	bans, err := n.List(ctx)
	if err != nil || len(bans) != 1 {
		t.Fatalf("list bans=%v err=%v", bans, err)
	}
	if err := n.Unban(ctx, ip); err != nil {
		t.Fatal(err)
	}
	bans, _ = n.List(ctx)
	if len(bans) != 0 {
		t.Fatalf("after unban: %d bans, want 0", len(bans))
	}
}

func TestNoopBanner_BanBatch(t *testing.T) {
	n := NewNoop()
	ctx := context.Background()
	reqs := []BanRequest{
		{IP: netip.MustParseAddr("1.1.1.1"), Rule: "sshd", TTL: time.Hour},
		{IP: netip.MustParseAddr("2.2.2.2"), Rule: "sshd", TTL: time.Hour},
	}
	if err := n.BanBatch(ctx, reqs); err != nil {
		t.Fatalf("BanBatch: %v", err)
	}
	bans, _ := n.List(ctx)
	if len(bans) != 2 {
		t.Fatalf("len(bans) = %d, want 2", len(bans))
	}
	_ = strings.Contains // satisfy import
}
