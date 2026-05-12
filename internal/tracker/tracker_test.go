package tracker

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse %s: %v", s, err)
	}
	return a
}

// fakeClock returns a controllable time source.
type fakeClock struct {
	now time.Time
}

func (c *fakeClock) Now() time.Time          { return c.now }
func (c *fakeClock) Advance(d time.Duration) { c.now = c.now.Add(d) }
func (c *fakeClock) Set(t time.Time)         { c.now = t }

func TestHit_TripsAtThreshold(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 5, 10, 12, 0, 0, 0, time.UTC)}
	tr := New(3, 10*time.Minute)
	tr.Now = clk.Now
	addr := mustAddr(t, "1.2.3.4")

	if tr.Hit(addr) {
		t.Fatal("first Hit should not trip")
	}
	clk.Advance(time.Second)
	if tr.Hit(addr) {
		t.Fatal("second Hit should not trip")
	}
	clk.Advance(time.Second)
	if !tr.Hit(addr) {
		t.Fatal("third Hit should trip threshold")
	}
}

func TestHit_OldStrikesExpire(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 5, 10, 12, 0, 0, 0, time.UTC)}
	tr := New(3, 5*time.Minute)
	tr.Now = clk.Now
	addr := mustAddr(t, "1.2.3.4")

	tr.Hit(addr)
	tr.Hit(addr)
	// jump past findtime; the two strikes should age out
	clk.Advance(6 * time.Minute)
	if tr.Hit(addr) {
		t.Fatal("third hit after window should not trip — older strikes expired")
	}
}

func TestReset(t *testing.T) {
	tr := New(3, 5*time.Minute)
	addr := mustAddr(t, "1.2.3.4")
	tr.Hit(addr)
	tr.Hit(addr)
	tr.Reset(addr)
	if tr.Size() != 0 {
		t.Fatalf("Size after Reset = %d, want 0", tr.Size())
	}
}

func TestSweep(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 5, 10, 12, 0, 0, 0, time.UTC)}
	tr := New(3, 5*time.Minute)
	tr.Now = clk.Now
	old := mustAddr(t, "10.0.0.1")
	cur := mustAddr(t, "10.0.0.2")

	tr.Hit(old)
	clk.Advance(6 * time.Minute)
	tr.Hit(cur)

	dropped := tr.Sweep()
	if dropped != 1 {
		t.Errorf("Sweep dropped = %d, want 1", dropped)
	}
	if tr.Size() != 1 {
		t.Errorf("Size after Sweep = %d, want 1", tr.Size())
	}
}

func TestSnapshot(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 5, 10, 12, 0, 0, 0, time.UTC)}
	tr := New(3, 5*time.Minute)
	tr.Now = clk.Now
	a := mustAddr(t, "1.1.1.1")
	b := mustAddr(t, "2.2.2.2")
	tr.Hit(a)
	tr.Hit(a)
	tr.Hit(b)
	snap := tr.Snapshot()
	if snap[a] != 2 {
		t.Errorf("snap[a] = %d, want 2", snap[a])
	}
	if snap[b] != 1 {
		t.Errorf("snap[b] = %d, want 1", snap[b])
	}
}

func TestShardingSpreadsLoad(t *testing.T) {
	// Sequential IPs across /24 should land on roughly every shard. We
	// don't assert perfect balance — just that more than one shard is used,
	// which guards against accidental degradation to a single-shard map.
	tr := New(1000, time.Minute)
	for i := 1; i <= 200; i++ {
		ip := mustAddr(t, fmt.Sprintf("10.0.0.%d", i))
		tr.Hit(ip)
	}
	used := 0
	for i := range tr.shards {
		if len(tr.shards[i].records) > 0 {
			used++
		}
	}
	if used < 4 {
		t.Errorf("only %d shards used out of %d — distribution is degenerate", used, shardCount)
	}
}

func TestHit_ConcurrentDifferentIPs(t *testing.T) {
	// Spread updates across many IPs (and therefore many shards) and ensure
	// every Hit is counted. -race must stay clean.
	tr := New(1000, 10*time.Minute)
	var wg sync.WaitGroup
	const goroutines = 16
	const perGoroutine = 1000
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for j := 0; j < perGoroutine; j++ {
				ip := mustAddr(t, fmt.Sprintf("10.%d.%d.%d", g, j/256, j%256))
				tr.Hit(ip)
			}
		}(g)
	}
	wg.Wait()
	if tr.Size() != goroutines*perGoroutine {
		t.Errorf("Size = %d, want %d", tr.Size(), goroutines*perGoroutine)
	}
}

func TestHit_Concurrent(t *testing.T) {
	tr := New(1000, 10*time.Minute)
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			addr := mustAddr(t, "10.0.0.1")
			for j := 0; j < 100; j++ {
				tr.Hit(addr)
			}
			_ = i
		}(i)
	}
	wg.Wait()
	snap := tr.Snapshot()
	if snap[mustAddr(t, "10.0.0.1")] != 1000 {
		t.Errorf("got %d hits, want 1000 (race or lost updates)", snap[mustAddr(t, "10.0.0.1")])
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	clk := &fakeClock{now: time.Date(2026, 5, 11, 12, 0, 0, 0, time.UTC)}
	src := New(3, 10*time.Minute)
	src.Now = clk.Now
	// Pre-populate with a few IPs and multiple strikes
	src.Hit(mustAddr(t, "1.2.3.4"))
	src.Hit(mustAddr(t, "1.2.3.4"))
	src.Hit(mustAddr(t, "5.6.7.8"))
	src.Hit(mustAddr(t, "2001:db8::1"))

	var buf bytes.Buffer
	if err := src.Save(&buf); err != nil {
		t.Fatalf("Save: %v", err)
	}

	dst := New(3, 10*time.Minute)
	dst.Now = clk.Now
	if err := dst.Load(&buf); err != nil {
		t.Fatalf("Load: %v", err)
	}

	srcSnap := src.Snapshot()
	dstSnap := dst.Snapshot()
	if len(srcSnap) != len(dstSnap) {
		t.Fatalf("snapshot sizes differ: src=%d dst=%d", len(srcSnap), len(dstSnap))
	}
	for addr, count := range srcSnap {
		if dstSnap[addr] != count {
			t.Errorf("addr %s count: src=%d dst=%d", addr, count, dstSnap[addr])
		}
	}
}

func TestLoadVersionMismatch(t *testing.T) {
	// Encode a state with the wrong Version field and verify Load rejects it.
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(savedState{Version: 99, SavedAt: time.Now(), Records: nil}); err != nil {
		t.Fatalf("encode: %v", err)
	}
	dst := New(3, time.Minute)
	if err := dst.Load(&buf); err == nil {
		t.Error("expected error on version mismatch, got nil")
	}
}

func TestHitAt_BackfilledEventCounts(t *testing.T) {
	// Three events from 8m, 5m, 2m ago — within a 10m window. Threshold
	// is 3 so the third should trip. Wall-clock Hit() would NOT trip
	// because all three strikes arrive at roughly the same wall-clock
	// time; HitAt with parsed times correctly distributes them.
	clk := &fakeClock{now: time.Date(2026, 5, 11, 12, 0, 0, 0, time.UTC)}
	tr := New(3, 10*time.Minute)
	tr.Now = clk.Now
	addr := mustAddr(t, "1.2.3.4")

	now := clk.Now()
	if tr.HitAt(addr, now.Add(-8*time.Minute)) {
		t.Fatal("first HitAt should not trip")
	}
	if tr.HitAt(addr, now.Add(-5*time.Minute)) {
		t.Fatal("second HitAt should not trip")
	}
	if !tr.HitAt(addr, now.Add(-2*time.Minute)) {
		t.Fatal("third HitAt should trip threshold")
	}
}

func TestHitAt_DropsEventsOlderThanWindow(t *testing.T) {
	// HitAt with an event from outside the sliding window should NOT count.
	clk := &fakeClock{now: time.Date(2026, 5, 11, 12, 0, 0, 0, time.UTC)}
	tr := New(3, 10*time.Minute)
	tr.Now = clk.Now
	addr := mustAddr(t, "1.2.3.4")
	old := clk.Now().Add(-30 * time.Minute)

	if tr.HitAt(addr, old) {
		t.Fatal("HitAt with too-old event should not trip")
	}
	// The strike should NOT be recorded — Snapshot should report zero.
	if got := tr.Snapshot()[addr]; got != 0 {
		t.Errorf("Snapshot[addr] = %d, want 0 (event was older than window)", got)
	}
}

func TestHitShimEqualsHitAtNow(t *testing.T) {
	// Hit and HitAt(now) must trip at the same point — the shim is the
	// only behavior used by rules that don't configure a datepattern.
	clk := &fakeClock{now: time.Date(2026, 5, 11, 12, 0, 0, 0, time.UTC)}
	a := New(3, 10*time.Minute)
	b := New(3, 10*time.Minute)
	a.Now = clk.Now
	b.Now = clk.Now
	addr := mustAddr(t, "1.2.3.4")
	for i := 0; i < 3; i++ {
		clk.Advance(time.Second)
		tripA := a.Hit(addr)
		tripB := b.HitAt(addr, clk.Now())
		if tripA != tripB {
			t.Fatalf("iteration %d: Hit=%v HitAt=%v — shim diverged", i, tripA, tripB)
		}
	}
}

func TestLoadEmptyReader(t *testing.T) {
	// Loading from an empty stream should be a no-op (no error).
	dst := New(3, time.Minute)
	if err := dst.Load(&bytes.Buffer{}); err != nil {
		t.Errorf("Load(empty) returned error: %v", err)
	}
	if dst.Size() != 0 {
		t.Errorf("Size() = %d, want 0", dst.Size())
	}
}
