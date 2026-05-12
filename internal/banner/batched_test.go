package banner

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

// countingBanner is a thin Banner that records every BanBatch / Ban call.
type countingBanner struct {
	mu       sync.Mutex
	batches  []int // sizes of received batches
	bans     atomic.Int64
	unbans   atomic.Int64
	listErr  error
}

func (c *countingBanner) Setup(_ context.Context) error { return nil }
func (c *countingBanner) Ban(_ context.Context, _ netip.Addr, _ string, _ time.Duration) error {
	c.bans.Add(1)
	return nil
}
func (c *countingBanner) BanBatch(_ context.Context, reqs []BanRequest) error {
	c.mu.Lock()
	c.batches = append(c.batches, len(reqs))
	c.bans.Add(int64(len(reqs)))
	c.mu.Unlock()
	return nil
}
func (c *countingBanner) Unban(_ context.Context, _ netip.Addr) error {
	c.unbans.Add(1)
	return nil
}
func (c *countingBanner) List(_ context.Context) ([]BanInfo, error) { return nil, c.listErr }
func (c *countingBanner) Close(_ context.Context, _ bool) error     { return nil }

func TestBatched_FlushesBySize(t *testing.T) {
	inner := &countingBanner{}
	b := NewBatched(inner, zerolog.Nop(), BatchOpts{FlushPeriod: time.Hour, FlushSize: 5})

	ctx := context.Background()
	for i := 0; i < 5; i++ {
		_ = b.Ban(ctx, netip.AddrFrom4([4]byte{1, 2, 3, byte(i + 1)}), "sshd", time.Minute)
	}
	// Should have flushed exactly one batch of 5.
	inner.mu.Lock()
	defer inner.mu.Unlock()
	if len(inner.batches) != 1 || inner.batches[0] != 5 {
		t.Errorf("batches = %v, want [5]", inner.batches)
	}
}

func TestBatched_FlushesByTimer(t *testing.T) {
	inner := &countingBanner{}
	b := NewBatched(inner, zerolog.Nop(), BatchOpts{FlushPeriod: 20 * time.Millisecond, FlushSize: 1000})

	ctx := context.Background()
	_ = b.Ban(ctx, netip.MustParseAddr("1.2.3.4"), "sshd", time.Minute)
	_ = b.Ban(ctx, netip.MustParseAddr("5.6.7.8"), "sshd", time.Minute)

	// Wait for timer to fire
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		inner.mu.Lock()
		n := len(inner.batches)
		inner.mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	inner.mu.Lock()
	defer inner.mu.Unlock()
	if len(inner.batches) != 1 || inner.batches[0] != 2 {
		t.Errorf("batches = %v, want [2]", inner.batches)
	}
}

func TestBatched_CloseFlushesPending(t *testing.T) {
	inner := &countingBanner{}
	b := NewBatched(inner, zerolog.Nop(), BatchOpts{FlushPeriod: time.Hour, FlushSize: 1000})

	ctx := context.Background()
	_ = b.Ban(ctx, netip.MustParseAddr("1.2.3.4"), "sshd", time.Minute)
	_ = b.Ban(ctx, netip.MustParseAddr("5.6.7.8"), "sshd", time.Minute)
	_ = b.Close(ctx, false)
	if inner.bans.Load() != 2 {
		t.Errorf("Close did not flush pending bans: got %d", inner.bans.Load())
	}
}

func TestBatched_UnbanPassesThrough(t *testing.T) {
	inner := &countingBanner{}
	b := NewBatched(inner, zerolog.Nop(), BatchOpts{})

	if err := b.Unban(context.Background(), netip.MustParseAddr("1.2.3.4")); err != nil {
		t.Fatalf("Unban: %v", err)
	}
	if inner.unbans.Load() != 1 {
		t.Errorf("unbans = %d, want 1", inner.unbans.Load())
	}
}

func TestBatched_ListFlushesFirst(t *testing.T) {
	inner := &countingBanner{}
	b := NewBatched(inner, zerolog.Nop(), BatchOpts{FlushPeriod: time.Hour, FlushSize: 1000})

	_ = b.Ban(context.Background(), netip.MustParseAddr("1.2.3.4"), "sshd", time.Minute)
	_, _ = b.List(context.Background())
	if inner.bans.Load() != 1 {
		t.Errorf("List did not flush pending: got %d bans", inner.bans.Load())
	}
}
