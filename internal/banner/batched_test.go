package banner

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

type countingBanner struct {
	mu       sync.Mutex
	batches  []int
	bans     atomic.Int64
	unbans   atomic.Int64
	listErr  error
	batchErr error
}

func (c *countingBanner) Setup(context.Context) error { return nil }
func (c *countingBanner) Ban(context.Context, netip.Addr, string, time.Duration) error {
	c.bans.Add(1)
	return nil
}
func (c *countingBanner) BanBatch(_ context.Context, reqs []BanRequest) error {
	c.mu.Lock()
	c.batches = append(c.batches, len(reqs))
	c.bans.Add(int64(len(reqs)))
	err := c.batchErr
	c.mu.Unlock()
	return err
}
func (c *countingBanner) Unban(context.Context, netip.Addr) error { c.unbans.Add(1); return nil }
func (c *countingBanner) List(context.Context) ([]BanInfo, error) { return nil, c.listErr }
func (c *countingBanner) Close(context.Context, bool) error       { return nil }

func banAsync(b *BatchedBanner, ip string) <-chan error {
	ch := make(chan error, 1)
	go func() { ch <- b.Ban(context.Background(), netip.MustParseAddr(ip), "sshd", time.Minute) }()
	return ch
}

func await(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for confirmed batch result")
		return nil
	}
}

func waitForPending(t *testing.T, b *BatchedBanner) {
	t.Helper()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		b.mu.Lock()
		pending := len(b.pending)
		b.mu.Unlock()
		if pending > 0 {
			return
		}
		select {
		case <-deadline.C:
			t.Fatal("timed out waiting for ban to enqueue")
		case <-ticker.C:
		}
	}
}

func TestBatched_FlushesBySizeAndAcknowledges(t *testing.T) {
	inner := &countingBanner{}
	b := NewBatched(inner, zerolog.Nop(), BatchOpts{FlushPeriod: time.Hour, FlushSize: 5})
	results := make([]<-chan error, 0, 5)
	for i := 1; i <= 5; i++ {
		results = append(results, banAsync(b, netip.AddrFrom4([4]byte{1, 2, 3, byte(i)}).String()))
	}
	for _, result := range results {
		if err := await(t, result); err != nil {
			t.Fatalf("Ban: %v", err)
		}
	}
	inner.mu.Lock()
	defer inner.mu.Unlock()
	if len(inner.batches) != 1 || inner.batches[0] != 5 {
		t.Fatalf("batches=%v, want [5]", inner.batches)
	}
}

func TestBatched_FlushesByTimer(t *testing.T) {
	inner := &countingBanner{}
	b := NewBatched(inner, zerolog.Nop(), BatchOpts{FlushPeriod: 20 * time.Millisecond, FlushSize: 1000})
	a := banAsync(b, "1.2.3.4")
	c := banAsync(b, "5.6.7.8")
	if err := await(t, a); err != nil {
		t.Fatal(err)
	}
	if err := await(t, c); err != nil {
		t.Fatal(err)
	}
	inner.mu.Lock()
	defer inner.mu.Unlock()
	if len(inner.batches) != 1 || inner.batches[0] != 2 {
		t.Fatalf("batches=%v, want [2]", inner.batches)
	}
}

func TestBatched_PropagatesKernelFailure(t *testing.T) {
	want := errors.New("netlink rejected element")
	inner := &countingBanner{batchErr: want}
	b := NewBatched(inner, zerolog.Nop(), BatchOpts{FlushPeriod: 10 * time.Millisecond, FlushSize: 100})
	if err := await(t, banAsync(b, "1.2.3.4")); !errors.Is(err, want) {
		t.Fatalf("err=%v, want %v", err, want)
	}
}

func TestBatched_CloseFlushesPending(t *testing.T) {
	inner := &countingBanner{}
	b := NewBatched(inner, zerolog.Nop(), BatchOpts{FlushPeriod: time.Hour, FlushSize: 1000})
	result := banAsync(b, "1.2.3.4")
	waitForPending(t, b)
	if err := b.Close(context.Background(), false); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := await(t, result); err != nil {
		t.Fatalf("Ban result: %v", err)
	}
	if inner.bans.Load() != 1 {
		t.Fatalf("bans=%d, want 1", inner.bans.Load())
	}
}

func TestBatched_UnbanPassesThrough(t *testing.T) {
	inner := &countingBanner{}
	b := NewBatched(inner, zerolog.Nop(), BatchOpts{})
	if err := b.Unban(context.Background(), netip.MustParseAddr("1.2.3.4")); err != nil {
		t.Fatal(err)
	}
	if inner.unbans.Load() != 1 {
		t.Fatalf("unbans=%d, want 1", inner.unbans.Load())
	}
}

func TestBatched_ListFlushesFirst(t *testing.T) {
	inner := &countingBanner{}
	b := NewBatched(inner, zerolog.Nop(), BatchOpts{FlushPeriod: time.Hour, FlushSize: 1000})
	result := banAsync(b, "1.2.3.4")
	waitForPending(t, b)
	if _, err := b.List(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := await(t, result); err != nil {
		t.Fatal(err)
	}
	if inner.bans.Load() != 1 {
		t.Fatalf("bans=%d, want 1", inner.bans.Load())
	}
}
