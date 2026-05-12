package banner

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

// BatchedBanner wraps a Banner and coalesces ban requests inside a short
// flush window. Multiple Ban() calls arriving within the window are sent to
// the underlying Banner as a single BanBatch — for the netlink ipset client
// this collapses N kernel round-trips into one.
//
// Unban/List/Setup/Close pass through unchanged.
type BatchedBanner struct {
	inner       Banner
	flushPeriod time.Duration
	flushSize   int
	log         zerolog.Logger

	mu       sync.Mutex
	pending  []BanRequest
	timer    *time.Timer
	closed   bool
	closedCh chan struct{}
}

// BatchOpts configures the batching behavior. Zero-value fields use safe
// defaults.
type BatchOpts struct {
	FlushPeriod time.Duration // default 10ms
	FlushSize   int           // default 32 (flush early when this many pending)
}

// NewBatched wraps inner with batching. Calls to BatchedBanner.Ban return
// nil immediately after enqueuing; errors from the underlying Banner are
// surfaced through the logger instead of the caller. Synchronous error
// surfaces are available via BanBatch (which calls inner.BanBatch directly).
func NewBatched(inner Banner, log zerolog.Logger, opts BatchOpts) *BatchedBanner {
	if opts.FlushPeriod <= 0 {
		opts.FlushPeriod = 10 * time.Millisecond
	}
	if opts.FlushSize <= 0 {
		opts.FlushSize = 32
	}
	return &BatchedBanner{
		inner:       inner,
		flushPeriod: opts.FlushPeriod,
		flushSize:   opts.FlushSize,
		log:         log.With().Str("component", "banner.batched").Logger(),
		closedCh:    make(chan struct{}),
	}
}

// Setup forwards to inner.
func (b *BatchedBanner) Setup(ctx context.Context) error { return b.inner.Setup(ctx) }

// Ban enqueues the request. The actual kernel call happens in a background
// flush (at most flushPeriod later) or immediately when the queue reaches
// flushSize.
func (b *BatchedBanner) Ban(_ context.Context, ip netip.Addr, rule string, ttl time.Duration) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil
	}
	b.pending = append(b.pending, BanRequest{IP: ip, Rule: rule, TTL: ttl})
	if len(b.pending) >= b.flushSize {
		// Flush synchronously (still under lock — but the flush copies and
		// releases). Caller doesn't block on this path beyond the kernel
		// roundtrip for the batch they triggered.
		b.flushLocked()
		return nil
	}
	if b.timer == nil {
		b.timer = time.AfterFunc(b.flushPeriod, b.flushAsync)
	}
	return nil
}

// BanBatch forwards directly to inner.BanBatch — the caller already produced
// a batch, so we don't need to enqueue.
func (b *BatchedBanner) BanBatch(ctx context.Context, reqs []BanRequest) error {
	return b.inner.BanBatch(ctx, reqs)
}

// Unban passes through. Unbans are infrequent so there's no batching win.
func (b *BatchedBanner) Unban(ctx context.Context, ip netip.Addr) error {
	return b.inner.Unban(ctx, ip)
}

// List flushes pending bans first so the returned set reflects everything
// queued at call time, then forwards to inner.
func (b *BatchedBanner) List(ctx context.Context) ([]BanInfo, error) {
	b.mu.Lock()
	b.flushLocked()
	b.mu.Unlock()
	return b.inner.List(ctx)
}

// Close flushes any pending bans and shuts the inner banner.
func (b *BatchedBanner) Close(ctx context.Context, flush bool) error {
	b.mu.Lock()
	b.closed = true
	if b.timer != nil {
		b.timer.Stop()
		b.timer = nil
	}
	b.flushLocked()
	b.mu.Unlock()
	close(b.closedCh)
	return b.inner.Close(ctx, flush)
}

// flushAsync is called from the timer goroutine.
func (b *BatchedBanner) flushAsync() {
	b.mu.Lock()
	b.timer = nil
	b.flushLocked()
	b.mu.Unlock()
}

// flushLocked drains pending into inner.BanBatch. Caller must hold b.mu.
// We release the lock while the kernel call is in flight so concurrent Ban
// requests can keep enqueuing.
func (b *BatchedBanner) flushLocked() {
	if len(b.pending) == 0 {
		return
	}
	batch := b.pending
	b.pending = nil
	b.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	err := b.inner.BanBatch(ctx, batch)
	cancel()
	b.mu.Lock()
	if err != nil {
		b.log.Error().Err(err).Int("size", len(batch)).Msg("batched ban flush failed")
	}
}
