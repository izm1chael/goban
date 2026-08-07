package banner

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

var ErrClosed = errors.New("banner closed")

type queuedBan struct {
	req    BanRequest
	result chan error
}

// BatchedBanner coalesces nearby requests while preserving the Banner
// contract: Ban returns success only after the underlying kernel operation has
// acknowledged the request. This prevents trackers and audit logs from
// recording a ban that was merely queued and later failed.
type BatchedBanner struct {
	inner       Banner
	flushPeriod time.Duration
	flushSize   int
	log         zerolog.Logger

	mu      sync.Mutex
	pending []queuedBan
	timer   *time.Timer
	closed  bool
}

type BatchOpts struct {
	FlushPeriod time.Duration
	FlushSize   int
}

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
	}
}

func (b *BatchedBanner) Setup(ctx context.Context) error { return b.inner.Setup(ctx) }

// Diagnostics delegates packet-path verification to the wrapped backend.
func (b *BatchedBanner) Diagnostics(ctx context.Context) []Diagnostic {
	if d, ok := b.inner.(Diagnoser); ok {
		return d.Diagnostics(ctx)
	}
	return []Diagnostic{{Name: "firewall hooks", Status: "skip", Detail: "backend does not expose hook diagnostics"}}
}

func (b *BatchedBanner) ReloadPolicy(ctx context.Context, expectedFingerprint string) error {
	r, ok := b.inner.(PolicyReloader)
	if !ok {
		return nil
	}
	return r.ReloadPolicy(ctx, expectedFingerprint)
}

func (b *BatchedBanner) Ban(ctx context.Context, ip netip.Addr, rule string, ttl time.Duration) error {
	q := queuedBan{
		req:    BanRequest{IP: ip, Rule: rule, TTL: ttl},
		result: make(chan error, 1),
	}

	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return ErrClosed
	}
	b.pending = append(b.pending, q)
	var batch []queuedBan
	if len(b.pending) >= b.flushSize {
		batch = b.drainLocked()
	} else if b.timer == nil {
		b.timer = time.AfterFunc(b.flushPeriod, b.flushAsync)
	}
	b.mu.Unlock()

	if len(batch) > 0 {
		b.flush(batch)
	}

	select {
	case err := <-q.result:
		return err
	case <-ctx.Done():
		// The request may still be applied after caller cancellation. This is
		// unavoidable once a batch is in-flight; the returned context error makes
		// the ambiguity explicit instead of claiming success.
		return ctx.Err()
	}
}

func (b *BatchedBanner) BanBatch(ctx context.Context, reqs []BanRequest) error {
	return b.inner.BanBatch(ctx, reqs)
}

func (b *BatchedBanner) Unban(ctx context.Context, ip netip.Addr) error {
	return b.inner.Unban(ctx, ip)
}

func (b *BatchedBanner) List(ctx context.Context) ([]BanInfo, error) {
	b.mu.Lock()
	batch := b.drainLocked()
	b.mu.Unlock()
	if len(batch) > 0 {
		if err := b.flush(batch); err != nil {
			return nil, err
		}
	}
	return b.inner.List(ctx)
}

func (b *BatchedBanner) Close(ctx context.Context, flush bool) error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return b.inner.Close(ctx, flush)
	}
	b.closed = true
	batch := b.drainLocked()
	b.mu.Unlock()

	if len(batch) > 0 {
		if err := b.flush(batch); err != nil {
			return err
		}
	}
	return b.inner.Close(ctx, flush)
}

func (b *BatchedBanner) flushAsync() {
	b.mu.Lock()
	batch := b.drainLocked()
	b.mu.Unlock()
	if len(batch) > 0 {
		b.flush(batch)
	}
}

func (b *BatchedBanner) drainLocked() []queuedBan {
	if b.timer != nil {
		b.timer.Stop()
		b.timer = nil
	}
	if len(b.pending) == 0 {
		return nil
	}
	batch := b.pending
	b.pending = nil
	return batch
}

func (b *BatchedBanner) flush(batch []queuedBan) error {
	reqs := make([]BanRequest, len(batch))
	for i := range batch {
		reqs[i] = batch[i].req
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	err := b.inner.BanBatch(ctx, reqs)
	cancel()
	if err != nil {
		b.log.Error().Err(err).Int("size", len(batch)).Msg("batched ban flush failed")
	}
	for i := range batch {
		batch[i].result <- err
		close(batch[i].result)
	}
	return err
}
