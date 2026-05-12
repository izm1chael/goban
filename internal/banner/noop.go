package banner

import (
	"context"
	"net/netip"
	"sync"
	"time"
)

// NoopBanner records bans in memory only — no kernel side-effects. Used by
// tests, dry-run mode, and unit-test fixtures for the jail orchestrator.
type NoopBanner struct {
	mu   sync.Mutex
	bans map[netip.Addr]BanInfo
}

// NewNoop returns an empty in-memory Banner.
func NewNoop() *NoopBanner {
	return &NoopBanner{bans: make(map[netip.Addr]BanInfo)}
}

// Setup is a no-op.
func (n *NoopBanner) Setup(_ context.Context) error { return nil }

// Ban records the ban in memory.
func (n *NoopBanner) Ban(_ context.Context, ip netip.Addr, rule string, ttl time.Duration) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	now := time.Now()
	n.bans[ip] = BanInfo{
		IP:        ip,
		Rule:      rule,
		BannedAt:  now,
		ExpiresAt: now.Add(ttl),
		TTL:       ttl,
	}
	return nil
}

// BanBatch records every request in memory. For the noop banner, batched is
// equivalent to a Ban loop.
func (n *NoopBanner) BanBatch(ctx context.Context, reqs []BanRequest) error {
	for _, r := range reqs {
		if err := n.Ban(ctx, r.IP, r.Rule, r.TTL); err != nil {
			return err
		}
	}
	return nil
}

// Unban removes the ban from memory.
func (n *NoopBanner) Unban(_ context.Context, ip netip.Addr) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.bans, ip)
	return nil
}

// List returns the current in-memory bans.
func (n *NoopBanner) List(_ context.Context) ([]BanInfo, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([]BanInfo, 0, len(n.bans))
	for _, b := range n.bans {
		out = append(out, b)
	}
	return out, nil
}

// Close is a no-op.
func (n *NoopBanner) Close(_ context.Context, _ bool) error { return nil }
