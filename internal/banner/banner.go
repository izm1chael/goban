// Package banner abstracts the network-level ban action so rules don't depend
// on iptables/ipset directly. The default implementation in iptables.go talks
// netlink directly to the kernel ipset subsystem; tests use noop.go.
package banner

import (
	"context"
	"net/netip"
	"time"
)

// BanRequest is one queued ban — used by BanBatch and the BatchedBanner
// decorator to coalesce many bans into a single kernel round-trip.
type BanRequest struct {
	IP   netip.Addr
	Rule string
	TTL  time.Duration
}

// BanInfo describes one currently-active ban.
type BanInfo struct {
	IP        netip.Addr
	Rule      string
	BannedAt  time.Time
	ExpiresAt time.Time // zero == permanent (no kernel timeout)
	TTL       time.Duration
}

// Banner manages the runtime ban set.
//
// Setup is invoked once at daemon start and must be idempotent — repeated
// invocations after a clean restart should not duplicate iptables rules.
//
// Ban records ip in the kernel set with a TTL; the kernel handles expiry, so
// implementations should NOT track a Go-side timer.
//
// BanBatch inserts many bans in one kernel round-trip. Implementations that
// don't have a native batch path may fall back to calling Ban in a loop.
//
// Unban removes ip immediately. Returns nil if ip is not currently banned.
//
// List returns all bans currently visible in the kernel set.
//
// Close optionally tears down rules; production callers usually pass false to
// preserve bans across daemon restart.
type Banner interface {
	Setup(ctx context.Context) error
	Ban(ctx context.Context, ip netip.Addr, rule string, ttl time.Duration) error
	BanBatch(ctx context.Context, reqs []BanRequest) error
	Unban(ctx context.Context, ip netip.Addr) error
	List(ctx context.Context) ([]BanInfo, error)
	Close(ctx context.Context, flush bool) error
}
