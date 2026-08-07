// Package banner abstracts the network-level ban action so rules don't depend
// on iptables/ipset directly. The default implementation in iptables.go talks
// netlink directly to the kernel ipset subsystem; tests use noop.go.
package banner

import (
	"context"
	"fmt"
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

// Diagnostic is one backend-specific enforcement health check. It is kept in
// the banner package so doctor can inspect concrete firewall hooks without
// coupling the backend to the control API.
type Diagnostic struct {
	Name        string
	Status      string // pass, warn, fail, or skip
	Detail      string
	Remediation string
}

// Diagnoser is implemented by backends that can verify their installed
// packet-path hooks in addition to listing the underlying decision sets.
type Diagnoser interface {
	Diagnostics(ctx context.Context) []Diagnostic
}

// PolicyReloader is implemented by split-mode backends whose privileged
// safety policy is loaded independently from root-managed configuration.
// expectedFingerprint proves both sides resolved the same allowlist semantics.
type PolicyReloader interface {
	ReloadPolicy(ctx context.Context, expectedFingerprint string) error
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

func validateTTL(ttl time.Duration) error {
	if ttl < time.Second {
		return fmt.Errorf("ban ttl %s is below the kernel-safe minimum of 1s", ttl)
	}
	if ttl/time.Second > time.Duration(^uint32(0)) {
		return fmt.Errorf("ban ttl %s exceeds the kernel timeout maximum", ttl)
	}
	return nil
}
