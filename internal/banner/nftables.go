package banner

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/izm1chael/goban/internal/nftables"
)

// NFTablesCommander is the subset of nftables.Client this Banner depends on.
// Defining it as an interface lets tests substitute a recorder without
// opening a netlink socket (which requires CAP_NET_ADMIN).
type NFTablesCommander interface {
	Setup(ctx context.Context, cfg nftables.SetupConfig) error
	AddElement(ctx context.Context, table, setName string, family nftables.EntryFamily, ip netip.Addr, ttl time.Duration) error
	DelElement(ctx context.Context, table, setName string, family nftables.EntryFamily, ip netip.Addr) error
	ListElements(ctx context.Context, table, setName string) ([]nftables.ListedEntry, error)
	DestroyTable(ctx context.Context, name string) error
	Close() error
}

// NFTables is the Banner implementation that talks to the kernel nf_tables
// subsystem via native netlink. It is selected by config when
// banner.backend == "nftables"; the default backend remains IPTables.
//
// Like IPTables, NFTables holds an in-memory rule-attribution map so the
// /banned listing can report which rule banned an IP. nftables itself
// doesn't track that.
type NFTables struct {
	Table   string
	SetV4   string
	SetV6   string
	Chain   string
	UseIPv6 bool

	cli    NFTablesCommander
	ownCli bool // we created cli ourselves and should Close it

	mu     sync.Mutex
	ruleOf map[netip.Addr]string
}

// NewNFTables returns an NFTables Banner. The actual netlink client is
// opened lazily on the first Setup call so tests that inject a mock via
// SetCommander aren't forced to root.
func NewNFTables(table, setV4, setV6, chain string, useIPv6 bool) *NFTables {
	return &NFTables{
		Table:   table,
		SetV4:   setV4,
		SetV6:   setV6,
		Chain:   chain,
		UseIPv6: useIPv6,
		ruleOf:  make(map[netip.Addr]string),
	}
}

// SetCommander overrides the netlink client (tests).
func (b *NFTables) SetCommander(c NFTablesCommander) {
	b.cli = c
	b.ownCli = false
}

// Setup creates the table, sets, chain, and rules. Idempotent.
func (b *NFTables) Setup(ctx context.Context) error {
	if b.cli == nil {
		cli, err := nftables.New()
		if err != nil {
			return fmt.Errorf("open netlink nftables socket (need CAP_NET_ADMIN): %w", err)
		}
		b.cli = cli
		b.ownCli = true
	}
	if err := b.cli.Setup(ctx, nftables.SetupConfig{
		Table: b.Table,
		SetV4: b.SetV4,
		SetV6: b.SetV6,
		Chain: b.Chain,
		IPv6:  b.UseIPv6,
	}); err != nil {
		return fmt.Errorf("nftables setup: %w", err)
	}
	return nil
}

// Ban adds ip to the appropriate set with the per-element TTL.
func (b *NFTables) Ban(ctx context.Context, ip netip.Addr, rule string, ttl time.Duration) error {
	if err := validateIP(ip); err != nil {
		return err
	}
	setName, family, err := b.routeFamily(ip)
	if err != nil {
		return err
	}
	if err := b.cli.AddElement(ctx, b.Table, setName, family, ip, ttl); err != nil {
		return fmt.Errorf("nft add element %s: %w", ip, err)
	}
	b.mu.Lock()
	b.ruleOf[ip] = rule
	b.mu.Unlock()
	return nil
}

// BanBatch loops over reqs and calls Ban for each. nftables doesn't have a
// per-element batching primitive equivalent to ipset's IPSET_ATTR_ADT —
// per-element NEWSETELEM messages already share the same netlink socket,
// so the kernel still processes them sequentially without the fork+exec
// overhead. Mirrors the IPTables backend's pattern.
func (b *NFTables) BanBatch(ctx context.Context, reqs []BanRequest) error {
	if len(reqs) == 0 {
		return nil
	}
	for _, r := range reqs {
		if err := b.Ban(ctx, r.IP, r.Rule, r.TTL); err != nil {
			return err
		}
	}
	return nil
}

// Unban removes ip from whichever set holds it.
func (b *NFTables) Unban(ctx context.Context, ip netip.Addr) error {
	if err := validateIP(ip); err != nil {
		return err
	}
	setName, family, err := b.routeFamily(ip)
	if err != nil {
		return err
	}
	if err := b.cli.DelElement(ctx, b.Table, setName, family, ip); err != nil {
		return fmt.Errorf("nft del element %s: %w", ip, err)
	}
	b.mu.Lock()
	delete(b.ruleOf, ip)
	b.mu.Unlock()
	return nil
}

// List enumerates current bans in both sets and attaches rule attribution.
func (b *NFTables) List(ctx context.Context) ([]BanInfo, error) {
	out := []BanInfo{}
	v4, err := b.cli.ListElements(ctx, b.Table, b.SetV4)
	if err != nil {
		return nil, fmt.Errorf("nft list %s: %w", b.SetV4, err)
	}
	now := time.Now()
	for _, e := range v4 {
		out = append(out, b.entryToBanInfo(e, now))
	}
	if b.UseIPv6 {
		v6, err := b.cli.ListElements(ctx, b.Table, b.SetV6)
		if err != nil {
			return nil, fmt.Errorf("nft list %s: %w", b.SetV6, err)
		}
		for _, e := range v6 {
			out = append(out, b.entryToBanInfo(e, now))
		}
	}
	return out, nil
}

// Close optionally destroys the table on shutdown.
func (b *NFTables) Close(ctx context.Context, flush bool) error {
	if flush && b.cli != nil {
		_ = b.cli.DestroyTable(ctx, b.Table)
	}
	if b.ownCli && b.cli != nil {
		_ = b.cli.Close()
		b.cli = nil
	}
	return nil
}

func (b *NFTables) routeFamily(ip netip.Addr) (string, nftables.EntryFamily, error) {
	if ip.Is6() && !ip.Is4In6() {
		if !b.UseIPv6 {
			return "", 0, fmt.Errorf("%s: ipv6 disabled by config", ip)
		}
		return b.SetV6, nftables.IPv6, nil
	}
	return b.SetV4, nftables.IPv4, nil
}

func (b *NFTables) entryToBanInfo(e nftables.ListedEntry, now time.Time) BanInfo {
	info := BanInfo{
		IP:   e.IP.Unmap(),
		Rule: b.ruleLookup(e.IP.Unmap()),
	}
	if e.Timeout > 0 {
		info.TTL = e.Timeout
		// nftables reports ExpiresIn (remaining) — but for /banned the
		// historical IPTables backend reports an extrapolated ExpiresAt
		// from TTL alone. Stay consistent: prefer the kernel's expire if
		// present, else fall back to now+TTL.
		if e.ExpiresIn > 0 {
			info.ExpiresAt = now.Add(e.ExpiresIn)
		} else {
			info.ExpiresAt = now.Add(info.TTL)
		}
	}
	return info
}

func (b *NFTables) ruleLookup(ip netip.Addr) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.ruleOf[ip]
}

// Compile-time assertion that NFTables satisfies the Banner interface.
var _ Banner = (*NFTables)(nil)
