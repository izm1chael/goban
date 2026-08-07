package banner

import (
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
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
	Table        string
	SetV4        string
	SetV6        string
	Chain        string
	ForwardChain string
	UseIPv6      bool

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
		Table:        table,
		SetV4:        setV4,
		SetV6:        setV6,
		Chain:        chain,
		ForwardChain: "forward",
		UseIPv6:      useIPv6,
		ruleOf:       make(map[netip.Addr]string),
	}
}

// SetCommander overrides the netlink client (tests).
func (b *NFTables) SetCommander(c NFTablesCommander) {
	b.cli = c
	b.ownCli = false
}

// SetForwardChain enables or disables enforcement on forwarded traffic.
func (b *NFTables) SetForwardChain(name string) { b.ForwardChain = name }

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
		Table:        b.Table,
		SetV4:        b.SetV4,
		SetV6:        b.SetV6,
		Chain:        b.Chain,
		ForwardChain: b.ForwardChain,
		IPv6:         b.UseIPv6,
	}); err != nil {
		return fmt.Errorf("nftables setup: %w", err)
	}
	return nil
}

// Repair reconstructs GoBan's own nftables table when hook drift is detected.
// Active set elements are snapshotted first and restored with their remaining
// TTL after the table is recreated. GoBan never edits or flushes another
// application's table.
func (b *NFTables) Repair(ctx context.Context) error {
	if !ownedNFTTableName(b.Table) {
		return fmt.Errorf("refusing destructive nftables repair of non-GoBan-owned table %q; use table goban or a goban_ prefix", b.Table)
	}
	if b.cli == nil {
		cli, err := nftables.New()
		if err != nil {
			return fmt.Errorf("open netlink nftables socket (need CAP_NET_ADMIN): %w", err)
		}
		b.cli = cli
		b.ownCli = true
	}

	// Snapshot each family independently so a partial-table failure never
	// discards decisions that are still recoverable from the surviving set.
	type saved struct {
		ip     netip.Addr
		rule   string
		family nftables.EntryFamily
		set    string
		ttl    time.Duration
	}
	var existing []saved
	foundOwnedSet := false
	snapshot := func(set string, family nftables.EntryFamily) {
		entries, err := b.cli.ListElements(ctx, b.Table, set)
		if err != nil {
			return
		}
		foundOwnedSet = true
		for _, e := range entries {
			ttl := e.ExpiresIn
			if ttl <= 0 {
				ttl = e.Timeout
			}
			if ttl < time.Second {
				continue
			}
			ip := e.IP.Unmap()
			existing = append(existing, saved{ip: ip, rule: b.ruleLookup(ip), family: family, set: set, ttl: ttl})
		}
	}
	snapshot(b.SetV4, nftables.IPv4)
	if b.UseIPv6 {
		snapshot(b.SetV6, nftables.IPv6)
	}

	if foundOwnedSet {
		if err := b.cli.DestroyTable(ctx, b.Table); err != nil {
			return fmt.Errorf("nftables repair destroy owned table: %w", err)
		}
	} else {
		// A missing/partial table is the common drift case. Best-effort removal
		// clears any surviving children before Setup recreates the owned graph.
		_ = b.cli.DestroyTable(ctx, b.Table)
	}

	if err := b.cli.Setup(ctx, nftables.SetupConfig{
		Table:        b.Table,
		SetV4:        b.SetV4,
		SetV6:        b.SetV6,
		Chain:        b.Chain,
		ForwardChain: b.ForwardChain,
		IPv6:         b.UseIPv6,
	}); err != nil {
		return fmt.Errorf("nftables repair setup: %w", err)
	}

	for _, item := range existing {
		if err := b.cli.AddElement(ctx, b.Table, item.set, item.family, item.ip, item.ttl); err != nil {
			return fmt.Errorf("nftables repair restore %s: %w", item.ip, err)
		}
	}
	return nil
}

// Diagnostics uses the optional nft userspace inspector to verify that the
// configured base chains still reference GoBan's address sets. The daemon's
// enforcement hot path remains direct netlink; `nft` is used only for this
// human-invoked diagnostic because its rendered rule listing is the most
// portable way to confirm complete expressions across supported kernels.
func (b *NFTables) Diagnostics(ctx context.Context) []Diagnostic {
	if _, err := exec.LookPath("nft"); err != nil {
		return []Diagnostic{{
			Name:        "nftables hooks",
			Status:      "warn",
			Detail:      "the nft inspection utility is unavailable; set operations remain testable with --probe, but packet-path hook drift cannot be independently verified",
			Remediation: "install the nftables inspection utility or run the privileged packet-path integration test before treating doctor as fully healthy",
		}}
	}
	chains := []string{b.Chain}
	if b.ForwardChain != "" {
		chains = append(chains, b.ForwardChain)
	}
	checks := make([]Diagnostic, 0, len(chains))
	for _, chain := range chains {
		cmd := exec.CommandContext(ctx, "nft", "list", "chain", "inet", b.Table, chain)
		out, err := cmd.CombinedOutput()
		name := fmt.Sprintf("nftables %s hook", chain)
		if err != nil {
			detail := strings.TrimSpace(string(out))
			if detail == "" {
				detail = err.Error()
			}
			checks = append(checks, Diagnostic{
				Name:        name,
				Status:      "fail",
				Detail:      "configured base chain is missing or unreadable: " + detail,
				Remediation: "restart GoBan or restore the nftables table, then run the kernel integration test",
			})
			continue
		}
		rendered := string(out)
		missing := []string{}
		if !strings.Contains(rendered, "@"+b.SetV4) {
			missing = append(missing, b.SetV4)
		}
		if b.UseIPv6 && !strings.Contains(rendered, "@"+b.SetV6) {
			missing = append(missing, b.SetV6)
		}
		if len(missing) > 0 {
			checks = append(checks, Diagnostic{
				Name:        name,
				Status:      "fail",
				Detail:      fmt.Sprintf("chain exists but does not reference expected sets: %s", strings.Join(missing, ", ")),
				Remediation: "restart GoBan or restore its set-backed drop rules",
			})
			continue
		}
		checks = append(checks, Diagnostic{Name: name, Status: "pass", Detail: fmt.Sprintf("chain references @%s%s", b.SetV4, func() string {
			if b.UseIPv6 {
				return " and @" + b.SetV6
			}
			return ""
		}())})
	}
	return checks
}

// Ban adds ip to the appropriate set with the per-element TTL.
func (b *NFTables) Ban(ctx context.Context, ip netip.Addr, rule string, ttl time.Duration) error {
	if err := validateIP(ip); err != nil {
		return err
	}
	if err := validateTTL(ttl); err != nil {
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

func ownedNFTTableName(name string) bool {
	return name == "goban" || strings.HasPrefix(name, "goban_")
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
