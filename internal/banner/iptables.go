package banner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/izm1chael/goban/internal/ipset"
)

// Runner abstracts process invocation so tests can substitute a recorder
// without spawning real iptables/ip6tables. The command is constrained to a
// fixed set of firewall-management binaries by execRunner.Run. Note: the
// hot-path ipset operations (Add/Del/List/Flush) no longer go through this
// Runner — they use the netlink-direct IPSetCommander instead. Runner is
// still used for one-time chain-rule installation at Setup().
type Runner interface {
	Run(ctx context.Context, name string, args ...string) (stdout, stderr []byte, err error)
}

type execRunner struct{}

// Run invokes iptables or ip6tables with args. The command name is dispatched
// through a literal-only switch so static analyzers can verify
// exec.CommandContext is never given a non-constant binary path.
func (execRunner) Run(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
	var cmd *exec.Cmd
	switch name {
	case "iptables":
		cmd = exec.CommandContext(ctx, "iptables", args...)
	case "ip6tables":
		cmd = exec.CommandContext(ctx, "ip6tables", args...)
	default:
		return nil, nil, fmt.Errorf("banner: command %q not permitted", name)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

// IPSetCommander is the subset of ipset.Client we depend on. Defining it as
// an interface lets tests substitute a recorder without opening a netlink
// socket (which requires CAP_NET_ADMIN).
type IPSetCommander interface {
	Create(ctx context.Context, opts ipset.CreateOptions) error
	Add(ctx context.Context, setName string, family ipset.Family, ip netip.Addr, ttl time.Duration) error
	AddBatch(ctx context.Context, setName string, family ipset.Family, entries []ipset.Entry) error
	Del(ctx context.Context, setName string, family ipset.Family, ip netip.Addr) error
	List(ctx context.Context, setName string) ([]ipset.Entry, error)
	Flush(ctx context.Context, setName string) error
	Close() error
}

// IPTables is the production Banner. It manages two ipsets (v4 + v6) and
// installs INPUT chain rules referencing them.
type IPTables struct {
	SetV4   string
	SetV6   string
	UseIPv6 bool

	// runner handles iptables/ip6tables shell-exec (one-time chain-rule
	// install at Setup); the hot path goes through ipsetCmd.
	runner    Runner
	ipsetCmd  IPSetCommander
	ownIPSet  bool // we created ipsetCmd ourselves and should Close it

	mu     sync.Mutex
	ruleOf map[netip.Addr]string // rule attribution for /banned listing
}

// NewIPTables returns an IPTables Banner. setV4/setV6 are the ipset names.
// If useIPv6 is false the v6 path is skipped entirely. The netlink ipset
// client is opened lazily on the first Setup call so that tests injecting a
// mock via SetIPSetCommander aren't forced to root.
func NewIPTables(setV4, setV6 string, useIPv6 bool) *IPTables {
	return &IPTables{
		SetV4:   setV4,
		SetV6:   setV6,
		UseIPv6: useIPv6,
		runner:  execRunner{},
		ruleOf:  make(map[netip.Addr]string),
	}
}

// SetRunner overrides the process runner used for iptables/ip6tables (tests).
func (b *IPTables) SetRunner(r Runner) { b.runner = r }

// SetIPSetCommander overrides the netlink ipset client (tests). Once set,
// Close will not invoke the commander's Close — caller owns its lifecycle.
func (b *IPTables) SetIPSetCommander(c IPSetCommander) {
	b.ipsetCmd = c
	b.ownIPSet = false
}

// Setup verifies the firewall binaries exist, opens the netlink ipset
// client (unless one was injected), creates the ipsets, and installs the
// INPUT-chain DROP rules referencing them. All operations are idempotent.
func (b *IPTables) Setup(ctx context.Context) error {
	// iptables is still shell-exec'd for chain-rule install — verify it's there.
	if _, err := exec.LookPath("iptables"); err != nil {
		return fmt.Errorf("required binary %q not found in PATH (install via apk add iptables / apt install iptables): %w", "iptables", err)
	}
	if b.UseIPv6 {
		if _, err := exec.LookPath("ip6tables"); err != nil {
			return fmt.Errorf("ipv6 enabled but ip6tables not found in PATH: %w", err)
		}
	}

	if b.ipsetCmd == nil {
		cli, err := ipset.New()
		if err != nil {
			return fmt.Errorf("open netlink ipset socket (need CAP_NET_ADMIN): %w", err)
		}
		b.ipsetCmd = cli
		b.ownIPSet = true
	}

	if err := b.ipsetCmd.Create(ctx, ipset.CreateOptions{Name: b.SetV4, Family: ipset.IPv4}); err != nil {
		return fmt.Errorf("create ipv4 set: %w", err)
	}
	if err := b.ensureRule(ctx, "iptables", b.SetV4); err != nil {
		return fmt.Errorf("install iptables rule: %w", err)
	}
	if b.UseIPv6 {
		if err := b.ipsetCmd.Create(ctx, ipset.CreateOptions{Name: b.SetV6, Family: ipset.IPv6}); err != nil {
			return fmt.Errorf("create ipv6 set: %w", err)
		}
		if err := b.ensureRule(ctx, "ip6tables", b.SetV6); err != nil {
			return fmt.Errorf("install ip6tables rule: %w", err)
		}
	}
	return nil
}

func (b *IPTables) ensureRule(ctx context.Context, ipt, set string) error {
	ruleArgs := []string{"-m", "set", "--match-set", set, "src", "-j", "DROP"}
	checkArgs := append([]string{"-C", "INPUT"}, ruleArgs...)
	_, _, err := b.runner.Run(ctx, ipt, checkArgs...)
	if err == nil {
		return nil
	}
	insertArgs := append([]string{"-I", "INPUT", "1"}, ruleArgs...)
	if _, stderr, err := b.runner.Run(ctx, ipt, insertArgs...); err != nil {
		return fmt.Errorf("%s -I INPUT: %w (%s)", ipt, err, strings.TrimSpace(string(stderr)))
	}
	return nil
}

// Ban adds ip to the appropriate ipset with kernel-side TTL.
func (b *IPTables) Ban(ctx context.Context, ip netip.Addr, rule string, ttl time.Duration) error {
	if err := validateIP(ip); err != nil {
		return err
	}
	family := ipset.FamilyOf(ip)
	setName := b.SetV4
	if family == ipset.IPv6 {
		if !b.UseIPv6 {
			return fmt.Errorf("ban %s: ipv6 disabled by config", ip)
		}
		setName = b.SetV6
	}
	if err := b.ipsetCmd.Add(ctx, setName, family, ip, ttl); err != nil {
		return fmt.Errorf("ipset add %s: %w", ip, err)
	}
	b.mu.Lock()
	b.ruleOf[ip] = rule
	b.mu.Unlock()
	return nil
}

// BanBatch sends multiple bans in a single netlink syscall. All bans must
// share the same family. The batched path is significantly cheaper than
// looped Ban calls because the kernel processes the whole batch in one
// syscall round-trip.
func (b *IPTables) BanBatch(ctx context.Context, reqs []BanRequest) error {
	if len(reqs) == 0 {
		return nil
	}
	// Split by family. Even if the caller passes a mixed batch, we split
	// transparently so they don't have to.
	var v4, v6 []ipset.Entry
	v4Rules := make(map[netip.Addr]string)
	v6Rules := make(map[netip.Addr]string)
	for _, r := range reqs {
		if err := validateIP(r.IP); err != nil {
			return err
		}
		family := ipset.FamilyOf(r.IP)
		entry := ipset.Entry{IP: r.IP, Timeout: uint32(int64(r.TTL.Seconds()))}
		if family == ipset.IPv4 {
			v4 = append(v4, entry)
			v4Rules[r.IP] = r.Rule
		} else {
			if !b.UseIPv6 {
				return fmt.Errorf("ban %s: ipv6 disabled by config", r.IP)
			}
			v6 = append(v6, entry)
			v6Rules[r.IP] = r.Rule
		}
	}
	// Per-entry Add inside the loop rather than ipsetCmd.AddBatch.
	// The kernel's IPSET_ATTR_ADT validation is stricter than this code can
	// reliably satisfy across kernel versions (an earlier attempt at batched
	// ADD produced IPSET_ERR_PROTOCOL on Linux 6.6). Per-entry Add is still
	// dramatically cheaper than the v1 fork+exec because it stays on one
	// already-open netlink socket — each call is one syscall round-trip.
	for _, e := range v4 {
		ttl := time.Duration(e.Timeout) * time.Second
		if err := b.ipsetCmd.Add(ctx, b.SetV4, ipset.IPv4, e.IP, ttl); err != nil {
			return fmt.Errorf("ipset add v4 %s: %w", e.IP, err)
		}
	}
	for _, e := range v6 {
		ttl := time.Duration(e.Timeout) * time.Second
		if err := b.ipsetCmd.Add(ctx, b.SetV6, ipset.IPv6, e.IP, ttl); err != nil {
			return fmt.Errorf("ipset add v6 %s: %w", e.IP, err)
		}
	}
	b.mu.Lock()
	for ip, rule := range v4Rules {
		b.ruleOf[ip] = rule
	}
	for ip, rule := range v6Rules {
		b.ruleOf[ip] = rule
	}
	b.mu.Unlock()
	return nil
}

// Unban removes ip from whichever ipset holds it. Missing-entry errors are
// suppressed by the netlink layer (ENOENT is tolerated).
func (b *IPTables) Unban(ctx context.Context, ip netip.Addr) error {
	if err := validateIP(ip); err != nil {
		return err
	}
	family := ipset.FamilyOf(ip)
	setName := b.SetV4
	if family == ipset.IPv6 {
		if !b.UseIPv6 {
			return fmt.Errorf("unban %s: ipv6 disabled", ip)
		}
		setName = b.SetV6
	}
	if err := b.ipsetCmd.Del(ctx, setName, family, ip); err != nil {
		return fmt.Errorf("ipset del %s: %w", ip, err)
	}
	b.mu.Lock()
	delete(b.ruleOf, ip)
	b.mu.Unlock()
	return nil
}

// List enumerates current bans in both ipsets and joins them with the
// rule-attribution map populated by Ban.
func (b *IPTables) List(ctx context.Context) ([]BanInfo, error) {
	out := []BanInfo{}
	v4, err := b.ipsetCmd.List(ctx, b.SetV4)
	if err != nil {
		return nil, fmt.Errorf("ipset list %s: %w", b.SetV4, err)
	}
	now := time.Now()
	for _, e := range v4 {
		out = append(out, b.entryToBanInfo(e, now))
	}
	if b.UseIPv6 {
		v6, err := b.ipsetCmd.List(ctx, b.SetV6)
		if err != nil {
			return nil, fmt.Errorf("ipset list %s: %w", b.SetV6, err)
		}
		for _, e := range v6 {
			out = append(out, b.entryToBanInfo(e, now))
		}
	}
	return out, nil
}

func (b *IPTables) entryToBanInfo(e ipset.Entry, now time.Time) BanInfo {
	info := BanInfo{IP: e.IP.Unmap(), Rule: b.ruleLookup(e.IP.Unmap())}
	if e.Timeout > 0 {
		info.TTL = time.Duration(e.Timeout) * time.Second
		info.ExpiresAt = now.Add(info.TTL)
	}
	return info
}

func (b *IPTables) ruleLookup(ip netip.Addr) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.ruleOf[ip]
}

// Close optionally flushes the sets and releases the netlink socket.
func (b *IPTables) Close(ctx context.Context, flush bool) error {
	if flush && b.ipsetCmd != nil {
		_ = b.ipsetCmd.Flush(ctx, b.SetV4)
		if b.UseIPv6 {
			_ = b.ipsetCmd.Flush(ctx, b.SetV6)
		}
	}
	if b.ownIPSet && b.ipsetCmd != nil {
		_ = b.ipsetCmd.Close()
		b.ipsetCmd = nil
	}
	return nil
}

func validateIP(ip netip.Addr) error {
	if !ip.IsValid() {
		return errors.New("invalid IP")
	}
	if ip.IsUnspecified() {
		return errors.New("refusing to ban unspecified address")
	}
	return nil
}
