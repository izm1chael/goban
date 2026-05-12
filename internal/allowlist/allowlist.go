// Package allowlist holds CIDR ranges that must never be banned. The check is
// performed before strike registration so allowlisted IPs never accumulate
// state.
package allowlist

import (
	"fmt"
	"net"
	"net/netip"
)

// Allowlist is a set of CIDR prefixes; Permit returns true when an IP falls
// inside any of them.
type Allowlist struct {
	prefixes []netip.Prefix
}

// New parses a slice of CIDR strings (IPv4 or IPv6) and returns an Allowlist.
func New(cidrs []string) (*Allowlist, error) {
	out := &Allowlist{}
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("parse cidr %q: %w", c, err)
		}
		out.prefixes = append(out.prefixes, p.Masked())
	}
	return out, nil
}

// AddLocalInterfaces appends prefixes derived from each address bound to a
// local network interface, ensuring the host can never ban itself.
func (a *Allowlist) AddLocalInterfaces() error {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return fmt.Errorf("interface addrs: %w", err)
	}
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ones, _ := ipnet.Mask.Size()
		ip, ok := netip.AddrFromSlice(ipnet.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		p, err := ip.Prefix(ones)
		if err != nil {
			continue
		}
		a.prefixes = append(a.prefixes, p.Masked())
	}
	return nil
}

// Permit returns true when ip is allowed (i.e. must NOT be banned).
func (a *Allowlist) Permit(ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, p := range a.prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// Prefixes returns a copy of the configured prefix list.
func (a *Allowlist) Prefixes() []netip.Prefix {
	out := make([]netip.Prefix, len(a.prefixes))
	copy(out, a.prefixes)
	return out
}
