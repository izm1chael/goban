package enforcer

import (
	"fmt"
	"net/netip"

	"github.com/izm1chael/goban/internal/allowlist"
	"github.com/izm1chael/goban/internal/config"
)

// Policy duplicates the safety-critical allowlist boundary inside the
// privileged process. The unprivileged daemon remains the primary decision
// engine, but a compromised parser cannot ask the helper to ban protected
// management/local addresses simply by bypassing rule code.
type Policy struct {
	global      *allowlist.Allowlist
	perRule     map[string]*allowlist.Allowlist
	fingerprint string
}

func NewPolicy(cfg *config.Config) (*Policy, error) {
	global, err := allowlist.New(cfg.Allowlist)
	if err != nil {
		return nil, fmt.Errorf("enforcer global allowlist: %w", err)
	}
	if err := global.AddLocalInterfaces(); err != nil {
		return nil, fmt.Errorf("enforcer local-address allowlist: %w", err)
	}
	p := &Policy{global: global, perRule: make(map[string]*allowlist.Allowlist), fingerprint: config.EnforcementPolicyFingerprint(cfg)}
	for _, rc := range cfg.Rules {
		if len(rc.Allowlist) == 0 {
			continue
		}
		a, err := allowlist.New(rc.Allowlist)
		if err != nil {
			return nil, fmt.Errorf("enforcer rule %q allowlist: %w", rc.Name, err)
		}
		p.perRule[rc.Name] = a
	}
	return p, nil
}

func (p *Policy) ValidateBan(ip netip.Addr, rule string) error {
	ip = ip.Unmap()
	if !ip.IsValid() || ip.IsUnspecified() {
		return fmt.Errorf("invalid/unspecified address")
	}
	if ip.IsLoopback() || ip.IsMulticast() {
		return fmt.Errorf("refusing to ban loopback or multicast address %s", ip)
	}
	if p == nil {
		return nil
	}
	if p.global != nil && p.global.Permit(ip) {
		return fmt.Errorf("address %s is protected by the global/local allowlist", ip)
	}
	if a := p.perRule[rule]; a != nil && a.Permit(ip) {
		return fmt.Errorf("address %s is protected by rule %q allowlist", ip, rule)
	}
	return nil
}

func (p *Policy) Fingerprint() string {
	if p == nil {
		return ""
	}
	return p.fingerprint
}
