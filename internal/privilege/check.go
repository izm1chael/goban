// Package privilege defines GoBan's runtime least-privilege invariants.
package privilege

import (
	"fmt"

	"github.com/izm1chael/goban/internal/procinfo"
)

const (
	ZeroCapabilityMask = "0000000000000000"
	NetAdminOnlyMask   = "0000000000001000"
)

func ValidateDetector(s procinfo.Status) error {
	if s.UID == 0 {
		return fmt.Errorf("detector is running as root")
	}
	if s.CapEff != ZeroCapabilityMask || s.CapBnd != ZeroCapabilityMask || s.CapAmb != ZeroCapabilityMask {
		return fmt.Errorf("detector capabilities are CapEff=%s CapBnd=%s CapAmb=%s; expected all zero", s.CapEff, s.CapBnd, s.CapAmb)
	}
	if !s.NoNewPrivs {
		return fmt.Errorf("detector NoNewPrivs is disabled")
	}
	return nil
}

func ValidateEnforcer(s procinfo.Status) error {
	if s.UID == 0 {
		return fmt.Errorf("enforcer is running as root")
	}
	if s.CapEff != NetAdminOnlyMask || s.CapBnd != NetAdminOnlyMask || s.CapAmb != NetAdminOnlyMask {
		return fmt.Errorf("enforcer capabilities are CapEff=%s CapBnd=%s CapAmb=%s; expected only CAP_NET_ADMIN (%s)", s.CapEff, s.CapBnd, s.CapAmb, NetAdminOnlyMask)
	}
	if !s.NoNewPrivs {
		return fmt.Errorf("enforcer NoNewPrivs is disabled")
	}
	return nil
}
