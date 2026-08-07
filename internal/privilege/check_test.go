package privilege

import (
	"testing"

	"github.com/izm1chael/goban/internal/procinfo"
)

func TestPrivilegeInvariants(t *testing.T) {
	detector := procinfo.Status{UID: 100, CapEff: ZeroCapabilityMask, CapBnd: ZeroCapabilityMask, CapAmb: ZeroCapabilityMask, NoNewPrivs: true}
	if err := ValidateDetector(detector); err != nil {
		t.Fatalf("valid detector rejected: %v", err)
	}
	detector.CapBnd = NetAdminOnlyMask
	if err := ValidateDetector(detector); err == nil {
		t.Fatal("detector with bounded capability accepted")
	}

	enforcer := procinfo.Status{UID: 101, CapEff: NetAdminOnlyMask, CapBnd: NetAdminOnlyMask, CapAmb: NetAdminOnlyMask, NoNewPrivs: true}
	if err := ValidateEnforcer(enforcer); err != nil {
		t.Fatalf("valid enforcer rejected: %v", err)
	}
	enforcer.UID = 0
	if err := ValidateEnforcer(enforcer); err == nil {
		t.Fatal("root enforcer accepted")
	}
}
