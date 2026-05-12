package allowlist

import (
	"net/netip"
	"testing"
)

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse %s: %v", s, err)
	}
	return a
}

func TestNew_RejectsBadCIDR(t *testing.T) {
	if _, err := New([]string{"not-a-cidr"}); err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

func TestPermit(t *testing.T) {
	a, err := New([]string{
		"127.0.0.0/8",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"::1/128",
		"fc00::/7",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	cases := map[string]struct {
		ip   string
		want bool
	}{
		"loopback_v4":    {"127.0.0.1", true},
		"loopback_v6":    {"::1", true},
		"rfc1918_10":     {"10.5.6.7", true},
		"rfc1918_172_16": {"172.16.0.1", true},
		"rfc1918_172_32": {"172.32.0.1", false},
		"rfc1918_192":    {"192.168.1.1", true},
		"public_v4":      {"8.8.8.8", false},
		"ula_v6":         {"fd00::1", true},
		"public_v6":      {"2001:db8::1", false},
		"v4_mapped":      {"::ffff:127.0.0.1", true},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := a.Permit(mustAddr(t, tc.ip))
			if got != tc.want {
				t.Errorf("Permit(%s) = %v, want %v", tc.ip, got, tc.want)
			}
		})
	}
}

func TestAddLocalInterfaces(t *testing.T) {
	a, err := New(nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := a.AddLocalInterfaces(); err != nil {
		t.Fatalf("AddLocalInterfaces: %v", err)
	}
	// Loopback should always be present on a sane host.
	if !a.Permit(mustAddr(t, "127.0.0.1")) {
		t.Error("loopback v4 not allowlisted after AddLocalInterfaces")
	}
}
