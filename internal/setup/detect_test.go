package setup

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectFixtureRoot(t *testing.T) {
	root := t.TempDir()
	mustWrite := func(path, data string) {
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite("etc/os-release", "ID=ubuntu\nVERSION_ID=26.04\n")
	mustWrite("var/log/auth.log", "")
	mustWrite("var/log/nginx/access.log", "")
	mustWrite("proc/net/if_inet6", "")
	mustWrite("usr/sbin/nft", "")
	plan, err := Detect(root)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Facts.Distribution != "ubuntu" || !plan.Facts.NFTables || !plan.Facts.IPv6 {
		t.Fatalf("unexpected facts: %#v", plan.Facts)
	}
	if !plan.Config.DryRun || plan.Config.Banner.Backend != "nftables" {
		t.Fatalf("unsafe proposal: %#v", plan.Config)
	}
	if len(plan.EnabledBundles) < 2 {
		t.Fatalf("expected detected bundles: %#v", plan.EnabledBundles)
	}
}

func TestDetectIPTablesDoesNotRequireIPSetUserspaceBinary(t *testing.T) {
	root := t.TempDir()
	mustWrite := func(path, data string) {
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(data), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite("etc/os-release", "ID=debian\nVERSION_ID=13\n")
	mustWrite("var/log/auth.log", "")
	mustWrite("usr/sbin/iptables", "")
	plan, err := Detect(root)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Facts.IPTables || plan.Facts.IPSet {
		t.Fatalf("unexpected firewall facts: %#v", plan.Facts)
	}
	if plan.Config.Banner.Backend != "iptables" {
		t.Fatalf("backend=%q, want iptables", plan.Config.Banner.Backend)
	}
}
