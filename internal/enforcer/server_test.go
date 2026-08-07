package enforcer

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"os/user"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/izm1chael/goban/internal/banner"
	"github.com/izm1chael/goban/internal/config"
	"github.com/izm1chael/goban/internal/enforcerproto"
)

func TestServerAcceptsCurrentUIDAndTypedDecisions(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(t.TempDir(), "enforcer.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := New(banner.NewNoop(), "noop", sock, current.Username, nil, zerolog.Nop())
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Stop(context.Background())

	client := unixHTTPClient(sock)
	postJSON(t, client, "/v1/setup", nil, http.StatusOK)
	postJSON(t, client, "/v1/ban-batch", enforcerproto.BanBatchRequest{Bans: []enforcerproto.BanRequest{{IP: "192.0.2.9", Rule: "sshd", TTL: time.Minute}}}, http.StatusOK)

	resp, err := client.Get("http://enforcer/v1/bans")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var bans []enforcerproto.BanInfo
	if err := json.NewDecoder(resp.Body).Decode(&bans); err != nil {
		t.Fatal(err)
	}
	if len(bans) != 1 || bans[0].IP != "192.0.2.9" {
		t.Fatalf("unexpected bans: %#v", bans)
	}

	postJSON(t, client, "/v1/unban", enforcerproto.UnbanRequest{IP: "192.0.2.9"}, http.StatusOK)
}

func TestServerRejectsUnknownJSONFields(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(t.TempDir(), "enforcer.sock")
	s := New(banner.NewNoop(), "noop", sock, current.Username, nil, zerolog.Nop())
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer s.Stop(context.Background())
	client := unixHTTPClient(sock)
	postJSONRaw(t, client, "/v1/ban-batch", []byte(`{"bans":[],"command":"nft flush ruleset"}`), http.StatusBadRequest)
}

func unixHTTPClient(sock string) *http.Client {
	return &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", sock)
	}}}
}

func postJSON(t *testing.T, c *http.Client, path string, body any, want int) {
	t.Helper()
	var data []byte
	if body != nil {
		data, _ = json.Marshal(body)
	}
	postJSONRaw(t, c, path, data, want)
}
func postJSONRaw(t *testing.T, c *http.Client, path string, data []byte, want int) {
	t.Helper()
	resp, err := c.Post("http://enforcer"+path, "application/json", bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != want {
		t.Fatalf("status=%d want=%d", resp.StatusCode, want)
	}
}

func TestNoopBackendSanity(t *testing.T) {
	b := banner.NewNoop()
	if err := b.Ban(context.Background(), netip.MustParseAddr("198.51.100.8"), "x", time.Minute); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyRejectsProtectedAddresses(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Allowlist = []string{"198.51.100.0/24"}
	cfg.Rules = []config.RuleConfig{{Name: "admin", Allowlist: []string{"203.0.113.0/24"}}}
	p, err := NewPolicy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ ip, rule string }{{"127.0.0.1", "manual"}, {"198.51.100.9", "manual"}, {"203.0.113.9", "admin"}, {"224.0.0.1", "manual"}} {
		if err := p.ValidateBan(netip.MustParseAddr(tc.ip), tc.rule); err == nil {
			t.Fatalf("expected %s/%s to be rejected", tc.ip, tc.rule)
		}
	}
	if err := p.ValidateBan(netip.MustParseAddr("192.0.2.55"), "manual"); err != nil {
		t.Fatalf("public test address rejected: %v", err)
	}
}

func TestRemoteRecoversFreshEnforcerWithoutDaemonRestart(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(t.TempDir(), "enforcer.sock")
	s := New(banner.NewNoop(), "noop", sock, current.Username, nil, zerolog.Nop())
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer s.Stop(context.Background())

	remote := banner.NewRemote(sock)
	// Deliberately do not call remote.Setup. The first typed operation should
	// observe HTTP 503, set the helper up idempotently, and retry once.
	if err := remote.Ban(context.Background(), netip.MustParseAddr("192.0.2.77"), "sshd", time.Minute); err != nil {
		t.Fatalf("automatic readiness recovery failed: %v", err)
	}
	bans, err := remote.List(context.Background())
	if err != nil || len(bans) != 1 {
		t.Fatalf("list after recovery: bans=%#v err=%v", bans, err)
	}
}

func TestCloseMarksEnforcerUnready(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(t.TempDir(), "enforcer.sock")
	s := New(banner.NewNoop(), "noop", sock, current.Username, nil, zerolog.Nop())
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer s.Stop(context.Background())
	client := unixHTTPClient(sock)
	postJSON(t, client, "/v1/setup", nil, http.StatusOK)
	postJSON(t, client, "/v1/close", enforcerproto.CloseRequest{Flush: false}, http.StatusOK)

	resp, err := client.Get("http://enforcer/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var health enforcerproto.HealthResp
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		t.Fatal(err)
	}
	if health.Ready {
		t.Fatal("closed backend must be reported unready")
	}
}

func TestPolicyReloadVerifiesFingerprintBeforeSwap(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	oldCfg := config.DefaultConfig()
	oldCfg.Allowlist = []string{"198.51.100.0/24"}
	oldPolicy, err := NewPolicy(oldCfg)
	if err != nil {
		t.Fatal(err)
	}
	newCfg := config.DefaultConfig()
	newCfg.Allowlist = []string{"203.0.113.0/24"}
	newPolicy, err := NewPolicy(newCfg)
	if err != nil {
		t.Fatal(err)
	}

	sock := filepath.Join(t.TempDir(), "enforcer.sock")
	s := New(banner.NewNoop(), "noop", sock, current.Username, oldPolicy, zerolog.Nop())
	s.SetPolicyLoader(func() (*Policy, error) { return newPolicy, nil })
	if err := s.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer s.Stop(context.Background())
	client := unixHTTPClient(sock)

	postJSON(t, client, "/v1/reload-policy", enforcerproto.ReloadPolicyRequest{ExpectedFingerprint: oldPolicy.Fingerprint()}, http.StatusConflict)
	postJSON(t, client, "/v1/reload-policy", enforcerproto.ReloadPolicyRequest{ExpectedFingerprint: newPolicy.Fingerprint()}, http.StatusOK)

	resp, err := client.Get("http://enforcer/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var health enforcerproto.HealthResp
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		t.Fatal(err)
	}
	if health.PolicyFingerprint != newPolicy.Fingerprint() {
		t.Fatalf("policy fingerprint=%s want=%s", health.PolicyFingerprint, newPolicy.Fingerprint())
	}
}
