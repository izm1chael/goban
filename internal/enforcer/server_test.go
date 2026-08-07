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
	"sync"
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

type driftBanner struct {
	inner   *banner.NoopBanner
	mu      sync.Mutex
	drift   bool
	repairs int
}

func newDriftBanner() *driftBanner                     { return &driftBanner{inner: banner.NewNoop()} }
func (d *driftBanner) Setup(ctx context.Context) error { return d.inner.Setup(ctx) }
func (d *driftBanner) Ban(ctx context.Context, ip netip.Addr, rule string, ttl time.Duration) error {
	return d.inner.Ban(ctx, ip, rule, ttl)
}
func (d *driftBanner) BanBatch(ctx context.Context, reqs []banner.BanRequest) error {
	return d.inner.BanBatch(ctx, reqs)
}
func (d *driftBanner) Unban(ctx context.Context, ip netip.Addr) error     { return d.inner.Unban(ctx, ip) }
func (d *driftBanner) List(ctx context.Context) ([]banner.BanInfo, error) { return d.inner.List(ctx) }
func (d *driftBanner) Close(ctx context.Context, flush bool) error        { return d.inner.Close(ctx, flush) }
func (d *driftBanner) Diagnostics(context.Context) []banner.Diagnostic {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.drift {
		return []banner.Diagnostic{{Name: "hook", Status: "fail", Detail: "injected drift"}}
	}
	return []banner.Diagnostic{{Name: "hook", Status: "pass", Detail: "ok"}}
}
func (d *driftBanner) Repair(context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.repairs++
	d.drift = false
	return nil
}

func TestServerAutomaticallyRepairsDetectedFirewallDrift(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	b := newDriftBanner()
	sock := filepath.Join(t.TempDir(), "enforcer.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := New(b, "test", sock, current.Username, nil, zerolog.Nop())
	s.SetReconcileInterval(20 * time.Millisecond)
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Stop(context.Background())
	client := unixHTTPClient(sock)
	postJSON(t, client, "/v1/setup", nil, http.StatusOK)
	b.mu.Lock()
	b.drift = true
	b.mu.Unlock()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		b.mu.Lock()
		repaired := b.repairs > 0 && !b.drift
		b.mu.Unlock()
		if repaired {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	b.mu.Lock()
	repairs, drift := b.repairs, b.drift
	b.mu.Unlock()
	if repairs != 1 || drift {
		t.Fatalf("repairs=%d drift=%t, want one successful repair", repairs, drift)
	}
	resp, err := client.Get("http://enforcer/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var health enforcerproto.HealthResp
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		t.Fatal(err)
	}
	if health.RepairCount != 1 || health.LastRepair.IsZero() || health.LastReconcile.IsZero() {
		t.Fatalf("unexpected reconcile health: %+v", health)
	}
}

type blockingDiagnosticBanner struct {
	*banner.NoopBanner
	entered sync.Once
	seen    chan struct{}
	mu      sync.Mutex
	closed  bool
}

func newBlockingDiagnosticBanner() *blockingDiagnosticBanner {
	return &blockingDiagnosticBanner{NoopBanner: banner.NewNoop(), seen: make(chan struct{})}
}

func (b *blockingDiagnosticBanner) Diagnostics(ctx context.Context) []banner.Diagnostic {
	b.entered.Do(func() { close(b.seen) })
	<-ctx.Done()
	return []banner.Diagnostic{{Name: "hook", Status: "pass", Detail: "cancelled"}}
}

func (b *blockingDiagnosticBanner) Repair(context.Context) error { return nil }

func (b *blockingDiagnosticBanner) Close(ctx context.Context, flush bool) error {
	b.mu.Lock()
	b.closed = true
	b.mu.Unlock()
	return b.NoopBanner.Close(ctx, flush)
}

func TestServerStopWaitsForReconcileLoopBeforeBackendClose(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	b := newBlockingDiagnosticBanner()
	sock := filepath.Join(t.TempDir(), "enforcer.sock")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := New(b, "test", sock, current.Username, nil, zerolog.Nop())
	s.SetReconcileInterval(time.Millisecond)
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	client := unixHTTPClient(sock)
	postJSON(t, client, "/v1/setup", nil, http.StatusOK)
	select {
	case <-b.seen:
	case <-time.After(time.Second):
		t.Fatal("reconcile diagnostics did not start")
	}
	stopCtx, stopCancel := context.WithTimeout(context.Background(), time.Second)
	defer stopCancel()
	if err := s.Stop(stopCtx); err != nil {
		t.Fatalf("stop: %v", err)
	}
	b.mu.Lock()
	closed := b.closed
	b.mu.Unlock()
	if !closed {
		t.Fatal("backend was not closed after reconcile loop drained")
	}
}
