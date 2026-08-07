package banner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/izm1chael/goban/internal/enforcerproto"
	"github.com/izm1chael/goban/internal/privilege"
	"github.com/izm1chael/goban/internal/procinfo"
)

// Remote is a Banner implementation backed by the privileged goban-enforcer
// process over an authenticated local Unix socket. The detector never sends
// raw firewall expressions; only typed ban/unban/list operations exist.
type Remote struct {
	socketPath      string
	expectedBackend string
	client          *http.Client

	mu             sync.RWMutex
	expectedPolicy string
}

const maxRemoteResponseBytes = 32 << 20

type remoteStatusError struct {
	code int
	err  error
}

func (e *remoteStatusError) Error() string { return e.err.Error() }
func (e *remoteStatusError) Unwrap() error { return e.err }

func NewRemote(socketPath string, expectedBackend ...string) *Remote {
	transport := &http.Transport{
		DisableCompression: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socketPath)
		},
	}
	expected := ""
	if len(expectedBackend) > 0 {
		expected = expectedBackend[0]
	}
	return &Remote{
		socketPath:      socketPath,
		expectedBackend: expected,
		client:          &http.Client{Transport: transport, Timeout: 12 * time.Second},
	}
}

func (r *Remote) SetExpectedPolicyFingerprint(fingerprint string) {
	r.mu.Lock()
	r.expectedPolicy = fingerprint
	r.mu.Unlock()
}

func (r *Remote) ReloadPolicy(ctx context.Context, expectedFingerprint string) error {
	var out enforcerproto.ReloadPolicyResp
	if err := r.do(ctx, http.MethodPost, "/v1/reload-policy", enforcerproto.ReloadPolicyRequest{ExpectedFingerprint: expectedFingerprint}, &out); err != nil {
		return fmt.Errorf("enforcer policy reload: %w", err)
	}
	if out.Fingerprint != expectedFingerprint {
		return fmt.Errorf("enforcer policy reload acknowledged fingerprint %s, expected %s", out.Fingerprint, expectedFingerprint)
	}
	r.SetExpectedPolicyFingerprint(expectedFingerprint)
	return nil
}

func (r *Remote) Setup(ctx context.Context) error {
	if _, err := r.health(ctx); err != nil {
		return fmt.Errorf("enforcer compatibility: %w", err)
	}
	var out map[string]string
	if err := r.do(ctx, http.MethodPost, "/v1/setup", nil, &out); err != nil {
		return fmt.Errorf("enforcer setup: %w", err)
	}
	return nil
}

func (r *Remote) Ban(ctx context.Context, ip netip.Addr, rule string, ttl time.Duration) error {
	return r.BanBatch(ctx, []BanRequest{{IP: ip, Rule: rule, TTL: ttl}})
}

func (r *Remote) BanBatch(ctx context.Context, reqs []BanRequest) error {
	if len(reqs) == 0 {
		return nil
	}
	wire := enforcerproto.BanBatchRequest{Bans: make([]enforcerproto.BanRequest, 0, len(reqs))}
	for _, req := range reqs {
		if !req.IP.IsValid() || req.IP.IsUnspecified() {
			return fmt.Errorf("invalid ban ip %q", req.IP)
		}
		if err := validateTTL(req.TTL); err != nil {
			return err
		}
		wire.Bans = append(wire.Bans, enforcerproto.BanRequest{IP: req.IP.String(), Rule: req.Rule, TTL: req.TTL})
	}
	var out map[string]int
	if err := r.doReady(ctx, http.MethodPost, "/v1/ban-batch", wire, &out); err != nil {
		return fmt.Errorf("enforcer ban batch: %w", err)
	}
	if out["applied"] != len(reqs) {
		return fmt.Errorf("enforcer acknowledged %d of %d bans", out["applied"], len(reqs))
	}
	return nil
}

func (r *Remote) Unban(ctx context.Context, ip netip.Addr) error {
	if !ip.IsValid() || ip.IsUnspecified() {
		return fmt.Errorf("invalid unban ip %q", ip)
	}
	var out map[string]string
	if err := r.doReady(ctx, http.MethodPost, "/v1/unban", enforcerproto.UnbanRequest{IP: ip.String()}, &out); err != nil {
		return fmt.Errorf("enforcer unban: %w", err)
	}
	return nil
}

func (r *Remote) List(ctx context.Context) ([]BanInfo, error) {
	var wire []enforcerproto.BanInfo
	if err := r.doReady(ctx, http.MethodGet, "/v1/bans", nil, &wire); err != nil {
		return nil, fmt.Errorf("enforcer list: %w", err)
	}
	out := make([]BanInfo, 0, len(wire))
	for _, item := range wire {
		ip, err := netip.ParseAddr(item.IP)
		if err != nil {
			return nil, fmt.Errorf("enforcer returned invalid ip %q: %w", item.IP, err)
		}
		out = append(out, BanInfo{IP: ip, Rule: item.Rule, BannedAt: item.BannedAt, ExpiresAt: item.ExpiresAt, TTL: item.TTL})
	}
	return out, nil
}

func (r *Remote) Diagnostics(ctx context.Context) []Diagnostic {
	health, err := r.health(ctx)
	if err != nil {
		return []Diagnostic{{
			Name: "privileged enforcer", Status: "fail", Detail: err.Error(),
			Remediation: "check goban-enforcer.service and /run/goban-enforcer/enforcer.sock",
		}}
	}
	out := []Diagnostic{{Name: "privileged enforcer", Status: "pass", Detail: fmt.Sprintf("protocol v%d connected to %s backend", health.Protocol, health.Backend)}}
	helperState := procinfo.Status{UID: health.UID, GID: health.GID, CapEff: health.CapEff, CapBnd: health.CapBnd, CapAmb: health.CapAmb, NoNewPrivs: health.NoNewPrivs}
	if err := privilege.ValidateEnforcer(helperState); err != nil {
		out = append(out, Diagnostic{
			Name: "enforcer privilege boundary", Status: "fail",
			Detail:      fmt.Sprintf("uid=%d gid=%d CapEff=%s CapBnd=%s CapAmb=%s NoNewPrivs=%t: %v", health.UID, health.GID, health.CapEff, health.CapBnd, health.CapAmb, health.NoNewPrivs, err),
			Remediation: "use the packaged goban-enforcer.service; do not run the helper as root or grant additional capabilities",
		})
	} else {
		out = append(out, Diagnostic{Name: "enforcer privilege boundary", Status: "pass", Detail: fmt.Sprintf("uid=%d with only CAP_NET_ADMIN and NoNewPrivileges", health.UID)})
	}

	if !health.Ready {
		if err := r.Setup(ctx); err != nil {
			out[0] = Diagnostic{Name: "privileged enforcer", Status: "fail", Detail: "enforcer restarted and automatic setup failed: " + err.Error(), Remediation: "inspect goban-enforcer.service and firewall backend availability"}
			return out
		}
		out[0].Detail += "; recovered helper restart with idempotent setup"
	}
	var checks []enforcerproto.Diagnostic
	if err := r.doReady(ctx, http.MethodGet, "/v1/diagnostics", nil, &checks); err != nil {
		return append(out, Diagnostic{Name: "enforcer diagnostics", Status: "fail", Detail: err.Error(), Remediation: "inspect goban-enforcer.service"})
	}
	for _, c := range checks {
		out = append(out, Diagnostic{Name: c.Name, Status: c.Status, Detail: c.Detail, Remediation: c.Remediation})
	}
	return out
}

func (r *Remote) health(ctx context.Context) (*enforcerproto.HealthResp, error) {
	var health enforcerproto.HealthResp
	if err := r.do(ctx, http.MethodGet, "/v1/health", nil, &health); err != nil {
		return nil, err
	}
	if health.Protocol != enforcerproto.Version {
		return nil, fmt.Errorf("protocol mismatch: daemon=%d enforcer=%d; restart both GoBan services from the same package version", enforcerproto.Version, health.Protocol)
	}
	if r.expectedBackend != "" && health.Backend != r.expectedBackend {
		return nil, fmt.Errorf("backend mismatch: daemon expects %s, enforcer reports %s; restart both services with the same configuration", r.expectedBackend, health.Backend)
	}
	r.mu.RLock()
	expectedPolicy := r.expectedPolicy
	r.mu.RUnlock()
	if expectedPolicy != "" && health.PolicyFingerprint != expectedPolicy {
		return nil, fmt.Errorf("enforcement-policy mismatch: daemon=%s enforcer=%s; reload/restart both services from the same configuration", expectedPolicy, health.PolicyFingerprint)
	}
	return &health, nil
}

func (r *Remote) Close(ctx context.Context, flush bool) error {
	var out map[string]string
	if err := r.do(ctx, http.MethodPost, "/v1/close", enforcerproto.CloseRequest{Flush: flush}, &out); err != nil {
		return fmt.Errorf("enforcer close: %w", err)
	}
	return nil
}

func (r *Remote) doReady(ctx context.Context, method, path string, body, out any) error {
	err := r.do(ctx, method, path, body, out)
	var statusErr *remoteStatusError
	if !errors.As(err, &statusErr) || statusErr.code != http.StatusServiceUnavailable {
		return err
	}
	if setupErr := r.Setup(ctx); setupErr != nil {
		return fmt.Errorf("recover enforcer readiness after %v: %w", err, setupErr)
	}
	return r.do(ctx, method, path, body, out)
}

func (r *Remote) do(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://goban-enforcer"+path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("connect %s: %w", r.socketPath, err)
	}
	defer resp.Body.Close()
	limited := io.LimitReader(resp.Body, maxRemoteResponseBytes)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var er enforcerproto.ErrorResp
		if err := json.NewDecoder(limited).Decode(&er); err == nil && er.Error != "" {
			return &remoteStatusError{code: resp.StatusCode, err: errors.New(er.Error)}
		}
		return &remoteStatusError{code: resp.StatusCode, err: fmt.Errorf("enforcer HTTP %s", resp.Status)}
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(limited).Decode(out); err != nil {
		return fmt.Errorf("decode enforcer response: %w", err)
	}
	return nil
}
