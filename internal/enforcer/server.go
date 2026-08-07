// Package enforcer exposes the tiny privileged firewall mutation service used
// by split-mode GoBan deployments. The service accepts only one configured
// local Unix peer UID (plus root), and it never accepts arbitrary firewall
// expressions or shell commands.
package enforcer

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/sys/unix"

	"github.com/izm1chael/goban/internal/banner"
	"github.com/izm1chael/goban/internal/enforcerproto"
	"github.com/izm1chael/goban/internal/procinfo"
)

const (
	maxRequestBytes = 1 << 20
	maxPeerConns    = 32
)

type Server struct {
	backend      banner.Banner
	backendName  string
	socketPath   string
	allowedUser  string
	policy       *Policy
	policyLoader func() (*Policy, error)
	log          zerolog.Logger

	mu                sync.Mutex
	setupMu           sync.Mutex
	policyReloadMu    sync.Mutex
	backendMu         sync.Mutex
	policyMu          sync.RWMutex
	listener          net.Listener
	server            *http.Server
	ready             bool
	reconcileInterval time.Duration
	lastReconcile     time.Time
	lastRepair        time.Time
	repairCount       uint64
	lastRepairError   string
	reconcileCancel   context.CancelFunc
	reconcileWG       sync.WaitGroup
}

func New(backend banner.Banner, backendName, socketPath, allowedUser string, policy *Policy, log zerolog.Logger) *Server {
	return &Server{
		backend: backend, backendName: backendName, socketPath: socketPath,
		allowedUser: allowedUser, policy: policy, log: log.With().Str("component", "enforcer").Logger(),
	}
}

// SetPolicyLoader configures the helper-side policy reload callback. The callback
// must load and validate policy from privileged configuration; it never accepts
// allowlist material supplied by the unprivileged detector.
func (s *Server) SetPolicyLoader(loader func() (*Policy, error)) {
	s.policyLoader = loader
}

// SetReconcileInterval enables periodic, idempotent restoration of GoBan-owned
// firewall hooks. A zero interval disables background drift repair.
func (s *Server) SetReconcileInterval(interval time.Duration) {
	s.reconcileInterval = interval
}

func (s *Server) Start(ctx context.Context) error {
	uid, gid, err := lookupIdentity(s.allowedUser)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.socketPath), 0o755); err != nil {
		return fmt.Errorf("mkdir enforcer socket dir: %w", err)
	}
	_ = os.Remove(s.socketPath)
	base, err := net.ListenUnix("unix", &net.UnixAddr{Name: s.socketPath, Net: "unix"})
	if err != nil {
		return fmt.Errorf("listen unix %s: %w", s.socketPath, err)
	}
	// Keep ownership with the minimal enforcer identity. The detector reaches
	// the socket through its primary group; SO_PEERCRED still restricts the
	// actual protocol to the exact configured detector UID (plus root).
	if stat, err := os.Stat(s.socketPath); err != nil {
		_ = base.Close()
		_ = os.Remove(s.socketPath)
		return fmt.Errorf("stat enforcer socket: %w", err)
	} else if sys, ok := stat.Sys().(*syscall.Stat_t); !ok || int(sys.Gid) != gid {
		if err := os.Chown(s.socketPath, -1, gid); err != nil {
			_ = base.Close()
			_ = os.Remove(s.socketPath)
			return fmt.Errorf("set enforcer socket group for %s: %w", s.allowedUser, err)
		}
	}
	if err := os.Chmod(s.socketPath, 0o660); err != nil {
		_ = base.Close()
		_ = os.Remove(s.socketPath)
		return fmt.Errorf("chmod enforcer socket: %w", err)
	}

	listener := &peerListener{UnixListener: base, allowedUID: uint32(uid), log: s.log, sem: make(chan struct{}, maxPeerConns)}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", s.handleHealth)
	mux.HandleFunc("POST /v1/setup", s.handleSetup)
	mux.HandleFunc("POST /v1/reload-policy", s.handleReloadPolicy)
	mux.HandleFunc("POST /v1/ban-batch", s.handleBanBatch)
	mux.HandleFunc("POST /v1/unban", s.handleUnban)
	mux.HandleFunc("GET /v1/bans", s.handleBans)
	mux.HandleFunc("GET /v1/diagnostics", s.handleDiagnostics)
	mux.HandleFunc("POST /v1/close", s.handleClose)

	srv := &http.Server{
		Handler: mux, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 8 * time.Second,
		WriteTimeout: 12 * time.Second, IdleTimeout: 20 * time.Second, MaxHeaderBytes: 8 << 10,
	}
	s.mu.Lock()
	s.listener = listener
	s.server = srv
	s.mu.Unlock()
	go func() {
		if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log.Error().Err(err).Msg("enforcer server stopped")
		}
	}()
	s.log.Info().Str("socket", s.socketPath).Str("peer_user", s.allowedUser).Msg("privileged enforcer listening")
	if s.reconcileInterval > 0 {
		reconcileCtx, cancel := context.WithCancel(ctx)
		s.mu.Lock()
		s.reconcileCancel = cancel
		s.mu.Unlock()
		s.reconcileWG.Add(1)
		go func() {
			defer s.reconcileWG.Done()
			s.reconcileLoop(reconcileCtx)
		}()
	}
	return nil
}

func (s *Server) Stop(ctx context.Context) error {
	s.mu.Lock()
	srv := s.server
	cancel := s.reconcileCancel
	s.reconcileCancel = nil
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	s.reconcileWG.Wait()
	if srv != nil {
		if err := srv.Shutdown(ctx); err != nil {
			return err
		}
	}
	s.backendMu.Lock()
	_ = s.backend.Close(ctx, false)
	s.backendMu.Unlock()
	_ = os.Remove(s.socketPath)
	return nil
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	ready := s.ready
	s.mu.Unlock()
	s.policyMu.RLock()
	fingerprint := s.policy.Fingerprint()
	s.policyMu.RUnlock()
	proc, err := procinfo.ReadSelf()
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Errorf("read enforcer privilege state: %w", err))
		return
	}
	s.mu.Lock()
	lastReconcile, lastRepair, repairCount, lastRepairError := s.lastReconcile, s.lastRepair, s.repairCount, s.lastRepairError
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, enforcerproto.HealthResp{
		Protocol: enforcerproto.Version, Backend: s.backendName, Ready: ready, PolicyFingerprint: fingerprint,
		UID: proc.UID, GID: proc.GID, CapEff: proc.CapEff, CapBnd: proc.CapBnd, CapAmb: proc.CapAmb, NoNewPrivs: proc.NoNewPrivs,
		ReconcileInterval: s.reconcileInterval, LastReconcile: lastReconcile, LastRepair: lastRepair, RepairCount: repairCount, LastRepairError: lastRepairError,
	})
}

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	s.setupMu.Lock()
	defer s.setupMu.Unlock()
	if err := requireEmptyBody(r); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.backendMu.Lock()
	err := s.backend.Setup(r.Context())
	s.backendMu.Unlock()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.mu.Lock()
	s.ready = true
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) handleReloadPolicy(w http.ResponseWriter, r *http.Request) {
	s.policyReloadMu.Lock()
	defer s.policyReloadMu.Unlock()
	var req enforcerproto.ReloadPolicyRequest
	if err := decodeStrict(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if !validFingerprint(req.ExpectedFingerprint) {
		writeError(w, http.StatusBadRequest, fmt.Errorf("expected_fingerprint must be a 64-character SHA-256 hex digest"))
		return
	}
	if s.policyLoader == nil {
		writeError(w, http.StatusNotImplemented, fmt.Errorf("policy reload is not configured"))
		return
	}
	candidate, err := s.policyLoader()
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Errorf("reload privileged policy: %w", err))
		return
	}
	if candidate.Fingerprint() != req.ExpectedFingerprint {
		writeError(w, http.StatusConflict, fmt.Errorf("policy fingerprint mismatch: detector=%s enforcer=%s", req.ExpectedFingerprint, candidate.Fingerprint()))
		return
	}
	s.policyMu.Lock()
	s.policy = candidate
	s.policyMu.Unlock()
	writeJSON(w, http.StatusOK, enforcerproto.ReloadPolicyResp{Fingerprint: candidate.Fingerprint()})
}

func (s *Server) requireReady(w http.ResponseWriter) bool {
	s.mu.Lock()
	ready := s.ready
	s.mu.Unlock()
	if ready {
		return true
	}
	writeError(w, http.StatusServiceUnavailable, fmt.Errorf("enforcer not ready; setup required"))
	return false
}

func (s *Server) handleBanBatch(w http.ResponseWriter, r *http.Request) {
	var req enforcerproto.BanBatchRequest
	if err := decodeStrict(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if !s.requireReady(w) {
		return
	}
	if len(req.Bans) == 0 || len(req.Bans) > 4096 {
		writeError(w, http.StatusBadRequest, fmt.Errorf("bans must contain 1..4096 decisions"))
		return
	}
	out := make([]banner.BanRequest, 0, len(req.Bans))
	for i, item := range req.Bans {
		ip, err := netip.ParseAddr(item.IP)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("bans[%d].ip: %w", i, err))
			return
		}
		if !validRuleName(item.Rule) {
			writeError(w, http.StatusBadRequest, fmt.Errorf("bans[%d].rule must be a safe 1..128 byte identifier", i))
			return
		}
		if err := s.validateBan(ip, item.Rule); err != nil {
			writeError(w, http.StatusForbidden, fmt.Errorf("bans[%d]: %w", i, err))
			return
		}
		if item.TTL < time.Second || item.TTL/time.Second > time.Duration(^uint32(0)) {
			writeError(w, http.StatusBadRequest, fmt.Errorf("bans[%d].ttl outside kernel-safe range", i))
			return
		}
		out = append(out, banner.BanRequest{IP: ip, Rule: item.Rule, TTL: item.TTL})
	}
	s.backendMu.Lock()
	err := s.backend.BanBatch(r.Context(), out)
	s.backendMu.Unlock()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"applied": len(out)})
}

func (s *Server) handleUnban(w http.ResponseWriter, r *http.Request) {
	if !s.requireReady(w) {
		return
	}
	var req enforcerproto.UnbanRequest
	if err := decodeStrict(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	ip, err := netip.ParseAddr(req.IP)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid ip: %w", err))
		return
	}
	s.backendMu.Lock()
	err = s.backend.Unban(r.Context(), ip)
	s.backendMu.Unlock()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "unbanned"})
}

func (s *Server) handleBans(w http.ResponseWriter, r *http.Request) {
	if !s.requireReady(w) {
		return
	}
	s.backendMu.Lock()
	bans, err := s.backend.List(r.Context())
	s.backendMu.Unlock()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	out := make([]enforcerproto.BanInfo, 0, len(bans))
	for _, b := range bans {
		out = append(out, enforcerproto.BanInfo{IP: b.IP.String(), Rule: b.Rule, BannedAt: b.BannedAt, ExpiresAt: b.ExpiresAt, TTL: b.TTL})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleDiagnostics(w http.ResponseWriter, r *http.Request) {
	if !s.requireReady(w) {
		return
	}
	d, ok := s.backend.(banner.Diagnoser)
	if !ok {
		writeJSON(w, http.StatusOK, []enforcerproto.Diagnostic{{Name: "firewall hooks", Status: "skip", Detail: "backend does not expose diagnostics"}})
		return
	}
	s.backendMu.Lock()
	checks := d.Diagnostics(r.Context())
	s.backendMu.Unlock()
	out := make([]enforcerproto.Diagnostic, 0, len(checks))
	for _, c := range checks {
		out = append(out, enforcerproto.Diagnostic{Name: c.Name, Status: c.Status, Detail: c.Detail, Remediation: c.Remediation})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleClose(w http.ResponseWriter, r *http.Request) {
	var req enforcerproto.CloseRequest
	if err := decodeStrict(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	s.backendMu.Lock()
	err := s.backend.Close(r.Context(), req.Flush)
	s.backendMu.Unlock()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.mu.Lock()
	s.ready = false
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"status": "closed"})
}

func (s *Server) repairBackend(ctx context.Context) error {
	s.backendMu.Lock()
	defer s.backendMu.Unlock()
	if repairer, ok := s.backend.(banner.Reconciler); ok {
		return repairer.Repair(ctx)
	}
	return s.backend.Setup(ctx)
}

func (s *Server) reconcileLoop(ctx context.Context) {
	ticker := time.NewTicker(s.reconcileInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.reconcileOnce(ctx)
		}
	}
}

func (s *Server) reconcileOnce(parent context.Context) {
	s.mu.Lock()
	ready := s.ready
	s.mu.Unlock()
	if !ready {
		return
	}
	diagnoser, ok := s.backend.(banner.Diagnoser)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	s.backendMu.Lock()
	checks := diagnoser.Diagnostics(ctx)
	s.backendMu.Unlock()
	now := time.Now().UTC()
	drift := false
	for _, check := range checks {
		if check.Status == "fail" {
			drift = true
			break
		}
	}
	s.mu.Lock()
	s.lastReconcile = now
	if !drift {
		// A previous repair error is historical once diagnostics are healthy
		// again (for example after an operator restored the hook manually).
		s.lastRepairError = ""
	}
	s.mu.Unlock()
	if !drift {
		return
	}

	s.setupMu.Lock()
	err := s.repairBackend(ctx)
	s.setupMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		s.lastRepairError = err.Error()
		s.log.Error().Err(err).Msg("automatic firewall drift repair failed")
		return
	}
	s.lastRepair = time.Now().UTC()
	s.repairCount++
	s.lastRepairError = ""
	s.log.Warn().Uint64("repairs", s.repairCount).Msg("restored drifted GoBan firewall objects")
}

func decodeStrict(w http.ResponseWriter, r *http.Request, out any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("multiple JSON values are not allowed")
		}
		return fmt.Errorf("invalid trailing JSON: %w", err)
	}
	return nil
}

func requireEmptyBody(r *http.Request) error {
	if r.Body == nil {
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, 1))
	if err != nil {
		return err
	}
	if len(data) != 0 {
		return fmt.Errorf("request body must be empty")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, enforcerproto.ErrorResp{Error: err.Error()})
}

func (s *Server) validateBan(ip netip.Addr, rule string) error {
	s.policyMu.RLock()
	policy := s.policy
	defer s.policyMu.RUnlock()
	if policy == nil {
		return nil
	}
	return policy.ValidateBan(ip, rule)
}

func validFingerprint(value string) bool {
	if len(value) != sha256HexLen {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32
}

const sha256HexLen = 64

func validRuleName(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.' {
			continue
		}
		return false
	}
	return true
}

func lookupIdentity(name string) (int, int, error) {
	if name == "" {
		return 0, 0, fmt.Errorf("enforcer allowed user is empty")
	}
	u, err := user.Lookup(name)
	if err != nil {
		return 0, 0, fmt.Errorf("lookup enforcer user %q: %w", name, err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return 0, 0, fmt.Errorf("parse uid for enforcer user %q: %w", name, err)
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return 0, 0, fmt.Errorf("parse gid for enforcer user %q: %w", name, err)
	}
	return uid, gid, nil
}

type peerListener struct {
	*net.UnixListener
	allowedUID uint32
	log        zerolog.Logger
	sem        chan struct{}
}

type limitedConn struct {
	net.Conn
	once sync.Once
	sem  chan struct{}
}

func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { <-c.sem })
	return err
}

func (l *peerListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.AcceptUnix()
		if err != nil {
			return nil, err
		}
		cred, err := peerCredential(conn)
		if err != nil {
			_ = conn.Close()
			l.log.Warn().Err(err).Msg("rejected enforcer peer without credentials")
			continue
		}
		if cred.Uid != 0 && cred.Uid != l.allowedUID {
			_ = conn.Close()
			l.log.Warn().Uint32("uid", cred.Uid).Int("pid", int(cred.Pid)).Msg("rejected unauthorized enforcer peer")
			continue
		}
		l.sem <- struct{}{}
		return &limitedConn{Conn: conn, sem: l.sem}, nil
	}
}

func peerCredential(conn *net.UnixConn) (*unix.Ucred, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return nil, err
	}
	var cred *unix.Ucred
	var sockErr error
	err = raw.Control(func(fd uintptr) {
		cred, sockErr = unix.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if err != nil {
		return nil, err
	}
	return cred, sockErr
}
