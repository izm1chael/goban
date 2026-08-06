package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

// State is the read-only view of the daemon that the control server exposes.
type State interface {
	Status() StatusResp
	Rules() []RuleInfo
	Sources() []SourceInfo
	Banned(ctx context.Context) ([]BanInfo, error)
	Unban(ctx context.Context, ip netip.Addr) error
	BanManual(ctx context.Context, ip netip.Addr, rule string, ttl time.Duration) error
	// Reload re-reads config from disk and applies the diff atomically.
	// On any failure the running daemon is unchanged and the error is
	// returned for the operator to see.
	Reload(ctx context.Context) error
}

// Server is the unix-socket HTTP server.
type Server struct {
	state       State
	socketPath  string
	socketMode  os.FileMode
	log         zerolog.Logger
	audit       *Audit // optional; nil disables audit logging
	socketGroup string

	mu       sync.Mutex
	listener net.Listener
	server   *http.Server
}

// New constructs a Server. The socket file is created on Start. audit may be
// nil; when non-nil, successful /ban and /unban requests append a JSON line
// to the audit log.
func New(state State, socketPath string, socketMode os.FileMode, log zerolog.Logger, audit *Audit, socketGroup ...string) *Server {
	group := ""
	if len(socketGroup) > 0 {
		group = socketGroup[0]
	}
	return &Server{
		state:       state,
		socketPath:  socketPath,
		socketMode:  socketMode,
		log:         log.With().Str("component", "control").Logger(),
		audit:       audit,
		socketGroup: group,
	}
}

// Start listens on the unix socket and serves HTTP in a goroutine.
func (s *Server) Start(_ context.Context) error {
	if err := os.MkdirAll(filepath.Dir(s.socketPath), 0o755); err != nil {
		return fmt.Errorf("mkdir socket dir: %w", err)
	}
	// Remove any leftover socket from a previous unclean shutdown.
	_ = os.Remove(s.socketPath)

	l, err := net.Listen("unix", s.socketPath)
	if err != nil {
		return fmt.Errorf("listen unix %s: %w", s.socketPath, err)
	}
	if err := os.Chmod(s.socketPath, s.socketMode); err != nil {
		_ = l.Close()
		return fmt.Errorf("chmod socket: %w", err)
	}
	if s.socketGroup != "" {
		grp, err := user.LookupGroup(s.socketGroup)
		if err != nil {
			_ = l.Close()
			_ = os.Remove(s.socketPath)
			return fmt.Errorf("lookup socket group %q: %w", s.socketGroup, err)
		}
		gid, err := strconv.Atoi(grp.Gid)
		if err != nil {
			_ = l.Close()
			_ = os.Remove(s.socketPath)
			return fmt.Errorf("parse gid for socket group %q: %w", s.socketGroup, err)
		}
		if err := os.Chown(s.socketPath, -1, gid); err != nil {
			_ = l.Close()
			_ = os.Remove(s.socketPath)
			return fmt.Errorf("chown socket group %q: %w", s.socketGroup, err)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", s.handleStatus)
	mux.HandleFunc("GET /rules", s.handleRules)
	mux.HandleFunc("GET /sources", s.handleSources)
	mux.HandleFunc("GET /banned", s.handleBanned)
	mux.HandleFunc("POST /unban", s.handleUnban)
	mux.HandleFunc("POST /ban", s.handleBan)
	mux.HandleFunc("POST /reload", s.handleReload)

	s.mu.Lock()
	s.listener = l
	s.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	srv := s.server
	s.mu.Unlock()

	go func() {
		if err := srv.Serve(l); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log.Error().Err(err).Msg("control server stopped")
		}
	}()
	s.log.Info().Str("socket", s.socketPath).Msg("control server listening")
	return nil
}

// Stop shuts the server down, closes the listener and removes the socket file.
func (s *Server) Stop(ctx context.Context) error {
	s.mu.Lock()
	srv := s.server
	s.mu.Unlock()
	if srv != nil {
		if err := srv.Shutdown(ctx); err != nil {
			return err
		}
	}
	_ = os.Remove(s.socketPath)
	return nil
}

func (s *Server) handleStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.state.Status())
}

func (s *Server) handleRules(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.state.Rules())
}

func (s *Server) handleSources(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, s.state.Sources())
}

func (s *Server) handleBanned(w http.ResponseWriter, r *http.Request) {
	bans, err := s.state.Banned(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, bans)
}

func (s *Server) handleUnban(w http.ResponseWriter, r *http.Request) {
	var req UnbanReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid JSON: %w", err))
		return
	}
	addr, err := netip.ParseAddr(req.IP)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid IP: %w", err))
		return
	}
	if err := s.state.Unban(r.Context(), addr); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if s.audit != nil {
		if err := s.audit.Log(AuditEvent{Action: "unban", IP: addr.String(), Source: "manual"}); err != nil {
			s.log.Error().Err(err).Msg("unban applied but audit write failed")
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "unbanned", "ip": addr.String()})
}

func (s *Server) handleBan(w http.ResponseWriter, r *http.Request) {
	var req BanReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid JSON: %w", err))
		return
	}
	addr, err := netip.ParseAddr(req.IP)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid IP: %w", err))
		return
	}
	if req.Rule == "" {
		writeError(w, http.StatusBadRequest, errors.New("rule is required (use 'manual' to be explicit)"))
		return
	}
	if req.TTL < time.Second {
		writeError(w, http.StatusBadRequest, errors.New("ttl must be at least 1s"))
		return
	}
	if req.TTL/time.Second > time.Duration(^uint32(0)) {
		writeError(w, http.StatusBadRequest, errors.New("ttl exceeds kernel timeout maximum"))
		return
	}
	if err := s.state.BanManual(r.Context(), addr, req.Rule, req.TTL); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if s.audit != nil {
		if err := s.audit.Log(AuditEvent{Action: "ban", IP: addr.String(), Rule: req.Rule, TTL: req.TTL.String(), Source: "manual"}); err != nil {
			s.log.Error().Err(err).Msg("manual ban applied but audit write failed")
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "banned", "ip": addr.String(), "rule": req.Rule})
}

func (s *Server) handleReload(w http.ResponseWriter, r *http.Request) {
	if err := s.state.Reload(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "reloaded"})
}

func writeJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, ErrorResp{Error: err.Error()})
}
