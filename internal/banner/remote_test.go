package banner

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/izm1chael/goban/internal/enforcerproto"
)

func TestRemoteBannerRoundTrip(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "enforcer.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	defer os.Remove(sock)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/setup", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ready"})
	})
	mux.HandleFunc("POST /v1/ban-batch", func(w http.ResponseWriter, r *http.Request) {
		var req enforcerproto.BanBatchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(map[string]int{"applied": len(req.Bans)})
	})
	mux.HandleFunc("GET /v1/bans", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode([]enforcerproto.BanInfo{{IP: "192.0.2.44", Rule: "sshd", TTL: time.Minute}})
	})
	mux.HandleFunc("POST /v1/unban", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "unbanned"})
	})
	mux.HandleFunc("POST /v1/close", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "closed"})
	})
	mux.HandleFunc("GET /v1/health", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(enforcerproto.HealthResp{Protocol: 1, Backend: "nftables", Ready: true, UID: 123, GID: 123, CapEff: "0000000000001000", CapBnd: "0000000000001000", CapAmb: "0000000000001000", NoNewPrivs: true})
	})
	mux.HandleFunc("GET /v1/diagnostics", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode([]enforcerproto.Diagnostic{{Name: "hook", Status: "pass", Detail: "ok"}})
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	defer srv.Shutdown(context.Background())

	b := NewRemote(sock)
	ctx := context.Background()
	if err := b.Setup(ctx); err != nil {
		t.Fatal(err)
	}
	if err := b.Ban(ctx, netip.MustParseAddr("192.0.2.44"), "sshd", time.Minute); err != nil {
		t.Fatal(err)
	}
	list, err := b.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Rule != "sshd" {
		t.Fatalf("unexpected list: %#v", list)
	}
	checks := b.Diagnostics(ctx)
	if len(checks) != 4 || checks[0].Status != "pass" || checks[1].Status != "warn" || checks[2].Status != "pass" || checks[3].Status != "pass" {
		t.Fatalf("unexpected diagnostics: %#v", checks)
	}
	if err := b.Unban(ctx, netip.MustParseAddr("192.0.2.44")); err != nil {
		t.Fatal(err)
	}
	if err := b.Close(ctx, false); err != nil {
		t.Fatal(err)
	}
}

func TestRemoteRejectsProtocolAndBackendMismatch(t *testing.T) {
	tests := []struct {
		name     string
		protocol int
		backend  string
		expected string
	}{
		{name: "protocol", protocol: enforcerproto.Version + 1, backend: "nftables", expected: "nftables"},
		{name: "backend", protocol: enforcerproto.Version, backend: "iptables", expected: "nftables"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			sock := filepath.Join(dir, "enforcer.sock")
			ln, err := net.Listen("unix", sock)
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			mux := http.NewServeMux()
			mux.HandleFunc("GET /v1/health", func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(enforcerproto.HealthResp{Protocol: tc.protocol, Backend: tc.backend, Ready: true})
			})
			srv := &http.Server{Handler: mux}
			go srv.Serve(ln)
			defer srv.Shutdown(context.Background())

			if err := NewRemote(sock, tc.expected).Setup(context.Background()); err == nil {
				t.Fatal("expected compatibility mismatch")
			}
		})
	}
}
