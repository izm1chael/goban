package control

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

type fakeState struct {
	mu          sync.Mutex
	banned      []BanInfo
	rules       []RuleInfo
	manualErr   error
	manualCount int
	unbanCount  int
	reloadErr   error
	reloadCount int
}

func (f *fakeState) Status() StatusResp {
	return StatusResp{Version: "test", Uptime: "1s", StartedAt: time.Now(), TotalBans: len(f.banned)}
}
func (f *fakeState) Rules() []RuleInfo     { return f.rules }
func (f *fakeState) Sources() []SourceInfo { return []SourceInfo{{Name: "auth", Status: "running"}} }
func (f *fakeState) Banned(_ context.Context) ([]BanInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]BanInfo, len(f.banned))
	copy(out, f.banned)
	return out, nil
}
func (f *fakeState) Unban(_ context.Context, ip netip.Addr) error {
	f.mu.Lock()
	f.unbanCount++
	defer f.mu.Unlock()
	keep := f.banned[:0]
	for _, b := range f.banned {
		if b.IP != ip.String() {
			keep = append(keep, b)
		}
	}
	f.banned = keep
	return nil
}
func (f *fakeState) BanManual(_ context.Context, ip netip.Addr, rule string, ttl time.Duration) error {
	f.mu.Lock()
	f.manualCount++
	f.mu.Unlock()
	if f.manualErr != nil {
		return f.manualErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.banned = append(f.banned, BanInfo{IP: ip.String(), Rule: rule, TTL: ttl})
	return nil
}

func (f *fakeState) Doctor(_ context.Context, _ DoctorReq) DoctorResp {
	return DoctorResp{Overall: "healthy", CheckedAt: time.Now(), Checks: []DoctorCheck{{Name: "test", Status: "pass", Detail: "ok"}}}
}

func (f *fakeState) Reload(_ context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reloadCount++
	return f.reloadErr
}

func TestServerRoundTrip(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "goban.sock")
	fs := &fakeState{
		rules: []RuleInfo{{Name: "sshd", Source: "auth", Threshold: 3}},
	}
	s := New(fs, sock, 0o660, zerolog.Nop())
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer s.Stop(context.Background())

	c := NewClient(sock)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	st, err := c.Status(ctx)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.Version != "test" {
		t.Errorf("status version = %q, want test", st.Version)
	}

	rules, err := c.Rules(ctx)
	if err != nil {
		t.Fatalf("Rules: %v", err)
	}
	if len(rules) != 1 || rules[0].Name != "sshd" {
		t.Errorf("rules = %+v", rules)
	}
	sources, err := c.Sources(ctx)
	if err != nil {
		t.Fatalf("Sources: %v", err)
	}
	if len(sources) != 1 || sources[0].Status != "running" {
		t.Errorf("sources = %+v", sources)
	}
	doctor, err := c.Doctor(ctx, DoctorReq{})
	if err != nil {
		t.Fatalf("Doctor: %v", err)
	}
	if doctor.Overall != "healthy" {
		t.Errorf("doctor = %+v", doctor)
	}

	if err := c.Ban(ctx, "1.2.3.4", "manual", time.Hour); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	bans, err := c.Banned(ctx)
	if err != nil {
		t.Fatalf("Banned: %v", err)
	}
	if len(bans) != 1 || bans[0].IP != "1.2.3.4" {
		t.Errorf("bans = %+v", bans)
	}

	if err := c.Unban(ctx, "1.2.3.4"); err != nil {
		t.Fatalf("Unban: %v", err)
	}
	bans, _ = c.Banned(ctx)
	if len(bans) != 0 {
		t.Errorf("expected 0 bans after unban, got %d", len(bans))
	}
}

func TestServer_RejectsInvalidIP(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "goban.sock")
	s := New(&fakeState{}, sock, 0o660, zerolog.Nop())
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer s.Stop(context.Background())

	c := NewClient(sock)
	err := c.Unban(context.Background(), "not-an-ip")
	if err == nil {
		t.Fatal("expected error for invalid IP")
	}
}

func TestServer_DelegatesEachManualActionOnce(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "goban.sock")
	fs := &fakeState{}
	s := New(fs, sock, 0o660, zerolog.Nop())
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer s.Stop(context.Background())

	c := NewClient(sock)
	if err := c.Ban(context.Background(), "1.2.3.4", "manual", time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := c.Unban(context.Background(), "1.2.3.4"); err != nil {
		t.Fatal(err)
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if fs.manualCount != 1 || fs.unbanCount != 1 {
		t.Fatalf("manualCount=%d unbanCount=%d, want 1 each", fs.manualCount, fs.unbanCount)
	}
}

func TestServer_Reload(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "goban.sock")
	fs := &fakeState{}
	s := New(fs, sock, 0o660, zerolog.Nop())
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer s.Stop(context.Background())

	c := NewClient(sock)
	if err := c.Reload(context.Background()); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	fs.mu.Lock()
	got := fs.reloadCount
	fs.mu.Unlock()
	if got != 1 {
		t.Errorf("Reload count = %d, want 1", got)
	}
}

func TestServer_ReloadPropagatesError(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "goban.sock")
	fs := &fakeState{reloadErr: errors.New("validation failed: bad regex")}
	s := New(fs, sock, 0o660, zerolog.Nop())
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer s.Stop(context.Background())

	c := NewClient(sock)
	err := c.Reload(context.Background())
	if err == nil {
		t.Fatal("expected error from daemon-side Reload")
	}
	if !strings.Contains(err.Error(), "validation failed") {
		t.Errorf("error %q does not contain expected substring", err.Error())
	}
}

func TestServer_ManualFailurePropagatesOnce(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "goban.sock")
	fs := &fakeState{manualErr: errors.New("kernel said no")}
	s := New(fs, sock, 0o660, zerolog.Nop())
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer s.Stop(context.Background())

	err := NewClient(sock).Ban(context.Background(), "1.2.3.4", "manual", time.Hour)
	if err == nil {
		t.Fatal("expected ban to fail")
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	if fs.manualCount != 1 {
		t.Fatalf("manualCount=%d, want 1", fs.manualCount)
	}
}
