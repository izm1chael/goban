package control

import (
	"bytes"
	"context"
	"encoding/json"
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
	reloadErr   error
	reloadCount int
}

func (f *fakeState) Status() StatusResp {
	return StatusResp{Version: "test", Uptime: "1s", StartedAt: time.Now(), TotalBans: len(f.banned)}
}
func (f *fakeState) Rules() []RuleInfo { return f.rules }
func (f *fakeState) Banned(_ context.Context) ([]BanInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]BanInfo, len(f.banned))
	copy(out, f.banned)
	return out, nil
}
func (f *fakeState) Unban(_ context.Context, ip netip.Addr) error {
	f.mu.Lock()
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
	if f.manualErr != nil {
		return f.manualErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.banned = append(f.banned, BanInfo{IP: ip.String(), Rule: rule, TTL: ttl})
	return nil
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
	s := New(fs, sock, 0o660, zerolog.Nop(), nil)
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
	s := New(&fakeState{}, sock, 0o660, zerolog.Nop(), nil)
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

func TestServer_AuditLogsBanAndUnban(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "goban.sock")
	var audit bytes.Buffer
	s := New(&fakeState{}, sock, 0o660, zerolog.Nop(), NewAuditWriter(&audit))
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer s.Stop(context.Background())

	c := NewClient(sock)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := c.Ban(ctx, "1.2.3.4", "manual", time.Hour); err != nil {
		t.Fatalf("Ban: %v", err)
	}
	if err := c.Unban(ctx, "1.2.3.4"); err != nil {
		t.Fatalf("Unban: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(audit.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("audit lines = %d, want 2: %q", len(lines), audit.String())
	}

	var first AuditEvent
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("audit line 0 JSON: %v", err)
	}
	if first.Action != "ban" || first.IP != "1.2.3.4" || first.Rule != "manual" {
		t.Errorf("ban audit wrong: %+v", first)
	}

	var second AuditEvent
	if err := json.Unmarshal([]byte(lines[1]), &second); err != nil {
		t.Fatalf("audit line 1 JSON: %v", err)
	}
	if second.Action != "unban" || second.IP != "1.2.3.4" {
		t.Errorf("unban audit wrong: %+v", second)
	}
}

func TestServer_Reload(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "goban.sock")
	fs := &fakeState{}
	s := New(fs, sock, 0o660, zerolog.Nop(), nil)
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
	s := New(fs, sock, 0o660, zerolog.Nop(), nil)
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

func TestServer_AuditNotLoggedOnFailure(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "goban.sock")
	var audit bytes.Buffer
	fs := &fakeState{manualErr: errors.New("kernel said no")}
	s := New(fs, sock, 0o660, zerolog.Nop(), NewAuditWriter(&audit))
	if err := s.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer s.Stop(context.Background())

	c := NewClient(sock)
	err := c.Ban(context.Background(), "1.2.3.4", "manual", time.Hour)
	if err == nil {
		t.Fatal("expected ban to fail")
	}
	if audit.Len() != 0 {
		t.Errorf("audit logged a failed ban: %q", audit.String())
	}
}
