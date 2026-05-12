//go:build !journald

// Package journal provides a systemd-journal log source. The default build
// excludes libsystemd to keep the binary CGO-free; configure a journal source
// only in builds produced via `make build-journald`.
package journal

import (
	"context"
	"fmt"

	"github.com/izm1chael/goban/internal/source"
)

// Config holds journal source configuration. Match selects which entries to
// read (e.g. "_SYSTEMD_UNIT=ssh.service"); empty means follow the whole journal.
type Config struct {
	Name       string
	Match      string
	MaxLineLen int
}

// Source is a journald-backed log source. In the default (non-journald) build
// it returns an error at Start; rebuild with `make build-journald` to enable.
type Source struct {
	name string
}

// New constructs a journal Source.
func New(cfg Config) *Source {
	return &Source{name: cfg.Name}
}

// Name returns the source name.
func (s *Source) Name() string { return s.name }

// Start fails because journald support is not compiled into this binary.
func (s *Source) Start(_ context.Context) error {
	return fmt.Errorf("source %q: journald support not compiled in — rebuild with `make build-journald`", s.name)
}

// Subscribe returns a closed channel.
func (s *Source) Subscribe(_ string, _ int) <-chan source.LogLine {
	ch := make(chan source.LogLine)
	close(ch)
	return ch
}

// Unsubscribe is a no-op for the stub (Subscribe already returned a closed channel).
func (s *Source) Unsubscribe(_ string) {}

// Close is a no-op for the stub.
func (s *Source) Close() error { return nil }
