//go:build journald

// Package journal provides a systemd-journal log source backed by sdjournal.
// This file is only built with the `journald` build tag, which also requires
// CGO and libsystemd-dev at build time and libsystemd0 at runtime.
package journal

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/coreos/go-systemd/v22/sdjournal"

	"github.com/izm1chael/goban/internal/source"
)

// Config holds journal source configuration. Match selects which entries to
// read (e.g. "_SYSTEMD_UNIT=ssh.service"); empty means follow the whole journal.
type Config struct {
	Name       string
	Match      string
	MaxLineLen int
}

// Source streams entries from the systemd journal and broadcasts them.
type Source struct {
	name   string
	match  string
	maxLen int

	hub    *source.Hub
	health source.RuntimeHealth
	j      *sdjournal.Journal
	cancel context.CancelFunc
}

// New constructs a journal Source.
func New(cfg Config) *Source {
	if cfg.MaxLineLen <= 0 {
		cfg.MaxLineLen = 16 * 1024
	}
	return &Source{
		name:   cfg.Name,
		match:  cfg.Match,
		maxLen: cfg.MaxLineLen,
		hub:    source.NewHub(),
	}
}

// Name returns the source name.
func (s *Source) Name() string { return s.name }

// Start opens the journal, applies the match filter (if any), seeks to the end
// to follow only new entries, and launches the read goroutine.
func (s *Source) Start(ctx context.Context) error {
	s.health.Starting()
	runCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	j, err := sdjournal.NewJournal()
	if err != nil {
		cancel()
		return fmt.Errorf("open journal: %w", err)
	}
	s.j = j
	// Bound data returned by libsystemd before Go allocates the journal field.
	// MESSAGE= adds eight bytes; the extra headroom covers metadata prefixes
	// without allowing an untrusted service to force an oversized allocation.
	if err := j.SetDataThreshold(uint64(s.maxLen + 256)); err != nil {
		cancel()
		_ = j.Close()
		return fmt.Errorf("journal data threshold: %w", err)
	}
	if s.match != "" {
		parts := strings.SplitN(s.match, "=", 2)
		if len(parts) == 2 {
			if err := j.AddMatch(parts[0] + "=" + parts[1]); err != nil {
				cancel()
				_ = j.Close()
				return fmt.Errorf("journal match: %w", err)
			}
		}
	}
	if err := j.SeekTail(); err != nil {
		cancel()
		_ = j.Close()
		return fmt.Errorf("journal SeekTail: %w", err)
	}
	// SeekTail positions before the newest entry; Previous moves to it so the
	// next Next() advances past it.
	if _, err := j.Previous(); err != nil {
		cancel()
		_ = j.Close()
		return fmt.Errorf("journal Previous: %w", err)
	}
	s.health.Running()
	go s.run(runCtx)
	return nil
}

func (s *Source) run(ctx context.Context) {
	defer s.hub.Close()
	defer s.health.Stopped()
	defer s.j.Close()
	for {
		if ctx.Err() != nil {
			return
		}
		n, err := s.j.Next()
		if err != nil {
			s.health.Error(err)
			time.Sleep(time.Second)
			continue
		}
		if n == 0 {
			s.j.Wait(2 * time.Second)
			continue
		}
		entry, err := s.j.GetEntry()
		if err != nil || entry == nil {
			continue
		}
		msg := entry.Fields["MESSAGE"]
		if msg == "" {
			continue
		}
		if len(msg) > s.maxLen {
			msg = msg[:s.maxLen]
		}
		eventTime := time.Unix(0, int64(entry.RealtimeTimestamp)*int64(time.Microsecond))
		s.health.Event(eventTime)
		receivedAt := time.Now()
		s.hub.Broadcast(source.LogLine{
			Source:     s.name,
			Unit:       entry.Fields["_SYSTEMD_UNIT"],
			Text:       msg,
			Time:       eventTime,
			ReceivedAt: receivedAt,
		})
	}
}

// Subscribe returns a line channel for a named subscriber.
func (s *Source) Subscribe(name string, bufSize int) <-chan source.LogLine {
	return s.hub.Subscribe(name, bufSize)
}

// Unsubscribe removes a subscriber and closes its channel; used during
// daemon.Reload to drop rules that are no longer configured.
func (s *Source) Unsubscribe(name string) {
	s.hub.Unsubscribe(name)
}

// Health returns lifecycle and fan-out counters.
func (s *Source) Health() source.Health { return s.health.Snapshot(s.name, s.hub) }

// Close stops the journal reader and closes subscriber channels.
func (s *Source) Close() error {
	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}
	// The reader owns and closes the Journal. Closing it concurrently with
	// Next/Wait is unsafe; Wait is bounded to two seconds, while closing the
	// hub immediately releases all rule consumers during shutdown/reload.
	s.hub.Close()
	s.health.Stopped()
	return nil
}
