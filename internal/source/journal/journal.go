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

	hub *source.Hub
	j   *sdjournal.Journal
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
	j, err := sdjournal.NewJournal()
	if err != nil {
		return fmt.Errorf("open journal: %w", err)
	}
	s.j = j
	if s.match != "" {
		parts := strings.SplitN(s.match, "=", 2)
		if len(parts) == 2 {
			if err := j.AddMatch(parts[0] + "=" + parts[1]); err != nil {
				return fmt.Errorf("journal match: %w", err)
			}
		}
	}
	if err := j.SeekTail(); err != nil {
		return fmt.Errorf("journal SeekTail: %w", err)
	}
	// SeekTail positions before the newest entry; Previous moves to it so the
	// next Next() advances past it.
	if _, err := j.Previous(); err != nil {
		return fmt.Errorf("journal Previous: %w", err)
	}
	go s.run(ctx)
	return nil
}

func (s *Source) run(ctx context.Context) {
	defer s.hub.Close()
	defer s.j.Close()
	for {
		if ctx.Err() != nil {
			return
		}
		n, err := s.j.Next()
		if err != nil {
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
		s.hub.Broadcast(source.LogLine{
			Source: s.name,
			Unit:   entry.Fields["_SYSTEMD_UNIT"],
			Text:   msg,
			Time:   time.Unix(0, int64(entry.RealtimeTimestamp)*int64(time.Microsecond)),
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

// Close stops the journal reader and closes subscriber channels.
func (s *Source) Close() error {
	s.hub.Close()
	if s.j != nil {
		return s.j.Close()
	}
	return nil
}
