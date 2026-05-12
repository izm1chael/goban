// Package file implements a Source backed by a tailed file with rotation
// support.
package file

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/nxadm/tail"

	"github.com/izm1chael/goban/internal/source"
)

// Source tails one file and fans out lines to subscribers.
type Source struct {
	name   string
	path   string
	replay bool
	maxLen int

	hub *source.Hub
	t   *tail.Tail
}

// Config holds the file source's runtime parameters.
type Config struct {
	Name       string
	Path       string
	Replay     bool // false = skip to end of file at start
	MaxLineLen int  // truncate longer lines before broadcast
}

// New constructs a file Source.
func New(cfg Config) *Source {
	if cfg.MaxLineLen <= 0 {
		cfg.MaxLineLen = 16 * 1024
	}
	return &Source{
		name:   cfg.Name,
		path:   cfg.Path,
		replay: cfg.Replay,
		maxLen: cfg.MaxLineLen,
		hub:    source.NewHub(),
	}
}

// Name returns the configured source name.
func (s *Source) Name() string { return s.name }

// Start opens the file with nxadm/tail and begins broadcasting lines.
func (s *Source) Start(ctx context.Context) error {
	location := &tail.SeekInfo{Offset: 0, Whence: io.SeekEnd}
	if s.replay {
		location = &tail.SeekInfo{Offset: 0, Whence: io.SeekStart}
	}
	t, err := tail.TailFile(s.path, tail.Config{
		Follow:    true,
		ReOpen:    true,
		MustExist: false,
		Logger:    tail.DiscardingLogger,
		Location:  location,
	})
	if err != nil {
		return fmt.Errorf("tail %s: %w", s.path, err)
	}
	s.t = t
	go s.run(ctx)
	return nil
}

func (s *Source) run(ctx context.Context) {
	defer s.hub.Close()
	defer func() { _ = s.t.Stop() }()
	for {
		select {
		case <-ctx.Done():
			return
		case line, ok := <-s.t.Lines:
			if !ok {
				return
			}
			if line == nil {
				continue
			}
			if line.Err != nil && !errors.Is(line.Err, io.EOF) {
				continue
			}
			txt := line.Text
			if len(txt) > s.maxLen {
				txt = txt[:s.maxLen]
			}
			s.hub.Broadcast(source.LogLine{
				Source: s.name,
				Text:   txt,
				Time:   time.Now(),
			})
		}
	}
}

// Subscribe returns the line channel for a named subscriber.
func (s *Source) Subscribe(name string, bufSize int) <-chan source.LogLine {
	return s.hub.Subscribe(name, bufSize)
}

// Unsubscribe removes a subscriber and closes its channel; used during
// daemon.Reload to drop rules that are no longer configured.
func (s *Source) Unsubscribe(name string) {
	s.hub.Unsubscribe(name)
}

// Close stops the tailer and closes all subscriber channels.
func (s *Source) Close() error {
	if s.t != nil {
		_ = s.t.Stop()
	}
	s.hub.Close()
	return nil
}
