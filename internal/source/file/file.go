// Package file implements a bounded, rotation-aware file follower.
package file

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/izm1chael/goban/internal/source"
)

const followPollInterval = 200 * time.Millisecond

// Source follows one file and fans out bounded lines to subscribers.
type Source struct {
	name   string
	path   string
	replay bool
	maxLen int

	hub    *source.Hub
	health source.RuntimeHealth

	mu     sync.Mutex
	f      *os.File
	cancel context.CancelFunc
	closed bool
}

// Config holds the file source's runtime parameters.
type Config struct {
	Name       string
	Path       string
	Replay     bool // false = skip to end of a file that exists at Start
	MaxLineLen int
}

func New(cfg Config) *Source {
	if cfg.MaxLineLen <= 0 {
		cfg.MaxLineLen = 16 * 1024
	}
	return &Source{name: cfg.Name, path: cfg.Path, replay: cfg.Replay, maxLen: cfg.MaxLineLen, hub: source.NewHub()}
}

func (s *Source) Name() string { return s.name }

// Start validates the containing directory, opens the current file when it
// exists, and starts a bounded follower. A missing file is allowed and will be
// picked up from byte zero when created after startup.
func (s *Source) Start(ctx context.Context) error {
	s.health.Starting()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return errors.New("file source is closed")
	}
	runCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.mu.Unlock()

	if st, err := os.Stat(filepath.Dir(s.path)); err != nil || !st.IsDir() {
		cancel()
		if err != nil {
			return fmt.Errorf("source directory %s: %w", filepath.Dir(s.path), err)
		}
		return fmt.Errorf("source directory %s is not a directory", filepath.Dir(s.path))
	}

	f, info, offset, err := s.openInitial()
	if err != nil {
		cancel()
		s.health.Error(err)
		return err
	}
	s.setFile(f)
	s.health.Running()
	go s.run(runCtx, f, info, offset)
	return nil
}

func (s *Source) openInitial() (*os.File, os.FileInfo, int64, error) {
	f, err := os.Open(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, 0, nil
	}
	if err != nil {
		return nil, nil, 0, fmt.Errorf("open %s: %w", s.path, err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, nil, 0, fmt.Errorf("stat %s: %w", s.path, err)
	}
	offset := int64(0)
	if !s.replay {
		offset, err = f.Seek(0, io.SeekEnd)
		if err != nil {
			_ = f.Close()
			return nil, nil, 0, fmt.Errorf("seek %s: %w", s.path, err)
		}
	}
	return f, info, offset, nil
}

func (s *Source) openFromStart() (*os.File, os.FileInfo, error) {
	f, err := os.Open(s.path)
	if err != nil {
		return nil, nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	return f, info, nil
}

func (s *Source) run(ctx context.Context, f *os.File, info os.FileInfo, offset int64) {
	defer s.hub.Close()
	defer s.health.Stopped()
	defer func() { s.setFile(nil) }()

	acc := source.NewBoundedAccumulator(s.maxLen)
	buf := make([]byte, 32*1024)
	for {
		if ctx.Err() != nil {
			if f != nil {
				_ = f.Close()
			}
			return
		}
		if f == nil {
			var err error
			f, info, err = s.openFromStart()
			if errors.Is(err, os.ErrNotExist) {
				if !sleepContext(ctx, followPollInterval) {
					return
				}
				continue
			}
			if err != nil {
				s.health.Error(fmt.Errorf("open %s: %w", s.path, err))
				if !sleepContext(ctx, time.Second) {
					return
				}
				continue
			}
			offset = 0
			acc.Reset()
			s.setFile(f)
			s.health.Running()
		}

		n, err := f.Read(buf)
		if n > 0 {
			offset += int64(n)
			acc.Feed(buf[:n], func(text string) bool {
				now := time.Now()
				s.health.Event(now)
				s.hub.Broadcast(source.LogLine{Source: s.name, Text: text, Time: now, ReceivedAt: now})
				return ctx.Err() == nil
			})
		}
		if err == nil {
			continue
		}
		if !errors.Is(err, io.EOF) {
			if ctx.Err() == nil {
				s.health.Error(fmt.Errorf("read %s: %w", s.path, err))
			}
			_ = f.Close()
			f, info, offset = nil, nil, 0
			s.setFile(nil)
			acc.Reset()
			continue
		}

		pathInfo, statErr := os.Stat(s.path)
		switch {
		case statErr == nil && info != nil && !os.SameFile(info, pathInfo):
			_ = f.Close()
			f, info, offset = nil, nil, 0
			s.setFile(nil)
			acc.Reset()
			continue
		case statErr == nil && pathInfo.Size() < offset:
			if _, seekErr := f.Seek(0, io.SeekStart); seekErr != nil {
				s.health.Error(fmt.Errorf("rewind truncated %s: %w", s.path, seekErr))
				_ = f.Close()
				f, info = nil, nil
				s.setFile(nil)
			} else {
				offset = 0
			}
			acc.Reset()
			continue
		case statErr != nil && !errors.Is(statErr, os.ErrNotExist):
			s.health.Error(fmt.Errorf("stat %s: %w", s.path, statErr))
		}
		if !sleepContext(ctx, followPollInterval) {
			_ = f.Close()
			return
		}
	}
}

func sleepContext(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func (s *Source) setFile(f *os.File) {
	s.mu.Lock()
	s.f = f
	s.mu.Unlock()
}

func (s *Source) Subscribe(name string, bufSize int) <-chan source.LogLine {
	return s.hub.Subscribe(name, bufSize)
}
func (s *Source) Unsubscribe(name string) { s.hub.Unsubscribe(name) }
func (s *Source) Health() source.Health   { return s.health.Snapshot(s.name, s.hub) }

func (s *Source) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}
	f := s.f
	s.f = nil
	s.mu.Unlock()
	if f != nil {
		_ = f.Close()
	}
	s.hub.Close()
	s.health.Stopped()
	return nil
}
