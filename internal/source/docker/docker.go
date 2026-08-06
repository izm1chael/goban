// Package docker implements a supervised Source that streams container logs
// and survives Docker daemon/event-stream restarts.
package docker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	dockerclient "github.com/docker/docker/client"

	"github.com/izm1chael/goban/internal/source"
)

const (
	minReconnectBackoff = time.Second
	maxReconnectBackoff = 30 * time.Second
	reconcileInterval   = 30 * time.Second
)

// Client is the subset of the Docker SDK used by the source.
type Client interface {
	Ping(ctx context.Context) (interface{}, error)
	ContainerList(ctx context.Context, opts container.ListOptions) ([]container.Summary, error)
	ContainerLogs(ctx context.Context, id string, opts container.LogsOptions) (io.ReadCloser, error)
	Events(ctx context.Context, opts events.ListOptions) (<-chan events.Message, <-chan error)
	Close() error
}

type Source struct {
	name      string
	container string
	labels    map[string]string
	maxLen    int

	hub    *source.Hub
	health source.RuntimeHealth
	cli    Client
	closer io.Closer

	mu      sync.Mutex
	tracked map[string]context.CancelFunc
	cancel  context.CancelFunc
	closed  bool
}

type Config struct {
	Name       string
	Container  string
	Labels     map[string]string
	MaxLineLen int
}

func New(cfg Config) (*Source, error) {
	cli, err := dockerclient.NewClientWithOpts(dockerclient.FromEnv, dockerclient.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("docker client: %w", err)
	}
	return newWithClient(cfg, &realClient{c: cli}, cli), nil
}

func newWithClient(cfg Config, c Client, raw io.Closer) *Source {
	if cfg.MaxLineLen <= 0 {
		cfg.MaxLineLen = 16 * 1024
	}
	labels := make(map[string]string, len(cfg.Labels))
	for k, v := range cfg.Labels {
		labels[k] = v
	}
	return &Source{
		name:      cfg.Name,
		container: cfg.Container,
		labels:    labels,
		maxLen:    cfg.MaxLineLen,
		hub:       source.NewHub(),
		cli:       c,
		closer:    raw,
		tracked:   make(map[string]context.CancelFunc),
	}
}

func (s *Source) Name() string { return s.name }

func (s *Source) Start(ctx context.Context) error {
	s.health.Starting()
	runCtx, cancel := context.WithCancel(ctx)
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		cancel()
		return errors.New("docker source is closed")
	}
	s.cancel = cancel
	s.mu.Unlock()
	if _, err := s.cli.Ping(runCtx); err != nil {
		cancel()
		s.health.Error(err)
		return fmt.Errorf("docker ping failed (hint: --group-add docker, mount /var/run/docker.sock): %w", err)
	}
	if err := s.reconcile(runCtx); err != nil {
		cancel()
		s.health.Error(err)
		return fmt.Errorf("container list: %w", err)
	}
	s.health.Running()
	go s.watchEvents(runCtx)
	return nil
}

func (s *Source) matches(c container.Summary) bool {
	if s.container != "" {
		for _, n := range c.Names {
			if strings.TrimPrefix(n, "/") == s.container {
				return true
			}
		}
		return false
	}
	for k, v := range s.labels {
		if c.Labels[k] != v {
			return false
		}
	}
	return len(s.labels) > 0
}

func displayName(c container.Summary) string {
	if len(c.Names) > 0 {
		return strings.TrimPrefix(c.Names[0], "/")
	}
	if len(c.ID) >= 12 {
		return c.ID[:12]
	}
	return c.ID
}

func (s *Source) eventFilters() filters.Args {
	args := filters.NewArgs()
	args.Add("type", "container")
	args.Add("event", "start")
	args.Add("event", "die")
	args.Add("event", "destroy")
	return args
}

// watchEvents reconnects whenever Docker closes either event channel. It also
// periodically reconciles the running container set, so missed events cannot
// leave protection silently detached.
func (s *Source) watchEvents(ctx context.Context) {
	defer s.hub.Close()
	defer s.health.Stopped()

	ticker := time.NewTicker(reconcileInterval)
	defer ticker.Stop()
	backoff := minReconnectBackoff

	for ctx.Err() == nil {
		msgCh, errCh := s.cli.Events(ctx, events.ListOptions{Filters: s.eventFilters()})
		reconnect := false
		for !reconnect && ctx.Err() == nil {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := s.reconcile(ctx); err != nil {
					s.health.Error(fmt.Errorf("docker reconcile: %w", err))
				}
			case msg, ok := <-msgCh:
				if !ok {
					s.health.Error(errors.New("docker event stream closed"))
					reconnect = true
					continue
				}
				s.handleEvent(ctx, msg)
			case err, ok := <-errCh:
				if !ok {
					s.health.Error(errors.New("docker event error stream closed"))
					reconnect = true
					continue
				}
				if err != nil && !isContextErr(err) {
					s.health.Error(err)
					reconnect = true
				}
			}
		}
		if ctx.Err() != nil {
			return
		}
		s.health.Reconnect()
		if !sleepContext(ctx, backoff) {
			return
		}
		if err := s.reconcile(ctx); err != nil {
			s.health.Error(fmt.Errorf("docker reconnect reconcile: %w", err))
			backoff = nextBackoff(backoff)
			continue
		}
		s.health.Running()
		backoff = minReconnectBackoff
	}
}

func (s *Source) reconcile(ctx context.Context) error {
	current, err := s.cli.ContainerList(ctx, container.ListOptions{All: false})
	if err != nil {
		return err
	}
	active := make(map[string]struct{})
	for _, c := range current {
		if !s.matches(c) {
			continue
		}
		active[c.ID] = struct{}{}
		s.attach(ctx, c.ID, displayName(c))
	}
	s.mu.Lock()
	for id, cancel := range s.tracked {
		if _, ok := active[id]; !ok {
			cancel()
			delete(s.tracked, id)
		}
	}
	s.mu.Unlock()
	return nil
}

func (s *Source) handleEvent(ctx context.Context, msg events.Message) {
	id := msg.Actor.ID
	if id == "" {
		return
	}
	switch msg.Action {
	case events.ActionStart:
		list, err := s.cli.ContainerList(ctx, container.ListOptions{Filters: filters.NewArgs(filters.Arg("id", id))})
		if err != nil {
			s.health.Error(err)
			return
		}
		if len(list) > 0 && s.matches(list[0]) {
			s.attach(ctx, id, displayName(list[0]))
		}
	case events.ActionDie, events.ActionDestroy:
		s.detach(id)
	}
}

func (s *Source) attach(parent context.Context, id, name string) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	if _, exists := s.tracked[id]; exists {
		s.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(parent)
	s.tracked[id] = cancel
	s.mu.Unlock()
	go s.streamLogs(ctx, id, name)
}

func (s *Source) detach(id string) {
	s.mu.Lock()
	if cancel, ok := s.tracked[id]; ok {
		cancel()
		delete(s.tracked, id)
	}
	s.mu.Unlock()
}

// streamLogs reopens a container log stream after transient scanner/daemon
// failures. ReadBoundedLines ensures an oversized record cannot force a 1 MiB
// scanner allocation or permanently terminate monitoring.
func (s *Source) streamLogs(ctx context.Context, id, name string) {
	defer s.detach(id)
	backoff := minReconnectBackoff
	for ctx.Err() == nil {
		rc, err := s.cli.ContainerLogs(ctx, id, container.LogsOptions{
			ShowStdout: true,
			ShowStderr: true,
			Follow:     true,
			Tail:       "0",
			Timestamps: false,
		})
		if err != nil {
			if !isContextErr(err) {
				s.health.Error(fmt.Errorf("container %s logs: %w", name, err))
			}
			if !sleepContext(ctx, backoff) {
				return
			}
			s.health.Reconnect()
			backoff = nextBackoff(backoff)
			continue
		}

		err = source.ReadBoundedLines(stripDockerStreamHeader(rc), s.maxLen, func(txt string) bool {
			if ctx.Err() != nil {
				return false
			}
			now := time.Now()
			s.health.Event(now)
			s.hub.Broadcast(source.LogLine{
				Source:     s.name,
				Container:  name,
				Text:       txt,
				Time:       now,
				ReceivedAt: now,
			})
			return true
		})
		_ = rc.Close()
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			s.health.Error(fmt.Errorf("container %s log stream: %w", name, err))
		} else {
			s.health.Error(fmt.Errorf("container %s log stream ended", name))
		}
		s.health.Reconnect()
		if !sleepContext(ctx, backoff) {
			return
		}
		backoff = nextBackoff(backoff)
	}
}

func (s *Source) Subscribe(name string, bufSize int) <-chan source.LogLine {
	return s.hub.Subscribe(name, bufSize)
}

func (s *Source) Unsubscribe(name string) { s.hub.Unsubscribe(name) }

func (s *Source) Health() source.Health { return s.health.Snapshot(s.name, s.hub) }

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
	for id, cancel := range s.tracked {
		cancel()
		delete(s.tracked, id)
	}
	s.mu.Unlock()
	s.hub.Close()
	s.health.Stopped()
	if s.closer != nil {
		return s.closer.Close()
	}
	return nil
}

func nextBackoff(v time.Duration) time.Duration {
	v *= 2
	if v > maxReconnectBackoff {
		return maxReconnectBackoff
	}
	return v
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

func isContextErr(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		strings.Contains(errString(err), "context canceled") || strings.Contains(errString(err), "context deadline exceeded")
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

type realClient struct{ c *dockerclient.Client }

func (r *realClient) Ping(ctx context.Context) (interface{}, error) {
	return r.c.Ping(ctx)
}
func (r *realClient) ContainerList(ctx context.Context, opts container.ListOptions) ([]container.Summary, error) {
	return r.c.ContainerList(ctx, opts)
}
func (r *realClient) ContainerLogs(ctx context.Context, id string, opts container.LogsOptions) (io.ReadCloser, error) {
	return r.c.ContainerLogs(ctx, id, opts)
}
func (r *realClient) Events(ctx context.Context, opts events.ListOptions) (<-chan events.Message, <-chan error) {
	return r.c.Events(ctx, opts)
}
func (r *realClient) Close() error { return r.c.Close() }
