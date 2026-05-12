// Package docker implements a Source that streams container logs from the
// Docker daemon and dynamically attaches to new containers matching a label or
// name selector.
package docker

import (
	"bufio"
	"context"
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

// Client is the subset of the docker SDK we depend on. Defining it as an
// interface lets tests substitute a fake.
type Client interface {
	Ping(ctx context.Context) (interface{}, error) // returns types.Ping in practice; not used by our code
	ContainerList(ctx context.Context, opts container.ListOptions) ([]container.Summary, error)
	ContainerLogs(ctx context.Context, id string, opts container.LogsOptions) (io.ReadCloser, error)
	Events(ctx context.Context, opts events.ListOptions) (<-chan events.Message, <-chan error)
	Close() error
}

// Source streams logs from containers matching either Container (name) or
// Labels (label k=v filter).
type Source struct {
	name      string
	container string
	labels    map[string]string
	maxLen    int

	hub    *source.Hub
	cli    Client
	closer io.Closer

	mu      sync.Mutex
	tracked map[string]context.CancelFunc // containerID -> per-container cancel
}

// Config holds the docker source's runtime parameters.
type Config struct {
	Name       string
	Container  string            // exact container name match
	Labels     map[string]string // optional label filter (AND semantics)
	MaxLineLen int
}

// New constructs a docker Source using a real docker client from the
// environment (DOCKER_HOST, /var/run/docker.sock).
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
	return &Source{
		name:      cfg.Name,
		container: cfg.Container,
		labels:    cfg.Labels,
		maxLen:    cfg.MaxLineLen,
		hub:       source.NewHub(),
		cli:       c,
		closer:    raw,
		tracked:   make(map[string]context.CancelFunc),
	}
}

// Name returns the source name.
func (s *Source) Name() string { return s.name }

// Start checks the docker socket, lists currently-running matching
// containers, and subscribes to events for newly-started ones.
func (s *Source) Start(ctx context.Context) error {
	if _, err := s.cli.Ping(ctx); err != nil {
		return fmt.Errorf("docker ping failed (hint: --group-add docker, mount /var/run/docker.sock): %w", err)
	}

	current, err := s.cli.ContainerList(ctx, container.ListOptions{All: false})
	if err != nil {
		return fmt.Errorf("container list: %w", err)
	}
	for _, c := range current {
		if s.matches(c) {
			s.attach(ctx, c.ID, displayName(c))
		}
	}

	go s.watchEvents(ctx)
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

func (s *Source) watchEvents(ctx context.Context) {
	defer s.hub.Close()
	args := filters.NewArgs()
	args.Add("type", "container")
	args.Add("event", "start")
	args.Add("event", "die")
	msgCh, errCh := s.cli.Events(ctx, events.ListOptions{Filters: args})
	for {
		select {
		case <-ctx.Done():
			return
		case msg, ok := <-msgCh:
			if !ok {
				return
			}
			s.handleEvent(ctx, msg)
		case err, ok := <-errCh:
			if !ok {
				return
			}
			if err != nil && !isContextErr(err) {
				time.Sleep(time.Second)
				msgCh, errCh = s.cli.Events(ctx, events.ListOptions{Filters: args})
			}
		}
	}
}

func (s *Source) handleEvent(ctx context.Context, msg events.Message) {
	id := msg.Actor.ID
	if id == "" {
		return
	}
	name := strings.TrimPrefix(msg.Actor.Attributes["name"], "/")
	switch msg.Action {
	case events.ActionStart:
		// re-list to confirm match by labels/name
		list, err := s.cli.ContainerList(ctx, container.ListOptions{Filters: filters.NewArgs(filters.Arg("id", id))})
		if err != nil || len(list) == 0 {
			return
		}
		if s.matches(list[0]) {
			s.attach(ctx, id, displayName(list[0]))
		}
	case events.ActionDie:
		s.mu.Lock()
		if cancel, ok := s.tracked[id]; ok {
			cancel()
			delete(s.tracked, id)
		}
		s.mu.Unlock()
		_ = name
	}
}

func (s *Source) attach(parent context.Context, id, name string) {
	s.mu.Lock()
	if _, exists := s.tracked[id]; exists {
		s.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(parent)
	s.tracked[id] = cancel
	s.mu.Unlock()
	go s.streamLogs(ctx, id, name)
}

func (s *Source) streamLogs(ctx context.Context, id, name string) {
	defer func() {
		s.mu.Lock()
		delete(s.tracked, id)
		s.mu.Unlock()
	}()
	rc, err := s.cli.ContainerLogs(ctx, id, container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     true,
		Tail:       "0",
		Timestamps: false,
	})
	if err != nil {
		return
	}
	defer rc.Close()
	scanner := bufio.NewScanner(stripDockerStreamHeader(rc))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		if ctx.Err() != nil {
			return
		}
		txt := scanner.Text()
		if len(txt) > s.maxLen {
			txt = txt[:s.maxLen]
		}
		s.hub.Broadcast(source.LogLine{
			Source:    s.name,
			Container: name,
			Text:      txt,
			Time:      time.Now(),
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

// Close cancels all per-container goroutines and closes the docker client.
func (s *Source) Close() error {
	s.mu.Lock()
	for id, cancel := range s.tracked {
		cancel()
		delete(s.tracked, id)
	}
	s.mu.Unlock()
	s.hub.Close()
	if s.closer != nil {
		return s.closer.Close()
	}
	return nil
}

func isContextErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "context canceled") || strings.Contains(msg, "context deadline exceeded")
}

// realClient adapts dockerclient.Client to our Client interface.
type realClient struct {
	c *dockerclient.Client
}

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
