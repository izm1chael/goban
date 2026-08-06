// Package source defines the LogLine type and Source interface shared by file,
// Docker, and journal backends. Hub provides bounded fan-out with observable
// drop counters so overload can never remain invisible to operators.
package source

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// LogLine is a single line of log output ready to be matched.
type LogLine struct {
	Source     string
	Container  string
	Unit       string
	Text       string
	Time       time.Time // source event time; rules use this as timestamp fallback
	ReceivedAt time.Time // ingestion time used for lossless, duplicate-free reload cutover
}

// Health is a point-in-time source health snapshot.
type Health struct {
	Name          string    `json:"name"`
	Status        string    `json:"status"` // starting|running|degraded|stopped
	StartedAt     time.Time `json:"started_at,omitempty"`
	LastEventAt   time.Time `json:"last_event_at,omitempty"`
	LastErrorAt   time.Time `json:"last_error_at,omitempty"`
	LastError     string    `json:"last_error,omitempty"`
	Reconnects    uint64    `json:"reconnects"`
	Subscribers   int       `json:"subscribers"`
	Delivered     uint64    `json:"delivered"`
	Dropped       uint64    `json:"dropped"`
	MaxQueueDepth int       `json:"max_queue_depth"`
}

// Source is the read side of a log stream.
type Source interface {
	Name() string
	Start(ctx context.Context) error
	Subscribe(name string, bufSize int) <-chan LogLine
	Unsubscribe(name string)
	Health() Health
	Close() error
}

type subscriber struct {
	ch chan LogLine
}

// HubStats are cumulative fan-out counters.
type HubStats struct {
	Subscribers   int
	Delivered     uint64
	Dropped       uint64
	MaxQueueDepth int
	Closed        bool
}

// Hub is a reusable, bounded fan-out helper.
type Hub struct {
	mu          sync.Mutex
	subscribers map[string]*subscriber
	closed      bool
	delivered   atomic.Uint64
	dropped     atomic.Uint64
	maxDepth    atomic.Int64
}

func NewHub() *Hub { return &Hub{subscribers: make(map[string]*subscriber)} }

// Subscribe returns a permanently closed channel when the hub has already
// stopped. This prevents a post-close subscriber from hanging forever.
func (h *Hub) Subscribe(name string, bufSize int) <-chan LogLine {
	if bufSize < 0 {
		bufSize = 0
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if existing, ok := h.subscribers[name]; ok {
		return existing.ch
	}
	ch := make(chan LogLine, bufSize)
	if h.closed {
		close(ch)
		return ch
	}
	h.subscribers[name] = &subscriber{ch: ch}
	return ch
}

func (h *Hub) Unsubscribe(name string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if sub, ok := h.subscribers[name]; ok {
		delete(h.subscribers, name)
		close(sub.ch)
	}
}

// Broadcast is deliberately non-blocking. Every dropped delivery is counted;
// callers surface the aggregate through Source.Health and the control API.
func (h *Hub) Broadcast(line LogLine) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return 0
	}
	delivered := 0
	for _, sub := range h.subscribers {
		select {
		case sub.ch <- line:
			delivered++
			h.delivered.Add(1)
			depth := int64(len(sub.ch))
			for {
				old := h.maxDepth.Load()
				if depth <= old || h.maxDepth.CompareAndSwap(old, depth) {
					break
				}
			}
		default:
			h.dropped.Add(1)
		}
	}
	return delivered
}

// Close atomically detaches and closes every subscriber. Removing entries
// before returning makes a later Unsubscribe a safe no-op rather than a
// double-close panic.
func (h *Hub) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}
	h.closed = true
	for name, sub := range h.subscribers {
		delete(h.subscribers, name)
		close(sub.ch)
	}
}

func (h *Hub) Stats() HubStats {
	h.mu.Lock()
	defer h.mu.Unlock()
	return HubStats{
		Subscribers:   len(h.subscribers),
		Delivered:     h.delivered.Load(),
		Dropped:       h.dropped.Load(),
		MaxQueueDepth: int(h.maxDepth.Load()),
		Closed:        h.closed,
	}
}

func (h *Hub) SubscriberCount() int { return h.Stats().Subscribers }

// RuntimeHealth centralises source lifecycle bookkeeping.
type RuntimeHealth struct {
	mu          sync.Mutex
	status      string
	startedAt   time.Time
	lastEventAt time.Time
	lastErrorAt time.Time
	lastError   string
	reconnects  uint64
}

func (r *RuntimeHealth) Starting() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.status = "starting"
	if r.startedAt.IsZero() {
		r.startedAt = time.Now().UTC()
	}
}

func (r *RuntimeHealth) Running() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.status = "running"
	if r.startedAt.IsZero() {
		r.startedAt = time.Now().UTC()
	}
	r.lastError = ""
}

func (r *RuntimeHealth) Event(at time.Time) {
	if at.IsZero() {
		at = time.Now()
	}
	r.mu.Lock()
	r.lastEventAt = at.UTC()
	if r.status != "stopped" {
		r.status = "running"
	}
	r.mu.Unlock()
}

func (r *RuntimeHealth) Error(err error) {
	if err == nil {
		return
	}
	r.mu.Lock()
	r.status = "degraded"
	r.lastError = err.Error()
	r.lastErrorAt = time.Now().UTC()
	r.mu.Unlock()
}

func (r *RuntimeHealth) Reconnect() {
	r.mu.Lock()
	r.reconnects++
	r.mu.Unlock()
}

func (r *RuntimeHealth) Stopped() {
	r.mu.Lock()
	r.status = "stopped"
	r.mu.Unlock()
}

func (r *RuntimeHealth) Snapshot(name string, hub *Hub) Health {
	r.mu.Lock()
	h := Health{
		Name:        name,
		Status:      r.status,
		StartedAt:   r.startedAt,
		LastEventAt: r.lastEventAt,
		LastErrorAt: r.lastErrorAt,
		LastError:   r.lastError,
		Reconnects:  r.reconnects,
	}
	r.mu.Unlock()
	if h.Status == "" {
		h.Status = "stopped"
	}
	if hub != nil {
		hs := hub.Stats()
		h.Subscribers = hs.Subscribers
		h.Delivered = hs.Delivered
		h.Dropped = hs.Dropped
		h.MaxQueueDepth = hs.MaxQueueDepth
	}
	return h
}
