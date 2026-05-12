// Package source defines the LogLine type and the Source interface that file,
// docker and journal backends implement. A simple Hub helper provides
// fan-out so multiple jails can subscribe to the same source.
package source

import (
	"context"
	"sync"
	"time"
)

// LogLine is a single line of log output ready to be matched.
type LogLine struct {
	Source    string    // source name (e.g. "auth-log")
	Container string    // populated by docker source
	Unit      string    // populated by journal source
	Text      string    // the raw line, trimmed of trailing newline
	Time      time.Time // event time if available, else producer wall time
}

// Source is the read side of a log stream. Subscribe returns a channel that
// receives LogLine values until the Source is shut down via Close or its
// internal context is cancelled.
type Source interface {
	// Name returns the user-configured source name.
	Name() string
	// Start begins producing lines; safe to call once. ctx cancellation
	// terminates the source.
	Start(ctx context.Context) error
	// Subscribe returns a receive-only channel of LogLine. Multiple
	// subscribers each receive every line. Buffered to absorb spikes.
	Subscribe(name string, bufSize int) <-chan LogLine
	// Unsubscribe removes a named subscriber, closing its channel so the
	// consuming goroutine's `range` over it terminates cleanly. Safe to
	// call on an unknown name (no-op).
	Unsubscribe(name string)
	// Close releases resources.
	Close() error
}

// Hub is a reusable fan-out helper for Source implementations.
type Hub struct {
	mu          sync.Mutex
	subscribers map[string]chan LogLine
	closed      bool
}

// NewHub returns an empty Hub.
func NewHub() *Hub {
	return &Hub{subscribers: make(map[string]chan LogLine)}
}

// Subscribe registers a named subscriber and returns its channel. If a
// subscriber with the same name already exists the existing channel is
// returned.
func (h *Hub) Subscribe(name string, bufSize int) <-chan LogLine {
	h.mu.Lock()
	defer h.mu.Unlock()
	if ch, ok := h.subscribers[name]; ok {
		return ch
	}
	ch := make(chan LogLine, bufSize)
	h.subscribers[name] = ch
	return ch
}

// Unsubscribe removes a named subscriber and closes its channel. Used by
// daemon.Reload when a rule is removed from config — the rule's goroutine
// sees the channel close (its `range in` loop terminates) and the source's
// Broadcast no longer publishes to a dead consumer.
//
// Safe to call on an unknown name (no-op) and on an already-removed
// subscriber (no double-close — we check membership before closing).
func (h *Hub) Unsubscribe(name string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if ch, ok := h.subscribers[name]; ok {
		delete(h.subscribers, name)
		close(ch)
	}
}

// Broadcast delivers line to every subscriber. If a subscriber's buffer is
// full the line is dropped for that subscriber (logged by caller if desired).
// Returns the number of subscribers that received the line.
func (h *Hub) Broadcast(line LogLine) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return 0
	}
	delivered := 0
	for _, ch := range h.subscribers {
		select {
		case ch <- line:
			delivered++
		default:
			// drop on full buffer; better than blocking the producer
		}
	}
	return delivered
}

// Close closes all subscriber channels.
func (h *Hub) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return
	}
	h.closed = true
	for _, ch := range h.subscribers {
		close(ch)
	}
}

// SubscriberCount returns the number of currently-registered subscribers.
func (h *Hub) SubscriberCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subscribers)
}
