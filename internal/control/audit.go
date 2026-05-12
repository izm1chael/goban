package control

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Audit is an append-only JSON-lines logger for administrative actions
// performed against the control plane (manual ban / unban). Writes are
// serialized by a mutex; the underlying writer is `*os.File` in production
// or a `*bytes.Buffer` in tests.
//
// Format example (one line, pretty-printed for readability):
//
//	{
//	  "time":   "2026-05-11T12:34:56.789Z",
//	  "action": "ban",
//	  "ip":     "192.0.2.99",
//	  "rule":   "manual",
//	  "ttl":    "5m0s",
//	  "source": "manual"
//	}
//
// The control server appends a line only on the SUCCESS path of /ban and
// /unban — failed attempts are deliberately not audited so the file stays
// useful as a "what was applied" timeline.
type Audit struct {
	mu sync.Mutex
	w  io.Writer
}

// AuditEvent is one entry in the audit log.
type AuditEvent struct {
	Time   time.Time `json:"time"`
	Action string    `json:"action"`
	IP     string    `json:"ip"`
	Rule   string    `json:"rule,omitempty"`
	TTL    string    `json:"ttl,omitempty"`
	Source string    `json:"source"`
}

// NewAuditFile opens (or creates) path in append mode with mode 0640.
// Parents are created with 0755. Returns a closer for callers to defer.
func NewAuditFile(path string) (*Audit, func() error, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, nil, fmt.Errorf("mkdir audit dir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, nil, fmt.Errorf("open audit file: %w", err)
	}
	return &Audit{w: f}, f.Close, nil
}

// NewAuditWriter wraps an arbitrary io.Writer (used by tests).
func NewAuditWriter(w io.Writer) *Audit { return &Audit{w: w} }

// Log appends one event as a JSON line. If the underlying writer fails the
// error is silently swallowed — audit logging must not break the control
// plane.
func (a *Audit) Log(ev AuditEvent) {
	if a == nil {
		return
	}
	if ev.Time.IsZero() {
		ev.Time = time.Now().UTC()
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	b, err := json.Marshal(ev)
	if err != nil {
		return
	}
	b = append(b, '\n')
	_, _ = a.w.Write(b)
}
