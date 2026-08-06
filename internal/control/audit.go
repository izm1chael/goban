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

// Audit is an append-only JSON-lines logger for confirmed automatic and
// manual ban/unban actions. Writes are
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
// The daemon appends a line only after a successful firewall operation;
// failed attempts are deliberately not audited so the file remains an
// accurate "what was applied" timeline.
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

// Log appends one event as a JSON line. Audit failure never rolls back an
// already-confirmed firewall operation, but it is returned so the daemon can
// surface degraded recidive/forensics coverage instead of failing silently.
func (a *Audit) Log(ev AuditEvent) error {
	if a == nil {
		return nil
	}
	if ev.Time.IsZero() {
		ev.Time = time.Now().UTC()
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	n, err := a.w.Write(b)
	if err != nil {
		return err
	}
	if n != len(b) {
		return io.ErrShortWrite
	}
	return nil
}
