// Package control defines the JSON shapes shared between the daemon's
// unix-socket HTTP server and goban-client.
package control

import "time"

// StatusResp is returned by GET /status.
type StatusResp struct {
	Version         string    `json:"version"`
	Uptime          string    `json:"uptime"`
	StartedAt       time.Time `json:"started_at"`
	Watchers        int       `json:"watchers"`
	TotalBans       int       `json:"total_bans"`
	NumRules        int       `json:"num_rules"`
	NumSources      int       `json:"num_sources"`
	DegradedSources int       `json:"degraded_sources"`
	DroppedLines    uint64    `json:"dropped_lines"`
	MemoryBytes     uint64    `json:"memory_bytes"`
	Goroutines      int       `json:"goroutines"`
	BannerError     string    `json:"banner_error,omitempty"`
}

// SourceInfo is one entry in GET /sources.
type SourceInfo struct {
	Name          string    `json:"name"`
	Status        string    `json:"status"`
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

// RuleInfo is one entry in GET /rules. It intentionally includes the full
// effective processing configuration so goban-client test can exercise the
// same rule pipeline as the daemon.
type RuleInfo struct {
	Name                string            `json:"name"`
	Source              string            `json:"source"`
	Regex               string            `json:"regex,omitempty"`
	Threshold           int               `json:"threshold"`
	FindTime            time.Duration     `json:"findtime"`
	BanTime             time.Duration     `json:"bantime"`
	Datepattern         string            `json:"datepattern,omitempty"`
	Timezone            string            `json:"timezone,omitempty"`
	DateFailurePolicy   string            `json:"date_failure_policy,omitempty"`
	Excludes            map[string]string `json:"excludes,omitempty"`
	Allowlist           []string          `json:"allowlist,omitempty"`
	GlobalAllowlist     []string          `json:"global_allowlist,omitempty"`
	TrustedProxyCapture string            `json:"trusted_proxy_capture,omitempty"`
	TrustedProxies      []string          `json:"trusted_proxies,omitempty"`
	Tracked             int               `json:"tracked"`
	Hits                uint64            `json:"hits"`
	Bans                uint64            `json:"bans"`
	Misses              uint64            `json:"misses"`
	DateParseFails      uint64            `json:"date_parse_fails"`
	DateDriftFallbacks  uint64            `json:"date_drift_fallbacks"`
	DateDrops           uint64            `json:"date_drops"`
	Strikes             map[string]int    `json:"strikes,omitempty"`
}

// BanInfo is one entry in GET /banned.
type BanInfo struct {
	DecisionID    string        `json:"decision_id,omitempty"`
	IP            string        `json:"ip"`
	Rule          string        `json:"rule,omitempty"`
	Source        string        `json:"source,omitempty"`
	Origin        string        `json:"origin,omitempty"`
	BannedAt      time.Time     `json:"banned_at,omitempty"`
	TTL           time.Duration `json:"ttl,omitempty"`
	ExpiresAt     time.Time     `json:"expires_at,omitempty"`
	EvidenceCount int           `json:"evidence_count,omitempty"`
	FirstSeen     time.Time     `json:"first_seen,omitempty"`
	LastSeen      time.Time     `json:"last_seen,omitempty"`
}

// DoctorCheck is one operator-facing verification result. Status is pass,
// warn, fail, or skip.
type DoctorCheck struct {
	Name        string `json:"name"`
	Status      string `json:"status"`
	Detail      string `json:"detail"`
	Remediation string `json:"remediation,omitempty"`
}

// DoctorResp is returned by POST /doctor. Overall is healthy, degraded, or
// not_enforcing.
type DoctorResp struct {
	Overall   string        `json:"overall"`
	CheckedAt time.Time     `json:"checked_at"`
	Checks    []DoctorCheck `json:"checks"`
}

type DoctorReq struct {
	Probe   bool   `json:"probe"`
	ProbeIP string `json:"probe_ip,omitempty"`
}

type UnbanReq struct {
	IP string `json:"ip"`
}
type BanReq struct {
	IP   string        `json:"ip"`
	Rule string        `json:"rule"`
	TTL  time.Duration `json:"ttl"`
}
type ErrorResp struct {
	Error string `json:"error"`
}
