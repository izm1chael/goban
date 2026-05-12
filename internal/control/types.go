// Package control defines the JSON shapes shared between the daemon's
// unix-socket HTTP server and goban-client.
package control

import "time"

// StatusResp is returned by GET /status.
type StatusResp struct {
	Version    string    `json:"version"`
	Uptime     string    `json:"uptime"`
	StartedAt  time.Time `json:"started_at"`
	Watchers   int       `json:"watchers"`
	TotalBans  int       `json:"total_bans"`
	NumRules   int       `json:"num_rules"`
	NumSources int       `json:"num_sources"`
}

// RuleInfo is one entry in GET /rules.
type RuleInfo struct {
	Name       string         `json:"name"`
	Source     string         `json:"source"`
	Regex      string         `json:"regex,omitempty"`
	Threshold  int            `json:"threshold"`
	FindTime   time.Duration  `json:"findtime"`
	BanTime    time.Duration  `json:"bantime"`
	Tracked    int            `json:"tracked"`
	Hits       uint64         `json:"hits"`
	Bans       uint64         `json:"bans"`
	Misses     uint64         `json:"misses"`
	Strikes    map[string]int `json:"strikes,omitempty"`
}

// BanInfo is one entry in GET /banned.
type BanInfo struct {
	IP        string        `json:"ip"`
	Rule      string        `json:"rule,omitempty"`
	TTL       time.Duration `json:"ttl,omitempty"`
	ExpiresAt time.Time     `json:"expires_at,omitempty"`
}

// UnbanReq is the body of POST /unban.
type UnbanReq struct {
	IP string `json:"ip"`
}

// BanReq is the body of POST /ban.
type BanReq struct {
	IP   string        `json:"ip"`
	Rule string        `json:"rule"`
	TTL  time.Duration `json:"ttl"`
}

// ErrorResp wraps an error message in a uniform shape.
type ErrorResp struct {
	Error string `json:"error"`
}
