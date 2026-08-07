// Package enforcerproto defines the deliberately small wire contract between
// the unprivileged GoBan daemon and the privileged firewall enforcer.
package enforcerproto

import "time"

const Version = 1

type HealthResp struct {
	Protocol          int    `json:"protocol"`
	Backend           string `json:"backend"`
	Ready             bool   `json:"ready"`
	PolicyFingerprint string `json:"policy_fingerprint"`
	UID               int    `json:"uid"`
	GID               int    `json:"gid"`
	CapEff            string `json:"cap_eff"`
	CapBnd            string `json:"cap_bnd"`
	CapAmb            string `json:"cap_amb"`
	NoNewPrivs        bool   `json:"no_new_privs"`
}

type ReloadPolicyRequest struct {
	ExpectedFingerprint string `json:"expected_fingerprint"`
}

type ReloadPolicyResp struct {
	Fingerprint string `json:"fingerprint"`
}

type BanRequest struct {
	IP   string        `json:"ip"`
	Rule string        `json:"rule"`
	TTL  time.Duration `json:"ttl"`
}

type BanBatchRequest struct {
	Bans []BanRequest `json:"bans"`
}

type UnbanRequest struct {
	IP string `json:"ip"`
}

type CloseRequest struct {
	Flush bool `json:"flush"`
}

type BanInfo struct {
	IP        string        `json:"ip"`
	Rule      string        `json:"rule,omitempty"`
	BannedAt  time.Time     `json:"banned_at,omitempty"`
	ExpiresAt time.Time     `json:"expires_at,omitempty"`
	TTL       time.Duration `json:"ttl,omitempty"`
}

type Diagnostic struct {
	Name        string `json:"name"`
	Status      string `json:"status"`
	Detail      string `json:"detail"`
	Remediation string `json:"remediation,omitempty"`
}

type ErrorResp struct {
	Error string `json:"error"`
}
