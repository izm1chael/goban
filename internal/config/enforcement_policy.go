package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"sort"
)

// EnforcementPolicyFingerprint identifies the allowlist semantics that the
// privileged enforcer must independently enforce. It deliberately excludes
// ordinary detection fields: only policy that can make a target protected or
// unprotected belongs in this digest.
func EnforcementPolicyFingerprint(cfg *Config) string {
	if cfg == nil {
		return ""
	}
	type rulePolicy struct {
		Name      string   `json:"name"`
		Allowlist []string `json:"allowlist"`
	}
	type policyView struct {
		Global []string     `json:"global"`
		Rules  []rulePolicy `json:"rules"`
	}
	view := policyView{Global: canonicalPolicyCIDRs(cfg.Allowlist)}
	for _, rule := range cfg.Rules {
		if len(rule.Allowlist) == 0 {
			continue
		}
		view.Rules = append(view.Rules, rulePolicy{Name: rule.Name, Allowlist: canonicalPolicyCIDRs(rule.Allowlist)})
	}
	sort.Slice(view.Rules, func(i, j int) bool { return view.Rules[i].Name < view.Rules[j].Name })
	data, _ := json.Marshal(view)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func canonicalPolicyCIDRs(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, raw := range values {
		value := raw
		if p, err := netip.ParsePrefix(raw); err == nil {
			value = p.Masked().String()
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
