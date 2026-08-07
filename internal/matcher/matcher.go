// Package matcher extracts banned-candidate IPs (and optional timestamps and
// arbitrary named captures) from log lines using a pre-compiled regex. The
// regex must contain at least one named capture group (?P<ip>...); an optional
// (?P<time>...) is also extracted so the rule processor can use it as the
// strike-window event time instead of wall-clock.
package matcher

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// Matcher pairs a compiled regex with all indexes for its named capture
// groups. Go's regexp package permits the same name in multiple alternation
// branches. Supporting every participating index lets one rule safely handle
// field-order variants such as structured JSON logs without broad .* hacks or
// duplicate runtime rules.
type Matcher struct {
	re       *regexp.Regexp
	captures map[string][]int
}

// New compiles pattern and verifies it contains an "ip" named capture. A
// "time" named capture is optional. Duplicate named groups are accepted and
// resolved by selecting the first group that participated in the match.
func New(pattern string) (*Matcher, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("compile regex: %w", err)
	}
	captures := make(map[string][]int)
	for i, name := range re.SubexpNames() {
		if name != "" {
			captures[name] = append(captures[name], i)
		}
	}
	if len(captures["ip"]) == 0 {
		return nil, fmt.Errorf("regex %q lacks (?P<ip>...) named capture", pattern)
	}
	return &Matcher{re: re, captures: captures}, nil
}

// Match runs the regex against line and returns the parsed netip.Addr, the raw
// timestamp string captured by the first participating (?P<time>...) group if
// present, and whether the regex matched and an "ip" capture parsed as an IP.
func (m *Matcher) Match(line string) (netip.Addr, string, bool) {
	idx := m.re.FindStringSubmatchIndex(line)
	if idx == nil {
		return netip.Addr{}, "", false
	}
	var addr netip.Addr
	found := false
	for _, captureIndex := range m.captures["ip"] {
		if candidate, ok := extractIP(line, idx, captureIndex); ok {
			addr, found = candidate, true
			break
		}
	}
	if !found {
		return netip.Addr{}, "", false
	}
	timeStr := ""
	for _, captureIndex := range m.captures["time"] {
		if value := extractString(line, idx, captureIndex); value != "" {
			timeStr = value
			break
		}
	}
	return addr, timeStr, true
}

// Capture returns the first participating substring captured by the named
// group in line. This supports duplicate group names in regex alternations.
func (m *Matcher) Capture(name string, line string) string {
	idx := m.re.FindStringSubmatchIndex(line)
	if idx == nil {
		return ""
	}
	for _, captureIndex := range m.captures[name] {
		if value := extractString(line, idx, captureIndex); value != "" {
			return value
		}
	}
	return ""
}

// extractIP pulls the IP at capture index i out of the regex's index pairs.
func extractIP(line string, idx []int, i int) (netip.Addr, bool) {
	if i*2+1 >= len(idx) {
		return netip.Addr{}, false
	}
	start, end := idx[i*2], idx[i*2+1]
	if start < 0 || end < 0 || end > len(line) {
		return netip.Addr{}, false
	}
	return parseCapturedAddr(line[start:end])
}

// CaptureAddr parses a named capture as an IP address. Plain IPv4/IPv6,
// bracketed IPv6, and IP:port forms are accepted so a trusted reverse-proxy
// peer can be validated without trusting a spoofable forwarded header alone.
func (m *Matcher) CaptureAddr(name, line string) (netip.Addr, bool) {
	raw := m.Capture(name, line)
	if raw == "" {
		return netip.Addr{}, false
	}
	return parseCapturedAddr(raw)
}

func parseCapturedAddr(raw string) (netip.Addr, bool) {
	raw = strings.TrimSpace(raw)
	if addr, err := netip.ParseAddr(strings.Trim(raw, "[]")); err == nil {
		return addr.Unmap(), true
	}
	if ap, err := netip.ParseAddrPort(raw); err == nil {
		return ap.Addr().Unmap(), true
	}
	return netip.Addr{}, false
}

// extractString pulls the substring at capture index i out of the regex's
// index pairs. Returns "" when the capture is absent or the index is invalid.
func extractString(line string, idx []int, i int) string {
	if i*2+1 >= len(idx) {
		return ""
	}
	start, end := idx[i*2], idx[i*2+1]
	if start < 0 || end < 0 || end > len(line) {
		return ""
	}
	return line[start:end]
}

// HasCapture reports whether the compiled expression contains a named group.
func (m *Matcher) HasCapture(name string) bool { return len(m.captures[name]) > 0 }

// String returns the source pattern (useful for logs).
func (m *Matcher) String() string { return m.re.String() }
