// Package matcher extracts banned-candidate IPs (and optional timestamps and
// arbitrary named captures) from log lines using a pre-compiled regex. The
// regex must contain a named capture group (?P<ip>...); an optional
// (?P<time>...) is also extracted so the rule processor can use it as the
// strike-window event time instead of wall-clock.
package matcher

import (
	"fmt"
	"net/netip"
	"regexp"
)

// Matcher pairs a compiled regex with the index of its "ip" capture group and,
// optionally, the index of its "time" capture group.
type Matcher struct {
	re        *regexp.Regexp
	ipIndex   int
	timeIndex int // -1 when the regex has no (?P<time>...) capture
}

// New compiles pattern and verifies it contains an "ip" named capture.
// A "time" named capture is optional.
func New(pattern string) (*Matcher, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("compile regex: %w", err)
	}
	ipIdx, timeIdx := -1, -1
	for i, name := range re.SubexpNames() {
		switch name {
		case "ip":
			ipIdx = i
		case "time":
			timeIdx = i
		}
	}
	if ipIdx == -1 {
		return nil, fmt.Errorf("regex %q lacks (?P<ip>...) named capture", pattern)
	}
	return &Matcher{re: re, ipIndex: ipIdx, timeIndex: timeIdx}, nil
}

// Match runs the regex against line and returns the parsed netip.Addr, the
// raw timestamp string captured by (?P<time>...) if present (empty otherwise),
// and a boolean indicating whether the regex matched and the "ip" capture
// could be parsed as an IP.
//
// Uses FindStringSubmatchIndex (returns one []int) rather than
// FindStringSubmatch (returns []string + per-capture substrings). Saves
// N-1 substring allocations per matched line — meaningful at high rates.
func (m *Matcher) Match(line string) (netip.Addr, string, bool) {
	idx := m.re.FindStringSubmatchIndex(line)
	if idx == nil {
		return netip.Addr{}, "", false
	}
	addr, ok := extractIP(line, idx, m.ipIndex)
	if !ok {
		return netip.Addr{}, "", false
	}
	timeStr := ""
	if m.timeIndex >= 0 {
		timeStr = extractString(line, idx, m.timeIndex)
	}
	return addr, timeStr, true
}

// Capture returns the substring captured by the named group `name` in line, or
// "" if name doesn't refer to a known capture or the regex doesn't match.
//
// Runs the regex a second time on the caller's behalf — only used on the
// excludes post-match filter path, which fires at most once per matched line
// (i.e. far below the rule's hit rate). For the hot path use Match.
func (m *Matcher) Capture(name string, line string) string {
	idx := m.re.FindStringSubmatchIndex(line)
	if idx == nil {
		return ""
	}
	for i, n := range m.re.SubexpNames() {
		if n == name {
			return extractString(line, idx, i)
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
	addr, err := netip.ParseAddr(line[start:end])
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

// extractString pulls the substring at capture index i out of the regex's
// index pairs. Returns "" when the capture is absent (i.e. didn't participate
// in the match) or the index is out of range.
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

// String returns the source pattern (useful for logs).
func (m *Matcher) String() string {
	return m.re.String()
}
