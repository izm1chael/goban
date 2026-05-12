// Package datepattern translates GoBan's `datepattern:` rule field into a Go
// time-layout string. Operators write either a named preset (sshd, iso8601,
// rfc3339, etc.) for ergonomics or a raw Go layout literal for anything
// custom. Resolve does the dispatch and is intentionally tiny — the bulk of
// date handling lives in the rule processor.
//
// Recognised presets cover the log formats GoBan's bundled rule library
// targets. New presets are cheap to add but they should reflect real-world
// log shapes, not theoretical ones — every preset is a maintenance commitment.
package datepattern

import (
	"fmt"
	"strings"
	"time"
)

// presets maps a preset name to its Go time-layout string. The layouts use
// Go's reference time (Mon Jan 2 15:04:05 MST 2006) — see time.Parse.
var presets = map[string]string{
	"iso8601":            "2006-01-02T15:04:05",
	"rfc3339":            time.RFC3339,
	"sshd":               "Jan _2 15:04:05",
	"syslog_traditional": "Jan _2 15:04:05",
	"nginx_combined":     "02/Jan/2006:15:04:05 -0700",
	"apache_combined":    "02/Jan/2006:15:04:05 -0700",
}

// Presets returns the recognised preset names, sorted for documentation use.
// Returned slice is a copy; callers may mutate it freely.
func Presets() []string {
	out := make([]string, 0, len(presets))
	for k := range presets {
		out = append(out, k)
	}
	// stable order so error messages are predictable
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

// Resolve returns the Go time layout corresponding to spec. spec may be:
//
//   - a recognised preset name (case-insensitive) — returns the canonical layout
//   - a raw Go layout literal containing the reference year "2006" — returned as-is
//
// Anything else returns an error. The "contains 2006" heuristic is how Go's
// own time package identifies a layout, so accepting it here keeps the
// ergonomic story consistent: if it parses with time.Parse it'll work as a
// datepattern.
func Resolve(spec string) (string, error) {
	if spec == "" {
		return "", nil
	}
	if layout, ok := presets[strings.ToLower(spec)]; ok {
		return layout, nil
	}
	if strings.Contains(spec, "2006") {
		return spec, nil
	}
	return "", fmt.Errorf("datepattern %q: not a known preset and not a Go time layout (must reference year 2006); known presets: %v",
		spec, Presets())
}
