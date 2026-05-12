package datepattern

import (
	"strings"
	"testing"
	"time"
)

func TestResolvePresets(t *testing.T) {
	t.Parallel()
	cases := []struct {
		spec   string
		sample string // a sample string that should parse with the resolved layout
	}{
		{"iso8601", "2024-11-05T14:30:00"},
		{"ISO8601", "2024-11-05T14:30:00"}, // case-insensitive
		{"rfc3339", "2024-11-05T14:30:00Z"},
		{"sshd", "Nov  5 14:30:00"}, // single-digit day padded
		{"syslog_traditional", "Nov 25 14:30:00"},
		{"nginx_combined", "05/Nov/2024:14:30:00 +0000"},
		{"apache_combined", "05/Nov/2024:14:30:00 -0500"},
	}
	for _, tc := range cases {
		t.Run(tc.spec, func(t *testing.T) {
			layout, err := Resolve(tc.spec)
			if err != nil {
				t.Fatalf("Resolve(%q): unexpected error: %v", tc.spec, err)
			}
			if layout == "" {
				t.Fatalf("Resolve(%q): empty layout", tc.spec)
			}
			if _, err := time.Parse(layout, tc.sample); err != nil {
				t.Fatalf("Resolve(%q)=%q failed to parse %q: %v", tc.spec, layout, tc.sample, err)
			}
		})
	}
}

func TestResolveRawLayout(t *testing.T) {
	t.Parallel()
	custom := "2006-01-02 15:04:05.000"
	got, err := Resolve(custom)
	if err != nil {
		t.Fatalf("Resolve(custom): %v", err)
	}
	if got != custom {
		t.Fatalf("Resolve(custom)=%q, want %q", got, custom)
	}
	// And it actually parses
	if _, err := time.Parse(got, "2024-11-05 14:30:00.123"); err != nil {
		t.Fatalf("custom layout failed: %v", err)
	}
}

func TestResolveEmpty(t *testing.T) {
	t.Parallel()
	layout, err := Resolve("")
	if err != nil {
		t.Fatalf("Resolve(\"\"): unexpected error: %v", err)
	}
	if layout != "" {
		t.Fatalf("Resolve(\"\")=%q, want empty", layout)
	}
}

func TestResolveUnknown(t *testing.T) {
	t.Parallel()
	_, err := Resolve("no-such-preset")
	if err == nil {
		t.Fatal("Resolve(invalid): want error, got nil")
	}
	// Error message lists the available presets so misconfig is debuggable.
	for _, p := range []string{"iso8601", "sshd", "nginx_combined"} {
		if !strings.Contains(err.Error(), p) {
			t.Errorf("Resolve(invalid) error missing preset %q: %v", p, err)
		}
	}
}

func TestPresetsStable(t *testing.T) {
	t.Parallel()
	a := Presets()
	b := Presets()
	if len(a) != len(b) {
		t.Fatalf("Presets() returned different lengths: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("Presets() not stable at %d: %q vs %q", i, a[i], b[i])
		}
	}
}
