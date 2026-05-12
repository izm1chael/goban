package matcher

import "testing"

func TestNew_RejectsRegexWithoutIPCapture(t *testing.T) {
	if _, err := New(`Failed password from (\S+)`); err == nil {
		t.Fatal("expected error for regex without (?P<ip>...) capture")
	}
}

func TestNew_RejectsInvalidRegex(t *testing.T) {
	if _, err := New(`(?P<ip>`); err == nil {
		t.Fatal("expected error for malformed regex")
	}
}

func TestMatch(t *testing.T) {
	cases := map[string]struct {
		pattern  string
		line     string
		wantIP   string
		wantTime string
		wantOK   bool
	}{
		"sshd_invalid_user": {
			pattern: `Failed password for (?:invalid user )?\S+ from (?P<ip>\S+) port`,
			line:    "Jan  1 12:00:00 host sshd[123]: Failed password for invalid user bob from 1.2.3.4 port 22 ssh2",
			wantIP:  "1.2.3.4", wantOK: true,
		},
		"sshd_valid_user": {
			pattern: `Failed password for (?:invalid user )?\S+ from (?P<ip>\S+) port`,
			line:    "Jan  1 12:00:00 host sshd[123]: Failed password for alice from 198.51.100.7 port 51324 ssh2",
			wantIP:  "198.51.100.7", wantOK: true,
		},
		"ipv6": {
			pattern: `from (?P<ip>\S+) port`,
			line:    "... from 2001:db8::1 port 1234",
			wantIP:  "2001:db8::1", wantOK: true,
		},
		"ipv4_mapped_ipv6_unmapped_to_v4": {
			pattern: `from (?P<ip>\S+) port`,
			line:    "... from ::ffff:1.2.3.4 port 1234",
			wantIP:  "1.2.3.4", wantOK: true,
		},
		"no_match": {
			pattern: `Failed password.*from (?P<ip>\S+)`,
			line:    "Accepted publickey for alice",
			wantOK:  false,
		},
		"unparseable_ip": {
			pattern: `from (?P<ip>\S+)`,
			line:    "... from notanip port",
			wantOK:  false,
		},
		"nextcloud": {
			pattern: `Login failed: .* Remote IP: (?P<ip>[^"\s]+)`,
			line:    `{"app":"core","msg":"Login failed: alice Remote IP: 203.0.113.7","level":"warn"}`,
			wantIP:  "203.0.113.7", wantOK: true,
		},
		"with_time_capture": {
			pattern:  `^(?P<time>\S+) .* from (?P<ip>\S+) port`,
			line:     "2024-11-05T14:30:00 sshd[1]: Failed password for invalid user bob from 198.51.100.7 port 22 ssh2",
			wantIP:   "198.51.100.7",
			wantTime: "2024-11-05T14:30:00",
			wantOK:   true,
		},
		"nginx_with_time_and_ip": {
			pattern:  `^(?P<ip>\S+) - - \[(?P<time>[^\]]+)\]`,
			line:     `203.0.113.7 - - [05/Nov/2024:14:30:00 +0000] "GET / HTTP/1.1" 401 ...`,
			wantIP:   "203.0.113.7",
			wantTime: "05/Nov/2024:14:30:00 +0000",
			wantOK:   true,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			m, err := New(tc.pattern)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			got, gotTime, ok := m.Match(tc.line)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (got=%q)", ok, tc.wantOK, got)
			}
			if !ok {
				return
			}
			if got.String() != tc.wantIP {
				t.Errorf("ip = %q, want %q", got.String(), tc.wantIP)
			}
			if gotTime != tc.wantTime {
				t.Errorf("time = %q, want %q", gotTime, tc.wantTime)
			}
		})
	}
}

func TestCapture(t *testing.T) {
	m, err := New(`"event":"(?P<event>[^"]+)".*"rule":"(?P<rule>[^"]+)".*"ip":"(?P<ip>[^"]+)"`)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	line := `{"time":"...","event":"ban","rule":"sshd","ip":"198.51.100.7","ttl":"1h"}`
	if got := m.Capture("event", line); got != "ban" {
		t.Errorf("Capture(event) = %q, want %q", got, "ban")
	}
	if got := m.Capture("rule", line); got != "sshd" {
		t.Errorf("Capture(rule) = %q, want %q", got, "sshd")
	}
	if got := m.Capture("ip", line); got != "198.51.100.7" {
		t.Errorf("Capture(ip) = %q, want %q", got, "198.51.100.7")
	}
	if got := m.Capture("unknown", line); got != "" {
		t.Errorf("Capture(unknown) = %q, want empty", got)
	}
	if got := m.Capture("event", "no match here"); got != "" {
		t.Errorf("Capture on non-matching line = %q, want empty", got)
	}
}
