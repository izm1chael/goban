package matcher

import "testing"

func FuzzMatcherNeverPanics(f *testing.F) {
	m, err := New(`(?:from (?P<ip>[0-9.]+)|"ClientHost":"(?P<ip>[^"]+)")`)
	if err != nil {
		f.Fatal(err)
	}
	for _, seed := range []string{
		"Failed password from 198.51.100.9",
		`{"ClientHost":"2001:db8::1"}`,
		"\x00\xff malformed [::",
		string(make([]byte, 64*1024)),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, line string) {
		_, _, _ = m.Match(line)
		_ = m.Capture("ip", line)
		_, _ = m.CaptureAddr("ip", line)
	})
}
