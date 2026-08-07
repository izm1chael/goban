package datepattern

import "testing"

func FuzzResolveNeverPanics(f *testing.F) {
	for _, seed := range []string{"sshd", "rfc3339", "2006-01-02T15:04:05", "", "\x00\xff"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, spec string) { _, _ = Resolve(spec) })
}
