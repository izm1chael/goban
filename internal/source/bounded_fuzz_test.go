package source

import "testing"

func FuzzBoundedAccumulatorNeverExceedsLimit(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte("normal line\nnext\n"),
		[]byte("\x00\xff\xfe\n"),
		[]byte(string(make([]byte, 64*1024)) + "\n"),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		const limit = 1024
		a := NewBoundedAccumulator(limit)
		a.Feed(data, func(line string) bool {
			if len(line) > limit {
				t.Fatalf("line len=%d > %d", len(line), limit)
			}
			return true
		})
		a.Flush(func(line string) bool {
			if len(line) > limit {
				t.Fatalf("flush len=%d > %d", len(line), limit)
			}
			return true
		})
		if len(a.buf) > limit {
			t.Fatalf("buffer len=%d > %d", len(a.buf), limit)
		}
	})
}
