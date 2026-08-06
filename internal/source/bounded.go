package source

import (
	"bufio"
	"errors"
	"io"
	"strings"
)

// BoundedAccumulator converts arbitrary byte chunks into newline-delimited
// records while retaining at most maxLen bytes from any one record. Additional
// bytes are discarded until the delimiter, so hostile producers cannot force
// an unbounded allocation before matching.
type BoundedAccumulator struct {
	maxLen int
	buf    []byte
}

func NewBoundedAccumulator(maxLen int) *BoundedAccumulator {
	if maxLen <= 0 {
		maxLen = 16 * 1024
	}
	return &BoundedAccumulator{maxLen: maxLen, buf: make([]byte, 0, maxLen)}
}

// Feed consumes bytes and invokes emit once per complete line. Returning false
// from emit stops processing the current chunk.
func (a *BoundedAccumulator) Feed(data []byte, emit func(string) bool) bool {
	for len(data) > 0 {
		i := 0
		for i < len(data) && data[i] != '\n' {
			i++
		}
		if len(a.buf) < a.maxLen {
			remaining := a.maxLen - len(a.buf)
			take := i
			if take > remaining {
				take = remaining
			}
			a.buf = append(a.buf, data[:take]...)
		}
		if i == len(data) {
			return true
		}
		line := strings.TrimSuffix(string(a.buf), "\r")
		a.buf = a.buf[:0]
		if !emit(line) {
			return false
		}
		data = data[i+1:]
	}
	return true
}

// Flush emits a final unterminated record, if present.
func (a *BoundedAccumulator) Flush(emit func(string) bool) bool {
	if len(a.buf) == 0 {
		return true
	}
	line := strings.TrimSuffix(string(a.buf), "\r")
	a.buf = a.buf[:0]
	return emit(line)
}

// Reset discards an incomplete record, used when a followed file is
// truncated/replaced before a newline arrives.
func (a *BoundedAccumulator) Reset() { a.buf = a.buf[:0] }

// ReadBoundedLines reads newline-delimited records while retaining at most
// maxLen bytes per record. Bytes beyond maxLen are discarded until the next
// newline, preventing a hostile producer from forcing an unbounded line
// allocation before the configured matcher cap is applied.
func ReadBoundedLines(r io.Reader, maxLen int, emit func(string) bool) error {
	if maxLen <= 0 {
		maxLen = 16 * 1024
	}
	reader := bufio.NewReaderSize(r, maxLen+1)
	acc := NewBoundedAccumulator(maxLen)
	for {
		frag, err := reader.ReadSlice('\n')
		if len(frag) > 0 && !acc.Feed(frag, emit) {
			return nil
		}
		switch {
		case err == nil:
			continue
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF):
			acc.Flush(emit)
			return nil
		default:
			return err
		}
	}
}
