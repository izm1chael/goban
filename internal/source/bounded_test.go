package source

import (
	"strings"
	"testing"
)

func TestReadBoundedLinesTruncatesWithoutLosingNextLine(t *testing.T) {
	input := strings.Repeat("x", 100) + "\nsecond\n"
	var got []string
	err := ReadBoundedLines(strings.NewReader(input), 8, func(line string) bool {
		got = append(got, line)
		return true
	})
	if err != nil {
		t.Fatalf("ReadBoundedLines: %v", err)
	}
	if len(got) != 2 || got[0] != strings.Repeat("x", 8) || got[1] != "second" {
		t.Fatalf("got %#v", got)
	}
}

func TestReadBoundedLinesHandlesFinalLine(t *testing.T) {
	var got []string
	err := ReadBoundedLines(strings.NewReader("tail"), 16, func(line string) bool {
		got = append(got, line)
		return true
	})
	if err != nil || len(got) != 1 || got[0] != "tail" {
		t.Fatalf("got=%v err=%v", got, err)
	}
}

func TestBoundedAccumulatorAcrossChunks(t *testing.T) {
	acc := NewBoundedAccumulator(5)
	var got []string
	emit := func(line string) bool { got = append(got, line); return true }
	if !acc.Feed([]byte("abc"), emit) || !acc.Feed([]byte("def\nnext\n"), emit) {
		t.Fatal("Feed stopped unexpectedly")
	}
	if len(got) != 2 || got[0] != "abcde" || got[1] != "next" {
		t.Fatalf("got %#v", got)
	}
}
