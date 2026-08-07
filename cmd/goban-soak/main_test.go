package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/izm1chael/goban/internal/control"
)

func TestAggregateFailsOnDroppedLines(t *testing.T) {
	dir := t.TempDir()
	f, err := os.Create(filepath.Join(dir, "samples.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for i, dropped := range []uint64{2, 5} {
		s := sample{Time: time.Unix(int64(i), 0).UTC(), Status: &control.StatusResp{DroppedLines: dropped, MemoryBytes: 100 + uint64(i), Goroutines: 5}, Doctor: &control.DoctorResp{Overall: "healthy"}}
		if err := json.NewEncoder(f).Encode(s); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	rep, err := aggregate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Verdict != "FAIL" || rep.DroppedLinesDelta != 3 {
		t.Fatalf("unexpected report: %#v", rep)
	}
}
