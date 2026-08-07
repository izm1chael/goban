package corpus

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/izm1chael/goban/internal/config"
)

func TestRepositoryCorpus(t *testing.T) {
	root := filepath.Join("..", "..")
	manifest, err := Load(filepath.Join(root, "testdata", "corpus", "manifest.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	rules, err := config.LoadRulesDir(filepath.Join(root, "examples", "rules.d"))
	if err != nil {
		t.Fatal(err)
	}
	report := Run(context.Background(), manifest, rules, Options{Now: time.Date(2026, 8, 6, 19, 0, 0, 0, time.UTC)})
	for _, result := range report.Results {
		if !result.Passed {
			t.Errorf("%s (%s): %v", result.ID, result.Rule, result.Errors)
		}
	}
	if report.Total < 90 {
		t.Fatalf("corpus has only %d cases; want at least 90", report.Total)
	}
	if report.Failed != 0 {
		t.Fatalf("corpus failed %d/%d cases", report.Failed, report.Total)
	}
}
