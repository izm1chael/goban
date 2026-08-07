package corpus

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/izm1chael/goban/internal/matcher"
)

func TestParseFail2Ban(t *testing.T) {
	input := strings.NewReader(`# comment
# failJSON: {"match": true, "host": "198.51.100.8"}
Aug  6 host sshd[1]: Failed password for root from 198.51.100.8 port 22 ssh2
# failJSON: {"match": false}
Aug  6 host sshd[1]: Accepted publickey for root from 198.51.100.9 port 22 ssh2
unannotated line
`)
	cases, unannotated, err := ParseFail2Ban(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) != 2 || !cases[0].WantMatch || cases[1].WantMatch {
		t.Fatalf("cases=%+v", cases)
	}
	if unannotated != 1 {
		t.Fatalf("unannotated=%d, want 1", unannotated)
	}
}

func TestCompareFail2Ban(t *testing.T) {
	path := t.TempDir() + "/annotated.log"
	body := `# failJSON: {"match": true, "host": "198.51.100.8"}
Failed password for root from 198.51.100.8
# failJSON: {"match": false}
Accepted password for root from 198.51.100.8
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := matcher.New(`^Failed password for \S+ from (?P<ip>\S+)$`)
	if err != nil {
		t.Fatal(err)
	}
	report, err := CompareFail2Ban(path, m)
	if err != nil {
		t.Fatal(err)
	}
	if report.TruePositive != 1 || report.TrueNegative != 1 || report.FalsePositive != 0 || report.FalseNegative != 0 {
		t.Fatalf("report=%+v", report)
	}
}

func TestFetchIsBounded(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("0123456789"))
	}))
	defer server.Close()
	src := ExternalSource{ID: "sample", URL: server.URL, FileName: "sample.log", MaxBytes: 5, License: "test"}
	if _, err := Fetch(context.Background(), server.Client(), src, t.TempDir()); err == nil {
		t.Fatal("Fetch succeeded beyond max_bytes")
	}
}
