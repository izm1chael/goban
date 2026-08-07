package corpus

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestManifestValidateAndFilter(t *testing.T) {
	m := &Manifest{
		Version: CurrentVersion,
		Sources: []ExternalSource{{
			ID: "upstream", Project: "example", URL: "https://example.invalid/log",
			License: "test", Redistribution: "external-only", Adapter: "plain-scan",
			FileName: "sample.log",
		}},
		Cases: []Case{
			{ID: "b", Service: "ssh", Rule: "sshd", Tags: []string{"ipv6"}, Lines: []string{"line"}},
			{ID: "a", Service: "web", Rule: "nginx", Tags: []string{"ipv4"}, Lines: []string{"line"}},
		},
	}
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	got := m.Filter("", "", "")
	if len(got) != 2 || got[0].ID != "a" || got[1].ID != "b" {
		t.Fatalf("Filter()=%v, want stable ID order", got)
	}
	if got := m.Filter("sshd", "", "ipv6"); len(got) != 1 || got[0].ID != "b" {
		t.Fatalf("rule/tag filter=%v", got)
	}
}

func TestManifestRejectsUnknownFieldsAndMultipleDocuments(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"unknown.yaml": "version: 1\nunknown: true\ncases: []\n",
		"multi.yaml":   "version: 1\ncases: []\n---\nversion: 1\ncases: []\n",
	} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil {
			t.Fatalf("Load(%s) succeeded; want strict failure", name)
		}
	}
}

func TestManifestRejectsUnsafeAndDuplicateIdentifiers(t *testing.T) {
	m := &Manifest{Version: CurrentVersion, Cases: []Case{
		{ID: "../escape", Service: "ssh", Rule: "sshd", Lines: []string{"line"}},
	}}
	if err := m.Validate(); err == nil || !strings.Contains(err.Error(), "unsupported character") {
		t.Fatalf("Validate() error=%v", err)
	}
	m.Cases = []Case{
		{ID: "same", Service: "ssh", Rule: "sshd", Lines: []string{"line"}},
		{ID: "same", Service: "ssh", Rule: "sshd", Lines: []string{"line"}},
	}
	if err := m.Validate(); err == nil || !strings.Contains(err.Error(), "duplicated") {
		t.Fatalf("Validate() error=%v", err)
	}
}
