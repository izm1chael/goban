package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadEffectiveAndHumanDurations(t *testing.T) {
	dir := t.TempDir()
	rules := filepath.Join(dir, "rules.d")
	if err := os.Mkdir(rules, 0o755); err != nil {
		t.Fatal(err)
	}
	main := filepath.Join(dir, "goban.yaml")
	if err := os.WriteFile(main, []byte(`
sock_path: /tmp/goban.sock
rules_dir: `+rules+`
sources:
  - type: file
    name: auth
    path: /tmp/auth.log
rules: []
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rules, "sshd.yaml"), []byte(`
- name: sshd
  source: auth
  regex: 'from (?P<ip>\S+)'
  max_retries: 3
  findtime: 10m
  bantime: 24h
`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadEffective(main, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Rules) != 1 || cfg.Rules[0].Name != "sshd" {
		t.Fatalf("rules=%+v", cfg.Rules)
	}
	out, err := EffectiveYAML(cfg)
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	if !strings.Contains(text, "findtime: 10m0s") || !strings.Contains(text, "bantime: 24h0m0s") {
		t.Fatalf("effective YAML did not preserve human durations:\n%s", text)
	}
}
