package migrate

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/izm1chael/goban/internal/config"
)

func TestParseF2BDuration(t *testing.T) {
	cases := map[string]time.Duration{"600": 10 * time.Minute, "10m": 10 * time.Minute, "2h": 2 * time.Hour, "2d": 48 * time.Hour, "1w": 168 * time.Hour}
	for input, want := range cases {
		got, err := parseF2BDuration(input)
		if err != nil || got != want {
			t.Fatalf("%s: got %s err=%v want %s", input, got, err, want)
		}
	}
}

func TestMergeINIOverrideOrder(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "jail.local")
	if err := os.WriteFile(path, []byte("[DEFAULT]\nbantime=1h\n[sshd]\nenabled=true\nmaxretry=3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := ini{Defaults: section{}, Sections: map[string]section{}}
	if err := mergeINIFile(path, &out); err != nil {
		t.Fatal(err)
	}
	values := overlay(out.Defaults, out.Sections["sshd"])
	if values["bantime"] != "1h" || values["maxretry"] != "3" {
		t.Fatalf("unexpected values: %#v", values)
	}
}

func TestConvertWritesValidStagingConfig(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "jail.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	data := `[DEFAULT]
bantime = 2h
findtime = 10m
ignoreip = 127.0.0.1 192.0.2.0/24 admin.example

[sshd]
enabled = true
backend = systemd
maxretry = 4

[custom-app]
enabled = true
logpath = /var/log/custom.log
`
	if err := os.WriteFile(filepath.Join(root, "jail.local"), []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "migration")
	report, err := Convert(Options{Root: root, OutputDir: out, RulesAvailable: filepath.Join("..", "..", "examples", "rules.d")})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Jails) != 2 {
		t.Fatalf("unexpected report: %#v", report)
	}
	if _, err := os.Stat(filepath.Join(out, "rules.d", "sshd.yaml")); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadEffective(filepath.Join(out, "goban.yaml"), filepath.Join(out, "rules.d"))
	if err != nil {
		t.Fatalf("generated configuration invalid: %v", err)
	}
	if len(cfg.Rules) != 1 || cfg.Rules[0].MaxRetries != 4 || cfg.Rules[0].BanTime != 2*time.Hour {
		t.Fatalf("unexpected migrated rule: %#v", cfg.Rules)
	}
}
