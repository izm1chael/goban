package procinfo

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status")
	data := "Name:\tgoban\nUid:\t123\t123\t123\t123\nGid:\t456\t456\t456\t456\nCapEff:\t0000000000000000\nCapBnd:\t0000000000001000\nCapAmb:\t0000000000001000\nNoNewPrivs:\t1\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.UID != 123 || got.GID != 456 || got.CapEff != "0000000000000000" || got.CapBnd != "0000000000001000" || got.CapAmb != "0000000000001000" || !got.NoNewPrivs {
		t.Fatalf("unexpected status: %#v", got)
	}
}

func TestReadRequiresPrivilegeFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status")
	if err := os.WriteFile(path, []byte("Uid:\t1 1 1 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(path); err == nil {
		t.Fatal("expected missing fields to fail")
	}
}
