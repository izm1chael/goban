package corpus

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestGenerateIsDeterministic(t *testing.T) {
	dir := t.TempDir()
	one := filepath.Join(dir, "one.log")
	two := filepath.Join(dir, "two.log")
	r1, err := Generate(GenerateOptions{Output: one, Lines: 500, Seed: 42, Profile: "mixed"})
	if err != nil {
		t.Fatal(err)
	}
	r2, err := Generate(GenerateOptions{Output: two, Lines: 500, Seed: 42, Profile: "mixed"})
	if err != nil {
		t.Fatal(err)
	}
	b1, _ := os.ReadFile(one)
	b2, _ := os.ReadFile(two)
	if !bytes.Equal(b1, b2) {
		t.Fatal("same seed generated different corpus bytes")
	}
	if !reflect.DeepEqual(r1.Expected, r2.Expected) || r1.Lines != 500 {
		t.Fatalf("reports differ: %+v %+v", r1, r2)
	}
}

func TestGenerateRejectsUnknownProfile(t *testing.T) {
	_, err := Generate(GenerateOptions{Output: filepath.Join(t.TempDir(), "x.log"), Lines: 1, Profile: "unknown"})
	if err == nil {
		t.Fatal("Generate accepted unknown profile")
	}
}
