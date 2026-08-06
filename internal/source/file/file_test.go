package file

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFileSource_TailAppend(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	// pre-populate so the file exists; we skip-to-end so this won't be tailed
	if err := os.WriteFile(path, []byte("preexisting line\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	s := New(Config{Name: "test", Path: path})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer s.Close()

	ch := s.Subscribe("jail", 8)

	// Give the tailer a moment to seek to end.
	time.Sleep(100 * time.Millisecond)

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("hello world\n"); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	select {
	case line := <-ch:
		if line.Text != "hello world" {
			t.Errorf("got %q, want %q", line.Text, "hello world")
		}
		if line.Source != "test" {
			t.Errorf("source = %q, want test", line.Source)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for tailed line")
	}
}

func TestFileSource_TruncatesLongLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	if err := os.WriteFile(path, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	s := New(Config{Name: "test", Path: path, MaxLineLen: 10})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer s.Close()
	ch := s.Subscribe("jail", 8)
	time.Sleep(100 * time.Millisecond)

	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	_, _ = f.WriteString("this is a very long line that exceeds the cap\n")
	_ = f.Close()

	select {
	case line := <-ch:
		if len(line.Text) != 10 {
			t.Errorf("len(line.Text) = %d, want 10", len(line.Text))
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out")
	}
}

func TestFileSource_FollowsRotationFromStart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	s := New(Config{Name: "test", Path: path})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ch := s.Subscribe("rule", 8)
	time.Sleep(250 * time.Millisecond)

	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("after rotation\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case line := <-ch:
		if line.Text != "after rotation" || line.ReceivedAt.IsZero() {
			t.Fatalf("line=%+v", line)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for rotated file")
	}
}

func TestFileSource_MissingAtStartReadsNewFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "later.log")
	s := New(Config{Name: "test", Path: path})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ch := s.Subscribe("rule", 8)
	if err := os.WriteFile(path, []byte("created later\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case line := <-ch:
		if line.Text != "created later" {
			t.Fatalf("line=%+v", line)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for newly-created file")
	}
}

func TestFileSource_RecoversAfterCopyTruncate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	s := New(Config{Name: "test", Path: path})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ch := s.Subscribe("rule", 8)
	time.Sleep(250 * time.Millisecond)

	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("before truncate\n"); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	select {
	case line := <-ch:
		if line.Text != "before truncate" {
			t.Fatalf("line=%+v", line)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out before truncation")
	}

	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	// Let the follower observe that the current inode shrank before appending
	// the next record. This models copytruncate-style log rotation.
	time.Sleep(2 * followPollInterval)
	f, err = os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("after truncate\n"); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	select {
	case line := <-ch:
		if line.Text != "after truncate" {
			t.Fatalf("line=%+v", line)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out after truncation")
	}
}
