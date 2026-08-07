// Package procinfo reads the small subset of Linux /proc process metadata
// GoBan uses to verify its runtime privilege boundary.
package procinfo

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Status is the privilege-relevant subset of /proc/<pid>/status.
type Status struct {
	UID        int
	GID        int
	CapEff     string
	CapBnd     string
	CapAmb     string
	NoNewPrivs bool
}

// ReadSelf returns privilege metadata for the current process.
func ReadSelf() (Status, error) { return Read("/proc/self/status") }

// Read parses a Linux proc status file. It intentionally preserves capability
// masks as the kernel's fixed-width hexadecimal strings so diagnostics can be
// compared directly with systemd/test expectations.
func Read(path string) (Status, error) {
	f, err := os.Open(path)
	if err != nil {
		return Status{}, err
	}
	defer f.Close()

	var out Status
	seen := map[string]bool{}
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := s.Text()
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch key {
		case "Uid":
			fields := strings.Fields(value)
			if len(fields) < 1 {
				return Status{}, fmt.Errorf("malformed Uid line")
			}
			v, err := strconv.Atoi(fields[0])
			if err != nil {
				return Status{}, fmt.Errorf("parse Uid: %w", err)
			}
			out.UID = v
			seen[key] = true
		case "Gid":
			fields := strings.Fields(value)
			if len(fields) < 1 {
				return Status{}, fmt.Errorf("malformed Gid line")
			}
			v, err := strconv.Atoi(fields[0])
			if err != nil {
				return Status{}, fmt.Errorf("parse Gid: %w", err)
			}
			out.GID = v
			seen[key] = true
		case "CapEff":
			out.CapEff = strings.ToLower(value)
			seen[key] = true
		case "CapBnd":
			out.CapBnd = strings.ToLower(value)
			seen[key] = true
		case "CapAmb":
			out.CapAmb = strings.ToLower(value)
			seen[key] = true
		case "NoNewPrivs":
			out.NoNewPrivs = value == "1"
			seen[key] = true
		}
	}
	if err := s.Err(); err != nil {
		return Status{}, err
	}
	for _, key := range []string{"Uid", "Gid", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs"} {
		if !seen[key] {
			return Status{}, fmt.Errorf("%s missing from %s", key, path)
		}
	}
	return out, nil
}
