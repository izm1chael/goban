package docker

import (
	"testing"

	"github.com/moby/moby/api/types/container"
)

func TestEventFiltersAreNarrow(t *testing.T) {
	s := &Source{}
	f := s.eventFilters()
	if !f["type"]["container"] {
		t.Fatal("container type filter missing")
	}
	for _, action := range []string{"start", "die", "destroy"} {
		if !f["event"][action] {
			t.Fatalf("event filter %q missing", action)
		}
	}
	if len(f) != 2 {
		t.Fatalf("unexpected filter terms: %#v", f)
	}
}

func TestMatchesContainerNameAndLabels(t *testing.T) {
	byName := &Source{container: "web"}
	if !byName.matches(container.Summary{Names: []string{"/web"}}) {
		t.Fatal("expected exact container name to match")
	}
	if byName.matches(container.Summary{Names: []string{"/worker"}}) {
		t.Fatal("unexpected container name match")
	}

	byLabels := &Source{labels: map[string]string{"app": "frontend", "env": "prod"}}
	if !byLabels.matches(container.Summary{Labels: map[string]string{"app": "frontend", "env": "prod", "extra": "ok"}}) {
		t.Fatal("expected required labels to match")
	}
	if byLabels.matches(container.Summary{Labels: map[string]string{"app": "frontend", "env": "dev"}}) {
		t.Fatal("unexpected label match")
	}
}
