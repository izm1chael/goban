package daemon

import (
	"testing"

	"github.com/izm1chael/goban/internal/control"
)

func TestDoctorOverall(t *testing.T) {
	tests := []struct {
		name string
		in   []control.DoctorCheck
		want string
	}{
		{"healthy", []control.DoctorCheck{{Status: "pass"}, {Status: "skip"}}, "healthy"},
		{"degraded", []control.DoctorCheck{{Status: "pass"}, {Status: "warn"}}, "degraded"},
		{"not enforcing", []control.DoctorCheck{{Status: "warn"}, {Status: "fail"}}, "not_enforcing"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := doctorOverall(tt.in); got != tt.want {
				t.Fatalf("doctorOverall=%q, want %q", got, tt.want)
			}
		})
	}
}
