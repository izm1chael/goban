package main

import (
	"testing"
	"time"
)

func TestParseBanArgsAcceptsFlagsBeforeOrAfterIP(t *testing.T) {
	cases := [][]string{
		{"198.51.100.7", "--rule", "manual", "--ttl", "12h"},
		{"--rule=manual", "--ttl=12h", "198.51.100.7"},
	}
	for _, args := range cases {
		ip, rule, ttl, err := parseBanArgs(args)
		if err != nil {
			t.Fatalf("parseBanArgs(%v): %v", args, err)
		}
		if ip != "198.51.100.7" || rule != "manual" || ttl != 12*time.Hour {
			t.Fatalf("parseBanArgs(%v) = %q, %q, %s", args, ip, rule, ttl)
		}
	}
}

func TestParseBanArgsRejectsMissingFlagValue(t *testing.T) {
	if _, _, _, err := parseBanArgs([]string{"198.51.100.7", "--rule", "--ttl", "1h"}); err == nil {
		t.Fatal("expected missing --rule value to fail")
	}
}
