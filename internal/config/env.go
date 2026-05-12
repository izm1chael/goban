package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// ApplyEnvOverrides reads GOBAN_* variables and overlays them on cfg.
//
// Supported variables:
//   - GOBAN_LOG_LEVEL        (string)
//   - GOBAN_LOG_FILE         (string)
//   - GOBAN_SOCKET_PATH      (string)
//   - GOBAN_SOCKET_GROUP     (string)
//   - GOBAN_SOCKET_MODE      (octal int, e.g. "0660")
//   - GOBAN_REPLAY_ON_START  (bool)
//   - GOBAN_FLUSH_ON_EXIT    (bool)
//   - GOBAN_IPV6             (bool)
//   - GOBAN_IPSET_V4         (string)
//   - GOBAN_IPSET_V6         (string)
//   - GOBAN_ALLOWLIST        (csv of CIDRs, replaces existing)
func ApplyEnvOverrides(cfg *Config) error {
	setStringEnv("GOBAN_LOG_LEVEL", func(v string) { cfg.LogLevel = v })
	setStringEnv("GOBAN_LOG_FILE", func(v string) { cfg.LogFile = v })
	setStringEnv("GOBAN_SOCKET_PATH", func(v string) { cfg.SocketPath = v })
	setStringEnv("GOBAN_SOCKET_GROUP", func(v string) { cfg.SocketGroup = v })
	setStringEnv("GOBAN_IPSET_V4", func(v string) { cfg.IPSetNameV4 = v })
	setStringEnv("GOBAN_IPSET_V6", func(v string) { cfg.IPSetNameV6 = v })

	if v := os.Getenv("GOBAN_SOCKET_MODE"); v != "" {
		mode, err := strconv.ParseUint(v, 8, 32)
		if err != nil {
			return fmt.Errorf("GOBAN_SOCKET_MODE invalid octal %q: %w", v, err)
		}
		cfg.SocketMode = uint32(mode)
	}
	if err := setBoolEnv("GOBAN_REPLAY_ON_START", func(b bool) { cfg.ReplayOnStart = b }); err != nil {
		return err
	}
	if err := setBoolEnv("GOBAN_FLUSH_ON_EXIT", func(b bool) { cfg.FlushOnExit = b }); err != nil {
		return err
	}
	if err := setBoolEnv("GOBAN_DRY_RUN", func(b bool) { cfg.DryRun = b }); err != nil {
		return err
	}
	if err := setBoolEnv("GOBAN_IPV6", func(b bool) { cfg.IPv6 = b }); err != nil {
		return err
	}
	if v := os.Getenv("GOBAN_ALLOWLIST"); v != "" {
		parts := strings.Split(v, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				out = append(out, p)
			}
		}
		cfg.Allowlist = out
	}
	if v := os.Getenv("GOBAN_DEFAULT_FINDTIME"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("GOBAN_DEFAULT_FINDTIME invalid duration %q: %w", v, err)
		}
		cfg.Defaults.FindTime = d
	}
	if v := os.Getenv("GOBAN_DEFAULT_BANTIME"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("GOBAN_DEFAULT_BANTIME invalid duration %q: %w", v, err)
		}
		cfg.Defaults.BanTime = d
	}
	if v := os.Getenv("GOBAN_DEFAULT_MAX_RETRIES"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("GOBAN_DEFAULT_MAX_RETRIES invalid int %q: %w", v, err)
		}
		cfg.Defaults.MaxRetries = n
	}
	cfg.ApplyRuleDefaults()
	return nil
}

func setStringEnv(key string, set func(string)) {
	if v := os.Getenv(key); v != "" {
		set(v)
	}
}

func setBoolEnv(key string, set func(bool)) error {
	v := os.Getenv(key)
	if v == "" {
		return nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fmt.Errorf("%s invalid bool %q: %w", key, v, err)
	}
	set(b)
	return nil
}
