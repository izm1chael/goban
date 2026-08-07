// Command goban-daemon watches log streams and bans offending IPs.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/izm1chael/goban/internal/config"
	"github.com/izm1chael/goban/internal/daemon"
	"github.com/izm1chael/goban/internal/logging"
	"github.com/izm1chael/goban/internal/privilege"
	"github.com/izm1chael/goban/internal/procinfo"
)

// version is overridden via -ldflags at build time.
var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "goban-daemon: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		configPath   = flag.String("config", "/etc/goban/goban.yaml", "path to YAML config")
		rulesDir     = flag.String("rules-dir", "", "directory of additional rule .yaml files to merge")
		logLevel     = flag.String("log-level", "", "override log level (debug|info|warn|error)")
		logFile      = flag.String("log-file", "", "override log file path; empty = stdout only")
		enforcerMode = flag.String("enforcer-mode", "", "override enforcement mode (direct|split)")
		showVersion  = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return nil
	}

	cfg, err := loadConfig(*configPath, *rulesDir, *logLevel, *logFile, *enforcerMode)
	if err != nil {
		return err
	}
	if cfg.Enforcer.Mode == "split" && !cfg.DryRun {
		state, err := procinfo.ReadSelf()
		if err != nil {
			return fmt.Errorf("verify split-mode detector privileges: %w", err)
		}
		if err := privilege.ValidateDetector(state); err != nil {
			return fmt.Errorf("unsafe split-mode detector runtime: %w; use the packaged goban.service", err)
		}
	}

	closeLog, err := logging.Init(cfg.LogFile, cfg.LogLevel)
	if err != nil {
		return fmt.Errorf("init logging: %w", err)
	}
	defer closeLog()
	log := logging.Get()

	d, err := daemon.New(cfg, *log, version, *configPath, *rulesDir, daemon.RuntimeOverrides{LogLevel: *logLevel, LogFile: *logFile, EnforcerMode: *enforcerMode})
	if err != nil {
		return fmt.Errorf("daemon init: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := d.Start(ctx); err != nil {
		return fmt.Errorf("daemon start: %w", err)
	}

	// SIGHUP triggers a hot config reload (validate-then-swap; running daemon
	// is unchanged on any failure). Separate from the SIGTERM/INT context
	// because we want to keep handling HUPs across the daemon's lifetime.
	hupCh := make(chan os.Signal, 1)
	signal.Notify(hupCh, syscall.SIGHUP)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-hupCh:
				if err := d.Reload(context.Background()); err != nil {
					log.Error().Err(err).Msg("SIGHUP reload failed; daemon unchanged")
				}
			}
		}
	}()

	<-ctx.Done()

	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return d.Stop(shutCtx)
}

func loadConfig(path, rulesDir, logLevel, logFile, enforcerMode string) (*config.Config, error) {
	cfg, err := config.LoadEffective(path, rulesDir)
	if err != nil {
		return nil, err
	}
	if logLevel != "" {
		cfg.LogLevel = logLevel
	}
	if logFile != "" {
		cfg.LogFile = logFile
	}
	if enforcerMode != "" {
		cfg.Enforcer.Mode = enforcerMode
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validate config after CLI overrides: %w", err)
	}
	return cfg, nil
}
