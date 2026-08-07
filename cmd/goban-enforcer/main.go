// Command goban-enforcer is GoBan's minimal privileged firewall helper.
// It owns CAP_NET_ADMIN and accepts typed decisions only from the configured
// unprivileged goban daemon UID over a private Unix socket.
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
	"github.com/izm1chael/goban/internal/enforcer"
	"github.com/izm1chael/goban/internal/firewall"
	"github.com/izm1chael/goban/internal/logging"
	"github.com/izm1chael/goban/internal/privilege"
	"github.com/izm1chael/goban/internal/procinfo"
)

var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "goban-enforcer: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	configPath := flag.String("config", "/etc/goban/goban.yaml", "path to GoBan YAML config")
	rulesDir := flag.String("rules-dir", "", "optional rules directory used while validating effective config")
	socket := flag.String("socket", "", "override private enforcer Unix socket")
	allowedUser := flag.String("allowed-user", "", "override daemon user permitted to connect")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return nil
	}

	state, err := procinfo.ReadSelf()
	if err != nil {
		return fmt.Errorf("verify enforcer privileges: %w", err)
	}
	if err := privilege.ValidateEnforcer(state); err != nil {
		return fmt.Errorf("unsafe enforcer runtime: %w; use the packaged goban-enforcer.service", err)
	}

	cfg, err := config.LoadEffective(*configPath, *rulesDir)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if *socket != "" {
		cfg.Enforcer.SocketPath = *socket
	}
	if *allowedUser != "" {
		cfg.Enforcer.AllowedUser = *allowedUser
	}
	if cfg.Enforcer.SocketPath == "" || cfg.Enforcer.AllowedUser == "" {
		return fmt.Errorf("enforcer socket_path and allowed_user must be configured")
	}

	closeLog, err := logging.Init("", cfg.LogLevel)
	if err != nil {
		return fmt.Errorf("init logging: %w", err)
	}
	defer closeLog()
	log := logging.Get()
	backendName := cfg.Banner.Backend
	if backendName == "" {
		backendName = "iptables"
	}
	policy, err := enforcer.NewPolicy(cfg)
	if err != nil {
		return fmt.Errorf("build enforcement policy: %w", err)
	}
	backend := firewall.NewLocal(cfg, *log)
	srv := enforcer.New(backend, backendName, cfg.Enforcer.SocketPath, cfg.Enforcer.AllowedUser, policy, *log)
	srv.SetReconcileInterval(cfg.Enforcer.ReconcileInterval)
	srv.SetPolicyLoader(func() (*enforcer.Policy, error) {
		fresh, err := config.LoadEffective(*configPath, *rulesDir)
		if err != nil {
			return nil, err
		}
		freshBackend := fresh.Banner.Backend
		if freshBackend == "" {
			freshBackend = "iptables"
		}
		if freshBackend != backendName {
			return nil, fmt.Errorf("banner backend changed from %s to %s; restart both GoBan services", backendName, freshBackend)
		}
		return enforcer.NewPolicy(fresh)
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := srv.Start(ctx); err != nil {
		return err
	}
	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return srv.Stop(shutdownCtx)
}
