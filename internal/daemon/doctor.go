package daemon

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/izm1chael/goban/internal/banner"
	"github.com/izm1chael/goban/internal/control"
	"github.com/izm1chael/goban/internal/privilege"
	"github.com/izm1chael/goban/internal/procinfo"
)

// Doctor verifies the live daemon rather than merely validating YAML. The
// default run is read-only; Probe explicitly performs a short-lived
// insert/list/remove cycle against the selected kernel backend.
func (d *Daemon) Doctor(ctx context.Context, req control.DoctorReq) control.DoctorResp {
	resp := control.DoctorResp{CheckedAt: time.Now().UTC()}
	add := func(name, status, detail, remediation string) {
		resp.Checks = append(resp.Checks, control.DoctorCheck{Name: name, Status: status, Detail: detail, Remediation: remediation})
	}

	d.mu.Lock()
	cfg := *d.cfg
	sources := make([]control.SourceInfo, 0, len(d.sources))
	for _, si := range d.sources {
		h := si.src.Health()
		sources = append(sources, control.SourceInfo{Name: h.Name, Status: h.Status, LastError: h.LastError, Dropped: h.Dropped})
	}
	ruleCount := len(d.rules)
	auditReady := d.audit != nil
	d.mu.Unlock()

	if cfg.DryRun {
		add("enforcement mode", "fail", "dry_run is enabled; GoBan is observing but cannot block traffic", "set dry_run: false and restart after verifying the firewall backend")
	} else {
		add("enforcement mode", "pass", "kernel enforcement is enabled", "")
	}
	if !cfg.DryRun && cfg.Enforcer.Mode == "split" {
		proc, err := procinfo.ReadSelf()
		if err != nil {
			add("detector privilege boundary", "fail", "cannot verify detector privilege state from /proc: "+err.Error(), "run the packaged Linux systemd service and ensure /proc is readable")
		} else if err := privilege.ValidateDetector(proc); err != nil {
			add("detector privilege boundary", "fail", fmt.Sprintf("uid=%d gid=%d CapEff=%s CapBnd=%s CapAmb=%s NoNewPrivs=%t: %v", proc.UID, proc.GID, proc.CapEff, proc.CapBnd, proc.CapAmb, proc.NoNewPrivs, err), "use the packaged goban.service and remove manual/root execution or added capabilities")
		} else {
			add("detector privilege boundary", "pass", fmt.Sprintf("uid=%d with zero effective/bounding/ambient capabilities and NoNewPrivileges", proc.UID), "")
		}
	} else if !cfg.DryRun {
		add("privilege separation", "skip", "direct compatibility mode keeps firewall privileges in goban-daemon", "packaged systemd installs use --enforcer-mode=split; use direct only when a separate helper is unsuitable")
	}

	listCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	bans, err := d.banner.List(listCtx)
	cancel()
	if err != nil {
		add("firewall backend", "fail", fmt.Sprintf("%s backend is not readable: %v", cfg.Banner.Backend, err), "check kernel modules/capabilities and run the privileged integration suite")
	} else {
		backend := cfg.Banner.Backend
		if backend == "" {
			backend = "iptables"
		}
		add("firewall backend", "pass", fmt.Sprintf("%s backend responded; %d active decisions", backend, len(bans)), "")
		unattributed := 0
		for _, active := range bans {
			if active.Rule != "" {
				continue
			}
			if d.banMeta == nil {
				unattributed++
				continue
			}
			meta, ok := d.banMeta.get(active.IP)
			if !ok || meta.DecisionID == "" {
				unattributed++
			}
		}
		if unattributed > 0 {
			add("decision attribution", "warn", fmt.Sprintf("%d active kernel decisions have no persisted rule/evidence attribution", unattributed), "inspect legacy/corrupt metadata; enforcement remains active but explainability is incomplete")
		} else {
			add("decision attribution", "pass", "all active decisions have runtime or persisted attribution", "")
		}
		if missing := d.missingPersistedBans(bans, time.Now().UTC()); missing > 0 {
			add("decision persistence", "warn", fmt.Sprintf("%d unexpired persisted decisions are missing from the kernel backend", missing), "restart GoBan to retry restoration and inspect firewall/backend errors; do not assume those specific decisions are enforced")
		} else {
			add("decision persistence", "pass", "all restorable persisted decisions are present in the kernel backend", "")
		}
	}

	if diagnoser, ok := d.banner.(banner.Diagnoser); ok {
		diagCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		for _, check := range diagnoser.Diagnostics(diagCtx) {
			add(check.Name, check.Status, check.Detail, check.Remediation)
		}
		cancel()
	} else {
		add("firewall hooks", "skip", "selected backend does not expose packet-path diagnostics", "run the privileged kernel integration suite before treating the host as production-ready")
	}

	if ruleCount == 0 {
		add("rules", "fail", "no active rules are loaded", "enable at least one tested rule in rules.d and reload")
	} else {
		add("rules", "pass", fmt.Sprintf("%d active rules loaded", ruleCount), "")
	}
	if len(sources) == 0 {
		add("sources", "fail", "no log sources are configured", "configure a file, journald, or Docker source")
	} else {
		degraded, dropped := 0, uint64(0)
		for _, src := range sources {
			if src.Status != "running" {
				degraded++
			}
			dropped += src.Dropped
		}
		switch {
		case degraded > 0:
			add("sources", "fail", fmt.Sprintf("%d of %d sources are not running", degraded, len(sources)), "run goban-client sources and resolve the reported source errors")
		case dropped > 0:
			add("sources", "warn", fmt.Sprintf("all %d sources are running, but %d deliveries have been dropped", len(sources), dropped), "increase strike_chan_size or reduce rule/source load; dropped security events weaken protection")
		default:
			add("sources", "pass", fmt.Sprintf("all %d sources are running with no observed drops", len(sources)), "")
		}
	}

	checkSocket(&resp, cfg.SocketPath, os.FileMode(cfg.SocketMode), cfg.SocketGroup)
	checkWritablePath(&resp, "state storage", cfg.StatePath, "warn")
	if cfg.AuditLog != "" && !auditReady {
		add("audit pipeline", "warn", "audit logging was configured but the writer did not open at daemon startup", "restore the audit path and restart GoBan; enforcement continues but decision history is incomplete")
	} else if cfg.AuditLog != "" {
		add("audit pipeline", "pass", "confirmed decisions are connected to the append-only audit writer", "")
	} else {
		add("audit pipeline", "skip", "audit logging is disabled", "configure audit_log when forensic history or recidive is required")
	}
	checkWritablePath(&resp, "audit storage", cfg.AuditLog, "warn")

	forwardConfigured := false
	if cfg.Banner.Backend != "nftables" {
		for _, chain := range cfg.Banner.IPTablesChains {
			if chain != "INPUT" {
				forwardConfigured = true
				break
			}
		}
	}
	if forwardConfigured {
		add("forwarded traffic policy", "pass", fmt.Sprintf("iptables enforcement includes non-INPUT chains %v", cfg.Banner.IPTablesChains), "verify the actual forwarded path with test/integration/kernel/run.sh")
	} else if cfg.Banner.Backend == "nftables" && cfg.Banner.ForwardChain != "" {
		add("forwarded traffic policy", "pass", fmt.Sprintf("nftables forward hook %q is configured", cfg.Banner.ForwardChain), "verify the forward path with test/integration/kernel/run.sh")
	} else {
		add("forwarded traffic policy", "warn", "forwarded/Docker bridge traffic enforcement is disabled", "enable a FORWARD/DOCKER-USER equivalent when this host publishes bridged workloads")
	}

	if req.Probe {
		d.doDoctorProbe(ctx, req.ProbeIP, &resp)
	} else {
		add("kernel write probe", "skip", "not requested; run goban-client doctor --probe for an insert/list/remove verification", "")
	}

	resp.Overall = doctorOverall(resp.Checks)
	return resp
}

func (d *Daemon) doDoctorProbe(ctx context.Context, raw string, resp *control.DoctorResp) {
	if raw == "" {
		raw = "192.0.2.254"
	}
	ip, err := netip.ParseAddr(raw)
	if err != nil {
		resp.Checks = append(resp.Checks, control.DoctorCheck{Name: "kernel write probe", Status: "fail", Detail: "invalid probe IP: " + err.Error(), Remediation: "supply a valid non-production address with --probe-ip"})
		return
	}
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	before, err := d.banner.List(probeCtx)
	if err != nil {
		resp.Checks = append(resp.Checks, control.DoctorCheck{Name: "kernel write probe", Status: "fail", Detail: "cannot list decisions before probe: " + err.Error()})
		return
	}
	for _, b := range before {
		if b.IP.Unmap() == ip.Unmap() {
			resp.Checks = append(resp.Checks, control.DoctorCheck{Name: "kernel write probe", Status: "skip", Detail: fmt.Sprintf("%s is already banned; refusing to overwrite a real decision", ip), Remediation: "choose another documentation/test address with --probe-ip"})
			return
		}
	}
	if err := d.banner.Ban(probeCtx, ip, "doctor-probe", 5*time.Second); err != nil {
		resp.Checks = append(resp.Checks, control.DoctorCheck{Name: "kernel write probe", Status: "fail", Detail: "kernel insert failed: " + err.Error(), Remediation: "verify CAP_NET_ADMIN/root and backend compatibility"})
		return
	}
	defer func() { _ = d.banner.Unban(context.Background(), ip) }()
	after, err := d.banner.List(probeCtx)
	if err != nil {
		resp.Checks = append(resp.Checks, control.DoctorCheck{Name: "kernel write probe", Status: "fail", Detail: "insert succeeded but list verification failed: " + err.Error()})
		return
	}
	found := false
	for _, b := range after {
		if b.IP.Unmap() == ip.Unmap() {
			found = true
			break
		}
	}
	if !found {
		resp.Checks = append(resp.Checks, control.DoctorCheck{Name: "kernel write probe", Status: "fail", Detail: "backend acknowledged the probe but the decision was not visible", Remediation: "do not treat this host as protected; inspect the backend and kernel integration"})
		return
	}
	if err := d.banner.Unban(probeCtx, ip); err != nil {
		resp.Checks = append(resp.Checks, control.DoctorCheck{Name: "kernel write probe", Status: "fail", Detail: "probe was visible but cleanup failed: " + err.Error(), Remediation: "manually remove the doctor-probe entry"})
		return
	}
	resp.Checks = append(resp.Checks, control.DoctorCheck{Name: "kernel write probe", Status: "pass", Detail: fmt.Sprintf("%s was inserted, observed, and removed successfully", ip)})
}

func checkSocket(resp *control.DoctorResp, path string, mode os.FileMode, group string) {
	info, err := os.Lstat(path)
	if err != nil {
		resp.Checks = append(resp.Checks, control.DoctorCheck{Name: "control socket", Status: "fail", Detail: err.Error(), Remediation: "confirm the daemon control server started and the runtime directory exists"})
		return
	}
	if info.Mode()&os.ModeSocket == 0 {
		resp.Checks = append(resp.Checks, control.DoctorCheck{Name: "control socket", Status: "fail", Detail: path + " is not a Unix socket"})
		return
	}
	if info.Mode().Perm() != mode.Perm() {
		resp.Checks = append(resp.Checks, control.DoctorCheck{Name: "control socket", Status: "warn", Detail: fmt.Sprintf("mode is %04o, configured %04o", info.Mode().Perm(), mode.Perm()), Remediation: "restart the daemon and verify runtime-directory ownership"})
		return
	}
	if group != "" {
		grp, err := user.LookupGroup(group)
		if err != nil {
			resp.Checks = append(resp.Checks, control.DoctorCheck{Name: "control socket", Status: "fail", Detail: "configured group lookup failed: " + err.Error()})
			return
		}
		want, err := strconv.ParseUint(grp.Gid, 10, 32)
		if err != nil {
			resp.Checks = append(resp.Checks, control.DoctorCheck{Name: "control socket", Status: "fail", Detail: "configured group has a non-numeric gid: " + err.Error()})
			return
		}
		if st, ok := info.Sys().(*syscall.Stat_t); ok && uint64(st.Gid) != want {
			resp.Checks = append(resp.Checks, control.DoctorCheck{Name: "control socket", Status: "warn", Detail: fmt.Sprintf("socket gid is %d, expected %d (%s)", st.Gid, want, group), Remediation: "restart GoBan after creating/configuring the socket group"})
			return
		}
	}
	resp.Checks = append(resp.Checks, control.DoctorCheck{Name: "control socket", Status: "pass", Detail: fmt.Sprintf("%s has mode %04o and expected ownership", path, info.Mode().Perm())})
}

func checkWritablePath(resp *control.DoctorResp, name, path, failureStatus string) {
	if path == "" {
		resp.Checks = append(resp.Checks, control.DoctorCheck{Name: name, Status: "skip", Detail: "disabled by configuration"})
		return
	}
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".goban-doctor-*")
	if err != nil {
		resp.Checks = append(resp.Checks, control.DoctorCheck{Name: name, Status: failureStatus, Detail: fmt.Sprintf("%s is not writable: %v", dir, err), Remediation: "restore directory ownership, permissions, and free space"})
		return
	}
	probe := f.Name()
	if _, err := f.Write([]byte("ok")); err != nil {
		_ = f.Close()
		_ = os.Remove(probe)
		resp.Checks = append(resp.Checks, control.DoctorCheck{Name: name, Status: failureStatus, Detail: "write probe failed: " + err.Error(), Remediation: "restore free space and directory permissions"})
		return
	}
	_ = f.Close()
	_ = os.Remove(probe)
	resp.Checks = append(resp.Checks, control.DoctorCheck{Name: name, Status: "pass", Detail: dir + " is writable"})
}

func doctorOverall(checks []control.DoctorCheck) string {
	overall := "healthy"
	for _, check := range checks {
		if check.Status == "fail" {
			return "not_enforcing"
		}
		if check.Status == "warn" {
			overall = "degraded"
		}
	}
	return overall
}
