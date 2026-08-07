// Command goban-soak records long-running GoBan health evidence and produces a
// deterministic release report. It is an operator/maintainer tool; it does not
// alter firewall policy unless --probe-every or --reload-every is explicitly set.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/izm1chael/goban/internal/control"
)

var version = "dev"

type metadata struct {
	Version     string        `json:"version"`
	PID         int           `json:"pid"`
	StartedAt   time.Time     `json:"started_at"`
	FinishedAt  time.Time     `json:"finished_at,omitempty"`
	Duration    time.Duration `json:"duration"`
	Interval    time.Duration `json:"interval"`
	Socket      string        `json:"socket"`
	State       string        `json:"state"`
	LastError   string        `json:"last_error,omitempty"`
	SampleCount int           `json:"sample_count"`
}

type ruleSnapshot struct {
	Name           string `json:"name"`
	Tracked        int    `json:"tracked"`
	Hits           uint64 `json:"hits"`
	Bans           uint64 `json:"bans"`
	Misses         uint64 `json:"misses"`
	DateParseFails uint64 `json:"date_parse_fails"`
	DateDrops      uint64 `json:"date_drops"`
}

type sample struct {
	Time       time.Time            `json:"time"`
	Status     *control.StatusResp  `json:"status,omitempty"`
	Sources    []control.SourceInfo `json:"sources,omitempty"`
	Rules      []ruleSnapshot       `json:"rules,omitempty"`
	ActiveBans int                  `json:"active_bans"`
	Doctor     *control.DoctorResp  `json:"doctor,omitempty"`
	Errors     []string             `json:"errors,omitempty"`
	Reload     string               `json:"reload,omitempty"`
	Probe      string               `json:"probe,omitempty"`
}

type report struct {
	GeneratedAt         time.Time `json:"generated_at"`
	RunDir              string    `json:"run_dir"`
	StartedAt           time.Time `json:"started_at"`
	FinishedAt          time.Time `json:"finished_at"`
	Duration            string    `json:"duration"`
	Samples             int       `json:"samples"`
	SamplesWithErrors   int       `json:"samples_with_errors"`
	DoctorHealthy       int       `json:"doctor_healthy"`
	DoctorDegraded      int       `json:"doctor_degraded"`
	DoctorNotEnforcing  int       `json:"doctor_not_enforcing"`
	ReloadSuccesses     int       `json:"reload_successes"`
	ReloadFailures      int       `json:"reload_failures"`
	ProbeSuccesses      int       `json:"probe_successes"`
	ProbeFailures       int       `json:"probe_failures"`
	InitialDroppedLines uint64    `json:"initial_dropped_lines"`
	FinalDroppedLines   uint64    `json:"final_dropped_lines"`
	DroppedLinesDelta   uint64    `json:"dropped_lines_delta"`
	InitialTotalBans    int       `json:"initial_total_bans"`
	FinalTotalBans      int       `json:"final_total_bans"`
	InitialMemoryBytes  uint64    `json:"initial_memory_bytes"`
	FinalMemoryBytes    uint64    `json:"final_memory_bytes"`
	MemoryGrowthBytes   uint64    `json:"memory_growth_bytes"`
	PeakMemoryBytes     uint64    `json:"peak_memory_bytes"`
	InitialGoroutines   int       `json:"initial_goroutines"`
	FinalGoroutines     int       `json:"final_goroutines"`
	GoroutineGrowth     int       `json:"goroutine_growth"`
	PeakGoroutines      int       `json:"peak_goroutines"`
	MaxDegradedSources  int       `json:"max_degraded_sources"`
	SourceReconnects    uint64    `json:"source_reconnects"`
	Verdict             string    `json:"verdict"`
	VerdictReasons      []string  `json:"verdict_reasons,omitempty"`
}

func usage() {
	fmt.Fprintf(os.Stderr, `goban-soak — collect long-running GoBan release evidence

Usage:
  goban-soak start [flags]       start a background or foreground soak
  goban-soak run [flags]         internal foreground runner
  goban-soak status --run DIR    show progress
  goban-soak report --run DIR    generate report.json and report.md
  goban-soak version

Start/run flags:
  --duration 168h                total run duration
  --interval 10s                 sampling interval
  --sock /run/goban/goban.sock   daemon socket
  --out DIR                      run directory
  --foreground                   do not detach
  --reload-every 0               optional transactional reload exercise
  --probe-every 0                optional doctor kernel probe exercise
`)
}

func main() {
	if err := runMain(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "goban-soak:", err)
		os.Exit(1)
	}
}

func runMain(args []string) error {
	if len(args) == 0 {
		usage()
		return errors.New("command required")
	}
	switch args[0] {
	case "start":
		return start(args[1:])
	case "run":
		return runSoak(args[1:])
	case "status":
		return status(args[1:])
	case "report":
		return makeReport(args[1:])
	case "version":
		fmt.Println(version)
		return nil
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

type runFlags struct {
	duration    time.Duration
	interval    time.Duration
	socket      string
	out         string
	foreground  bool
	reloadEvery time.Duration
	probeEvery  time.Duration
}

func parseRunFlags(name string, args []string) (runFlags, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	var out runFlags
	fs.DurationVar(&out.duration, "duration", 7*24*time.Hour, "total run duration")
	fs.DurationVar(&out.interval, "interval", 10*time.Second, "sampling interval")
	fs.StringVar(&out.socket, "sock", "/run/goban/goban.sock", "daemon socket")
	fs.StringVar(&out.out, "out", "", "run directory")
	fs.BoolVar(&out.foreground, "foreground", false, "run in the foreground")
	fs.DurationVar(&out.reloadEvery, "reload-every", 0, "exercise transactional reload at this interval")
	fs.DurationVar(&out.probeEvery, "probe-every", 0, "exercise doctor kernel probe at this interval")
	if err := fs.Parse(args); err != nil {
		return out, err
	}
	if fs.NArg() != 0 {
		return out, fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	if out.duration < time.Second || out.interval < time.Second {
		return out, errors.New("duration and interval must be at least 1s")
	}
	if out.out == "" {
		out.out = filepath.Join("soak-runs", time.Now().UTC().Format("20060102T150405Z"))
	}
	return out, nil
}

func start(args []string) error {
	flags, err := parseRunFlags("start", args)
	if err != nil {
		return err
	}
	if flags.foreground {
		return execute(flags)
	}
	preflightCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	_, preflightErr := control.NewClient(flags.socket).Status(preflightCtx)
	cancel()
	if preflightErr != nil {
		return fmt.Errorf("daemon preflight failed: %w", preflightErr)
	}
	if err := os.MkdirAll(flags.out, 0o755); err != nil {
		return err
	}
	logFile, err := os.OpenFile(filepath.Join(flags.out, "runner.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	defer logFile.Close()
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	childArgs := []string{"run", "--duration", flags.duration.String(), "--interval", flags.interval.String(), "--sock", flags.socket, "--out", flags.out}
	if flags.reloadEvery > 0 {
		childArgs = append(childArgs, "--reload-every", flags.reloadEvery.String())
	}
	if flags.probeEvery > 0 {
		childArgs = append(childArgs, "--probe-every", flags.probeEvery.String())
	}
	cmd := exec.Command(exe, childArgs...)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	fmt.Printf("GoBan soak started: PID %d\nRun directory: %s\n", cmd.Process.Pid, flags.out)
	fmt.Printf("Status: goban-soak status --run %s\n", flags.out)
	return nil
}

func runSoak(args []string) error {
	flags, err := parseRunFlags("run", args)
	if err != nil {
		return err
	}
	return execute(flags)
}

func execute(flags runFlags) error {
	if err := os.MkdirAll(flags.out, 0o755); err != nil {
		return err
	}
	meta := metadata{Version: version, PID: os.Getpid(), StartedAt: time.Now().UTC(), Duration: flags.duration, Interval: flags.interval, Socket: flags.socket, State: "running"}
	if err := writeJSONAtomic(filepath.Join(flags.out, "run.json"), meta); err != nil {
		return err
	}
	samplesFile, err := os.OpenFile(filepath.Join(flags.out, "samples.jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	defer samplesFile.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	deadline := time.NewTimer(flags.duration)
	defer deadline.Stop()
	ticker := time.NewTicker(flags.interval)
	defer ticker.Stop()
	client := control.NewClient(flags.socket)
	lastReload, lastProbe := time.Now(), time.Now()

	collect := func() {
		s := collectSample(ctx, client)
		if flags.reloadEvery > 0 && time.Since(lastReload) >= flags.reloadEvery {
			opCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			if err := client.Reload(opCtx); err != nil {
				s.Reload = "failed: " + err.Error()
			} else {
				s.Reload = "success"
			}
			cancel()
			lastReload = time.Now()
		}
		if flags.probeEvery > 0 && time.Since(lastProbe) >= flags.probeEvery {
			opCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			resp, err := client.Doctor(opCtx, control.DoctorReq{Probe: true})
			if err != nil {
				s.Probe = "failed: " + err.Error()
			} else if resp.Overall == "not_enforcing" {
				s.Probe = "failed: doctor reported not_enforcing"
			} else {
				s.Probe = "success"
			}
			cancel()
			lastProbe = time.Now()
		}
		data, _ := json.Marshal(s)
		_, _ = samplesFile.Write(append(data, '\n'))
		_ = samplesFile.Sync()
		meta.SampleCount++
		if len(s.Errors) > 0 {
			meta.LastError = strings.Join(s.Errors, "; ")
		}
		_ = writeJSONAtomic(filepath.Join(flags.out, "run.json"), meta)
	}

	collect()
	for {
		select {
		case <-ctx.Done():
			meta.State = "stopped"
			meta.FinishedAt = time.Now().UTC()
			_ = writeJSONAtomic(filepath.Join(flags.out, "run.json"), meta)
			return makeReport([]string{"--run", flags.out})
		case <-deadline.C:
			meta.State = "completed"
			meta.FinishedAt = time.Now().UTC()
			_ = writeJSONAtomic(filepath.Join(flags.out, "run.json"), meta)
			return makeReport([]string{"--run", flags.out})
		case <-ticker.C:
			collect()
		}
	}
}

func collectSample(parent context.Context, client *control.Client) sample {
	s := sample{Time: time.Now().UTC()}
	call := func(name string, fn func(context.Context) error) {
		ctx, cancel := context.WithTimeout(parent, 15*time.Second)
		defer cancel()
		if err := fn(ctx); err != nil {
			s.Errors = append(s.Errors, name+": "+err.Error())
		}
	}
	call("status", func(ctx context.Context) error {
		value, err := client.Status(ctx)
		if err == nil {
			s.Status = &value
		}
		return err
	})
	call("sources", func(ctx context.Context) error {
		value, err := client.Sources(ctx)
		if err == nil {
			s.Sources = value
		}
		return err
	})
	call("rules", func(ctx context.Context) error {
		value, err := client.Rules(ctx)
		if err == nil {
			s.Rules = make([]ruleSnapshot, 0, len(value))
			for _, rule := range value {
				s.Rules = append(s.Rules, ruleSnapshot{Name: rule.Name, Tracked: rule.Tracked, Hits: rule.Hits, Bans: rule.Bans, Misses: rule.Misses, DateParseFails: rule.DateParseFails, DateDrops: rule.DateDrops})
			}
		}
		return err
	})
	call("banned", func(ctx context.Context) error {
		value, err := client.Banned(ctx)
		if err == nil {
			s.ActiveBans = len(value)
		}
		return err
	})
	call("doctor", func(ctx context.Context) error {
		value, err := client.Doctor(ctx, control.DoctorReq{})
		if err == nil {
			s.Doctor = &value
		}
		return err
	})
	return s
}

func status(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	runDir := fs.String("run", "", "run directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *runDir == "" {
		return errors.New("--run is required")
	}
	var meta metadata
	if err := readJSON(filepath.Join(*runDir, "run.json"), &meta); err != nil {
		return err
	}
	alive := processAlive(meta.PID)
	fmt.Printf("State: %s\nPID: %d (%s)\nStarted: %s\nSamples: %d\n", meta.State, meta.PID, map[bool]string{true: "alive", false: "not running"}[alive], meta.StartedAt.Format(time.RFC3339), meta.SampleCount)
	if meta.LastError != "" {
		fmt.Printf("Last error: %s\n", meta.LastError)
	}
	return nil
}

func makeReport(args []string) error {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	runDir := fs.String("run", "", "run directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *runDir == "" {
		return errors.New("--run is required")
	}
	rep, err := aggregate(*runDir)
	if err != nil {
		return err
	}
	if err := writeJSONAtomic(filepath.Join(*runDir, "report.json"), rep); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*runDir, "report.md"), []byte(markdownReport(rep)), 0o644); err != nil {
		return err
	}
	fmt.Printf("Soak verdict: %s\nSamples: %d  Error samples: %d  Dropped delta: %d\nReport: %s\n", rep.Verdict, rep.Samples, rep.SamplesWithErrors, rep.DroppedLinesDelta, filepath.Join(*runDir, "report.md"))
	return nil
}

func aggregate(runDir string) (report, error) {
	f, err := os.Open(filepath.Join(runDir, "samples.jsonl"))
	if err != nil {
		return report{}, err
	}
	defer f.Close()
	rep := report{GeneratedAt: time.Now().UTC(), RunDir: runDir, Verdict: "PASS"}
	var firstStatus, lastStatus *control.StatusResp
	sourceReconnects := map[string]uint64{}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		var s sample
		if err := json.Unmarshal(scanner.Bytes(), &s); err != nil {
			return report{}, err
		}
		if rep.Samples == 0 {
			rep.StartedAt = s.Time
		}
		rep.FinishedAt = s.Time
		rep.Samples++
		if len(s.Errors) > 0 {
			rep.SamplesWithErrors++
		}
		if s.Status != nil {
			if firstStatus == nil {
				copy := *s.Status
				firstStatus = &copy
			}
			copy := *s.Status
			lastStatus = &copy
			if s.Status.MemoryBytes > rep.PeakMemoryBytes {
				rep.PeakMemoryBytes = s.Status.MemoryBytes
			}
			if s.Status.Goroutines > rep.PeakGoroutines {
				rep.PeakGoroutines = s.Status.Goroutines
			}
			if s.Status.DegradedSources > rep.MaxDegradedSources {
				rep.MaxDegradedSources = s.Status.DegradedSources
			}
		}
		if s.Doctor != nil {
			switch s.Doctor.Overall {
			case "healthy":
				rep.DoctorHealthy++
			case "degraded":
				rep.DoctorDegraded++
			case "not_enforcing":
				rep.DoctorNotEnforcing++
			}
		}
		if s.Reload == "success" {
			rep.ReloadSuccesses++
		} else if strings.HasPrefix(s.Reload, "failed") {
			rep.ReloadFailures++
		}
		if s.Probe == "success" {
			rep.ProbeSuccesses++
		} else if strings.HasPrefix(s.Probe, "failed") {
			rep.ProbeFailures++
		}
		for _, source := range s.Sources {
			if source.Reconnects > sourceReconnects[source.Name] {
				sourceReconnects[source.Name] = source.Reconnects
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return report{}, err
	}
	if rep.Samples == 0 {
		return report{}, errors.New("no samples found")
	}
	rep.Duration = rep.FinishedAt.Sub(rep.StartedAt).String()
	if firstStatus != nil {
		rep.InitialDroppedLines = firstStatus.DroppedLines
		rep.InitialTotalBans = firstStatus.TotalBans
		rep.InitialMemoryBytes = firstStatus.MemoryBytes
		rep.InitialGoroutines = firstStatus.Goroutines
	}
	if lastStatus != nil {
		rep.FinalDroppedLines = lastStatus.DroppedLines
		rep.FinalTotalBans = lastStatus.TotalBans
		rep.FinalMemoryBytes = lastStatus.MemoryBytes
		rep.FinalGoroutines = lastStatus.Goroutines
	}
	if rep.FinalMemoryBytes >= rep.InitialMemoryBytes {
		rep.MemoryGrowthBytes = rep.FinalMemoryBytes - rep.InitialMemoryBytes
	}
	rep.GoroutineGrowth = rep.FinalGoroutines - rep.InitialGoroutines
	for _, reconnects := range sourceReconnects {
		rep.SourceReconnects += reconnects
	}
	if rep.FinalDroppedLines >= rep.InitialDroppedLines {
		rep.DroppedLinesDelta = rep.FinalDroppedLines - rep.InitialDroppedLines
	}
	hardFail := false
	if rep.SamplesWithErrors > 0 {
		hardFail = true
		rep.VerdictReasons = append(rep.VerdictReasons, fmt.Sprintf("%d samples contained API errors", rep.SamplesWithErrors))
	}
	if rep.DoctorNotEnforcing > 0 {
		hardFail = true
		rep.VerdictReasons = append(rep.VerdictReasons, fmt.Sprintf("doctor reported not_enforcing %d times", rep.DoctorNotEnforcing))
	}
	if rep.DroppedLinesDelta > 0 {
		hardFail = true
		rep.VerdictReasons = append(rep.VerdictReasons, fmt.Sprintf("dropped lines increased by %d", rep.DroppedLinesDelta))
	}
	if rep.ReloadFailures > 0 || rep.ProbeFailures > 0 {
		hardFail = true
		rep.VerdictReasons = append(rep.VerdictReasons, "an explicitly requested reload/probe exercise failed")
	}
	warn := false
	if rep.InitialMemoryBytes > 0 && rep.MemoryGrowthBytes > 128*1024*1024 && rep.FinalMemoryBytes > rep.InitialMemoryBytes*2 {
		warn = true
		rep.VerdictReasons = append(rep.VerdictReasons, "allocated memory more than doubled and grew by over 128 MiB")
	}
	if rep.GoroutineGrowth > 100 {
		warn = true
		rep.VerdictReasons = append(rep.VerdictReasons, "goroutine count grew by more than 100")
	}
	if rep.DoctorDegraded > 0 || rep.MaxDegradedSources > 0 {
		warn = true
		rep.VerdictReasons = append(rep.VerdictReasons, "degraded health was observed")
	}
	if hardFail {
		rep.Verdict = "FAIL"
	} else if warn {
		rep.Verdict = "WARN"
	}
	return rep, nil
}

func markdownReport(r report) string {
	lines := []string{
		"# GoBan soak report", "",
		"- Verdict: **" + r.Verdict + "**",
		"- Duration: `" + r.Duration + "`",
		"- Samples: `" + strconv.Itoa(r.Samples) + "`",
		"- Samples with errors: `" + strconv.Itoa(r.SamplesWithErrors) + "`",
		"- Dropped-line delta: `" + strconv.FormatUint(r.DroppedLinesDelta, 10) + "`",
		"- Memory: `" + strconv.FormatUint(r.InitialMemoryBytes, 10) + " → " + strconv.FormatUint(r.FinalMemoryBytes, 10) + " bytes`",
		"- Peak memory: `" + strconv.FormatUint(r.PeakMemoryBytes, 10) + " bytes`",
		"- Goroutines: `" + strconv.Itoa(r.InitialGoroutines) + " → " + strconv.Itoa(r.FinalGoroutines) + "`",
		"- Peak goroutines: `" + strconv.Itoa(r.PeakGoroutines) + "`",
		"- Maximum degraded sources: `" + strconv.Itoa(r.MaxDegradedSources) + "`",
		"- Source reconnects: `" + strconv.FormatUint(r.SourceReconnects, 10) + "`",
		"- Reload exercises: `" + strconv.Itoa(r.ReloadSuccesses) + " passed / " + strconv.Itoa(r.ReloadFailures) + " failed`",
		"- Kernel probe exercises: `" + strconv.Itoa(r.ProbeSuccesses) + " passed / " + strconv.Itoa(r.ProbeFailures) + " failed`", "",
	}
	if len(r.VerdictReasons) > 0 {
		lines = append(lines, "## Findings", "")
		for _, reason := range r.VerdictReasons {
			lines = append(lines, "- "+reason)
		}
		lines = append(lines, "")
	}
	lines = append(lines, "Generated: `"+r.GeneratedAt.Format(time.RFC3339)+"`", "")
	return strings.Join(lines, "\n")
}

func writeJSONAtomic(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readJSON(path string, out any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, out)
}

func processAlive(pid int) bool {
	if pid < 1 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}
