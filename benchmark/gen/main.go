// Command gen writes synthetic sshd-failure log lines to a target file at a
// configurable rate. Used by the benchmark and soak harness to drive both
// GoBan and fail2ban under controlled load.
//
// Two operating modes:
//
//  1. Fixed run (default): writes at --rate for --duration then exits.
//
//  2. Soak mode (--control-fifo PATH): reads commands from a FIFO so the
//     orchestrator can change rate, cardinality, or trigger bursts without
//     restarting the generator. Commands are newline-terminated text:
//
//     rate <n>           change steady rate (lines/sec)
//     ips <n>            grow unique IP pool to n (only grows, never shrinks)
//     burst <n> <sec>    burst at <n> lines/sec for <sec> seconds, then resume
//     rotate <newpath>   reopen log file (caller has already mv'd the path)
//     quit               exit
//
//     Stats are appended to --stats-out as CSV: t_sec,lines_written.
//
// No cryptographic randomness is used; outputs are deterministic for given
// flags/commands, which is desirable for reproducibility.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"sync"
	"time"
)

type state struct {
	mu         sync.Mutex
	rate       int
	ips        []string
	burstUntil time.Time
	burstRate  int
	rotateTo   string
}

func main() {
	var (
		target      = flag.String("target", "/tmp/bench-auth.log", "log file to append to")
		rate        = flag.Int("rate", 1000, "lines per second")
		duration    = flag.Duration("duration", 60*time.Second, "total run duration (ignored if --control-fifo is set)")
		uniqueIPs   = flag.Int("unique-ips", 200, "starting unique IPs to cycle through")
		controlFIFO = flag.String("control-fifo", "", "optional named pipe for soak-mode commands")
		statsOut    = flag.String("stats-out", "", "append per-second line-count CSV to this path")
		ipv6        = flag.Bool("ipv6", false, "use ipv6 source addresses")
	)
	flag.Parse()

	st := &state{rate: *rate}
	st.growIPs(*uniqueIPs, *ipv6)

	f, err := os.OpenFile(*target, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open:", err)
		os.Exit(1)
	}
	currentTarget := *target

	var statsFile *os.File
	if *statsOut != "" {
		statsFile, err = os.OpenFile(*statsOut, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			fmt.Fprintln(os.Stderr, "stats:", err)
			os.Exit(1)
		}
		fmt.Fprintln(statsFile, "t_sec,lines_written")
	}

	soakMode := *controlFIFO != ""
	if soakMode {
		go readCommands(*controlFIFO, st, *ipv6)
	}

	deadline := time.Now().Add(*duration)
	const pid = 12345
	template := "%s host sshd[%d]: Failed password for invalid user benchuser from %s port %d ssh2\n"
	start := time.Now()
	cursor := 0
	written := 0
	statsBucket := 0
	statsTickedAt := start

	w := bufio.NewWriterSize(f, 64*1024)
	for {
		st.mu.Lock()
		curRate := st.rate
		if !st.burstUntil.IsZero() && time.Now().Before(st.burstUntil) {
			curRate = st.burstRate
		} else if !st.burstUntil.IsZero() {
			st.burstUntil = time.Time{}
		}
		ipsCopy := st.ips
		rotateTo := st.rotateTo
		st.rotateTo = ""
		st.mu.Unlock()

		if rotateTo != "" {
			_ = w.Flush()
			_ = f.Close()
			f, err = os.OpenFile(rotateTo, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
			if err != nil {
				fmt.Fprintln(os.Stderr, "rotate open:", err)
				os.Exit(1)
			}
			w = bufio.NewWriterSize(f, 64*1024)
			currentTarget = rotateTo
		}
		_ = currentTarget

		if !soakMode && time.Now().After(deadline) {
			break
		}

		// 100 ticks/sec drive
		ticksPerSec := 100
		if curRate < 100 {
			ticksPerSec = curRate
			if ticksPerSec < 1 {
				time.Sleep(100 * time.Millisecond)
				continue
			}
		}
		perTick := curRate / ticksPerSec
		if perTick < 1 {
			perTick = 1
		}
		interval := time.Second / time.Duration(ticksPerSec)
		now := time.Now()
		nowStr := now.Format("Jan _2 15:04:05")
		for i := 0; i < perTick; i++ {
			ip := ipsCopy[cursor%len(ipsCopy)]
			port := 1024 + (cursor*101)%60000
			cursor++
			fmt.Fprintf(w, template, nowStr, pid, ip, port)
			written++
			statsBucket++
		}
		if statsFile != nil && now.Sub(statsTickedAt) >= time.Second {
			fmt.Fprintf(statsFile, "%.0f,%d\n", now.Sub(start).Seconds(), statsBucket)
			statsBucket = 0
			statsTickedAt = now
			_ = w.Flush()
		}
		time.Sleep(interval)
	}
	_ = w.Flush()
	_ = f.Close()
	fmt.Fprintf(os.Stderr, "wrote %d lines\n", written)
}

func (s *state) growIPs(target int, ipv6 bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.ips); i < target; i++ {
		var ip string
		if ipv6 {
			ip = fmt.Sprintf("2001:db8::%x:%x", (i/0xffff)+1, i%0xffff)
		} else {
			// 198.51.0.0/16 is reserved for documentation — safe for synthetic
			// loads. We can address 65k IPs in that range.
			ip = fmt.Sprintf("198.51.%d.%d", (i/254)+1, (i%254)+1)
		}
		s.ips = append(s.ips, ip)
	}
}

func readCommands(fifo string, s *state, ipv6 bool) {
	for {
		f, err := os.OpenFile(fifo, os.O_RDONLY, 0)
		if err != nil {
			fmt.Fprintln(os.Stderr, "fifo open:", err)
			return
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := sc.Text()
			var verb string
			var a, b int
			var path string
			if _, err := fmt.Sscanf(line, "rate %d", &a); err == nil {
				verb = "rate"
			} else if _, err := fmt.Sscanf(line, "ips %d", &a); err == nil {
				verb = "ips"
			} else if _, err := fmt.Sscanf(line, "burst %d %d", &a, &b); err == nil {
				verb = "burst"
			} else if _, err := fmt.Sscanf(line, "rotate %s", &path); err == nil {
				verb = "rotate"
			} else if line == "quit" {
				os.Exit(0)
			}
			switch verb {
			case "rate":
				s.mu.Lock()
				s.rate = a
				s.mu.Unlock()
			case "ips":
				s.growIPs(a, ipv6)
			case "burst":
				s.mu.Lock()
				s.burstRate = a
				s.burstUntil = time.Now().Add(time.Duration(b) * time.Second)
				s.mu.Unlock()
			case "rotate":
				s.mu.Lock()
				s.rotateTo = path
				s.mu.Unlock()
			}
		}
		_ = f.Close()
	}
}
