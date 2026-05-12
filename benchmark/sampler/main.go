// Command sampler watches a PID and emits CSV samples of CPU time and RSS
// every interval. On exit (signal or PID gone) it prints a one-line summary.
//
// Output columns: t_sec,cpu_pct,rss_kb
package main

import (
	"flag"
	"fmt"
	"math"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func main() {
	var (
		pid      = flag.Int("pid", 0, "PID to watch")
		out      = flag.String("out", "", "CSV output path (default stdout)")
		interval = flag.Duration("interval", 200*time.Millisecond, "sampling interval")
		duration = flag.Duration("duration", 0, "max run time (0 = until PID exits)")
	)
	flag.Parse()

	if *pid == 0 {
		fmt.Fprintln(os.Stderr, "pid required")
		os.Exit(1)
	}

	var w *os.File = os.Stdout
	if *out != "" {
		var err error
		w, err = os.Create(*out)
		if err != nil {
			fmt.Fprintln(os.Stderr, "create:", err)
			os.Exit(1)
		}
		defer w.Close()
	}
	fmt.Fprintln(w, "t_sec,cpu_pct,rss_kb")

	clkTck := float64(getClkTck())

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	ticker := time.NewTicker(*interval)
	defer ticker.Stop()

	start := time.Now()
	var prevTotal float64
	var prevWall float64
	var samples int
	var sumCPU, maxCPU, maxRSS float64

	deadline := time.Time{}
	if *duration > 0 {
		deadline = start.Add(*duration)
	}

	for {
		select {
		case <-sigCh:
			summary(samples, sumCPU, maxCPU, maxRSS)
			return
		case t := <-ticker.C:
			if !deadline.IsZero() && t.After(deadline) {
				summary(samples, sumCPU, maxCPU, maxRSS)
				return
			}
			utime, stime, rssKB, ok := readStat(*pid)
			if !ok {
				summary(samples, sumCPU, maxCPU, maxRSS)
				return
			}
			total := (utime + stime) / clkTck
			wall := t.Sub(start).Seconds()
			var cpu float64
			if samples > 0 {
				dWall := wall - prevWall
				if dWall > 0 {
					cpu = 100 * (total - prevTotal) / dWall
				}
			}
			prevTotal = total
			prevWall = wall
			fmt.Fprintf(w, "%.3f,%.2f,%.0f\n", wall, cpu, rssKB)
			if samples > 0 {
				sumCPU += cpu
				if cpu > maxCPU {
					maxCPU = cpu
				}
			}
			if rssKB > maxRSS {
				maxRSS = rssKB
			}
			samples++
		}
	}
}

func readStat(pid int) (utime, stime, rssKB float64, ok bool) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, 0, 0, false
	}
	// Field 1 is pid, field 2 is "(comm)" which may contain spaces. Skip up
	// to the last ')' then split the rest.
	rparen := strings.LastIndex(string(data), ")")
	if rparen < 0 || rparen+2 >= len(data) {
		return 0, 0, 0, false
	}
	fields := strings.Fields(string(data[rparen+2:]))
	if len(fields) < 22 {
		return 0, 0, 0, false
	}
	// After the (comm) field is removed, fields[0] is state.
	// utime is original field 14 → index 14-3 = 11
	// stime is field 15 → index 12
	// rss is field 24 → index 21 (in pages)
	utime, _ = parse(fields[11])
	stime, _ = parse(fields[12])
	rssPages, _ := parse(fields[21])
	rssKB = rssPages * float64(os.Getpagesize()) / 1024
	return utime, stime, rssKB, true
}

func parse(s string) (float64, error) { return strconv.ParseFloat(s, 64) }

// getClkTck returns the kernel's user_hz (clock ticks per second) — needed
// to convert jiffies from /proc/PID/stat into seconds. Read once at startup.
// Standard Linux is 100 on x86_64; we fall back to that if reading fails.
func getClkTck() int64 {
	// On Linux, sysconf(_SC_CLK_TCK) is the canonical source. cgo would let
	// us call it directly; without cgo we just default to 100, which is the
	// kernel default on every distro shipped in the last decade.
	return 100
}

func summary(samples int, sumCPU, maxCPU, maxRSS float64) {
	mean := 0.0
	if samples > 1 {
		mean = sumCPU / float64(samples-1)
	}
	fmt.Fprintf(os.Stderr, "samples=%d mean_cpu=%.2f%% peak_cpu=%.2f%% peak_rss=%.0fKB\n",
		samples, mean, math.Max(maxCPU, 0), maxRSS)
}
