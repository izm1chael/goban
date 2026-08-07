package corpus

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/izm1chael/goban/internal/matcher"
)

const defaultExternalMaxBytes int64 = 64 << 20

type FetchResult struct {
	ID      string `json:"id"`
	Path    string `json:"path"`
	Bytes   int64  `json:"bytes"`
	SHA256  string `json:"sha256"`
	License string `json:"license"`
	Adapter string `json:"adapter"`
	Rule    string `json:"rule,omitempty"`
}

func Fetch(ctx context.Context, client *http.Client, src ExternalSource, root string) (FetchResult, error) {
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Minute}
	}
	maxBytes := src.MaxBytes
	if maxBytes == 0 {
		maxBytes = defaultExternalMaxBytes
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src.URL, nil)
	if err != nil {
		return FetchResult{}, err
	}
	req.Header.Set("User-Agent", "goban-corpus/1")
	resp, err := client.Do(req)
	if err != nil {
		return FetchResult{}, fmt.Errorf("download %s: %w", src.ID, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return FetchResult{}, fmt.Errorf("download %s: HTTP %s", src.ID, resp.Status)
	}
	if resp.ContentLength > maxBytes {
		return FetchResult{}, fmt.Errorf("download %s: content length %d exceeds max_bytes %d", src.ID, resp.ContentLength, maxBytes)
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return FetchResult{}, err
	}
	destination := filepath.Join(root, filepath.Base(src.FileName))
	out, err := os.CreateTemp(root, ".goban-corpus-download-*")
	if err != nil {
		return FetchResult{}, err
	}
	temporary := out.Name()
	if err := out.Chmod(0o600); err != nil {
		_ = out.Close()
		_ = os.Remove(temporary)
		return FetchResult{}, err
	}
	hasher := sha256.New()
	limited := io.LimitReader(resp.Body, maxBytes+1)
	written, copyErr := io.Copy(io.MultiWriter(out, hasher), limited)
	closeErr := out.Close()
	if copyErr != nil {
		_ = os.Remove(temporary)
		return FetchResult{}, copyErr
	}
	if closeErr != nil {
		_ = os.Remove(temporary)
		return FetchResult{}, closeErr
	}
	if written > maxBytes {
		_ = os.Remove(temporary)
		return FetchResult{}, fmt.Errorf("download %s exceeded max_bytes %d", src.ID, maxBytes)
	}
	if err := os.Rename(temporary, destination); err != nil {
		_ = os.Remove(temporary)
		return FetchResult{}, err
	}
	return FetchResult{
		ID: src.ID, Path: destination, Bytes: written,
		SHA256: hex.EncodeToString(hasher.Sum(nil)), License: src.License,
		Adapter: src.Adapter, Rule: src.Rule,
	}, nil
}

type Fail2BanCase struct {
	Line        string
	WantMatch   bool
	ExpectedRaw string
}

type Fail2BanReport struct {
	File          string `json:"file"`
	Total         int    `json:"total"`
	ExpectedHits  int    `json:"expected_hits"`
	ExpectedMiss  int    `json:"expected_misses"`
	TruePositive  int    `json:"true_positive"`
	TrueNegative  int    `json:"true_negative"`
	FalsePositive int    `json:"false_positive"`
	FalseNegative int    `json:"false_negative"`
	HostMismatch  int    `json:"host_mismatch"`
	Unannotated   int    `json:"unannotated"`
}

func ParseFail2Ban(r io.Reader) ([]Fail2BanCase, int, error) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 4<<20)
	var pending *Fail2BanCase
	cases := make([]Fail2BanCase, 0, 256)
	unannotated := 0
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "# failJSON:") {
			raw := strings.TrimSpace(strings.TrimPrefix(trimmed, "# failJSON:"))
			var meta struct {
				Match bool   `json:"match"`
				Host  string `json:"host"`
			}
			if err := json.Unmarshal([]byte(raw), &meta); err != nil {
				return nil, unannotated, fmt.Errorf("parse failJSON %q: %w", raw, err)
			}
			pending = &Fail2BanCase{WantMatch: meta.Match, ExpectedRaw: meta.Host}
			continue
		}
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if pending == nil {
			unannotated++
			continue
		}
		pending.Line = line
		cases = append(cases, *pending)
		pending = nil
	}
	if err := scanner.Err(); err != nil {
		return nil, unannotated, err
	}
	return cases, unannotated, nil
}

func CompareFail2Ban(path string, m *matcher.Matcher) (Fail2BanReport, error) {
	f, err := os.Open(path)
	if err != nil {
		return Fail2BanReport{}, err
	}
	defer f.Close()
	cases, unannotated, err := ParseFail2Ban(f)
	if err != nil {
		return Fail2BanReport{}, err
	}
	report := Fail2BanReport{File: path, Total: len(cases), Unannotated: unannotated}
	positiveLines := make(map[string]struct{}, len(cases))
	for _, tc := range cases {
		if tc.WantMatch {
			positiveLines[tc.Line] = struct{}{}
		}
	}
	for _, tc := range cases {
		gotIP, _, got := m.Match(tc.Line)
		if tc.WantMatch {
			report.ExpectedHits++
			if !got {
				report.FalseNegative++
				continue
			}
			report.TruePositive++
			if tc.ExpectedRaw != "" {
				if expected, err := parseExternalAddr(tc.ExpectedRaw); err == nil && gotIP != expected {
					report.HostMismatch++
				}
			}
		} else {
			report.ExpectedMiss++
			if _, alsoPositive := positiveLines[tc.Line]; alsoPositive {
				continue
			}
			if got {
				report.FalsePositive++
			} else {
				report.TrueNegative++
			}
		}
	}
	return report, nil
}

func parseExternalAddr(raw string) (netip.Addr, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.ContainsAny(raw, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") {
		return netip.Addr{}, errors.New("hostname or empty")
	}
	if addr, err := netip.ParseAddr(strings.Trim(raw, "[]")); err == nil {
		return addr.Unmap(), nil
	}
	if ap, err := netip.ParseAddrPort(raw); err == nil {
		return ap.Addr().Unmap(), nil
	}
	return netip.Addr{}, fmt.Errorf("not an address: %q", raw)
}

type ScanReport struct {
	File       string   `json:"file"`
	Lines      int      `json:"lines"`
	Matches    int      `json:"matches"`
	UniqueIPs  int      `json:"unique_ips"`
	SampleIPs  []string `json:"sample_ips,omitempty"`
	ReadErrors int      `json:"read_errors"`
}

func Scan(path string, m *matcher.Matcher, sampleLimit int) (ScanReport, error) {
	f, err := os.Open(path)
	if err != nil {
		return ScanReport{}, err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 4<<20)
	report := ScanReport{File: path}
	unique := make(map[netip.Addr]struct{})
	for scanner.Scan() {
		report.Lines++
		if ip, _, ok := m.Match(scanner.Text()); ok {
			report.Matches++
			unique[ip] = struct{}{}
			if len(report.SampleIPs) < sampleLimit {
				report.SampleIPs = append(report.SampleIPs, ip.String())
			}
		}
	}
	if err := scanner.Err(); err != nil {
		report.ReadErrors++
		return report, err
	}
	report.UniqueIPs = len(unique)
	return report, nil
}
