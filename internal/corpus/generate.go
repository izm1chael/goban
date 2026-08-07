package corpus

import (
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"time"
)

type GenerateOptions struct {
	Output  string
	Lines   int
	Seed    int64
	Profile string
}

type GenerateReport struct {
	Output    string         `json:"output"`
	Lines     int            `json:"lines"`
	Seed      int64          `json:"seed"`
	Profile   string         `json:"profile"`
	Expected  map[string]int `json:"expected_matches"`
	Generated time.Time      `json:"generated_at"`
}

func Generate(opts GenerateOptions) (GenerateReport, error) {
	if opts.Output == "" {
		return GenerateReport{}, fmt.Errorf("output path is required")
	}
	if opts.Lines < 1 {
		return GenerateReport{}, fmt.Errorf("lines must be >= 1")
	}
	if opts.Seed == 0 {
		opts.Seed = 1
	}
	if opts.Profile == "" {
		opts.Profile = "mixed"
	}
	if opts.Profile != "mixed" && opts.Profile != "sshd" && opts.Profile != "web" && opts.Profile != "mail" {
		return GenerateReport{}, fmt.Errorf("profile %q: want mixed, sshd, web, or mail", opts.Profile)
	}
	if dir := filepath.Dir(opts.Output); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return GenerateReport{}, err
		}
	}
	f, err := os.OpenFile(opts.Output, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return GenerateReport{}, err
	}
	writer := bufio.NewWriterSize(f, 256*1024)
	rng := rand.New(rand.NewSource(opts.Seed))
	expected := make(map[string]int)
	for i := 0; i < opts.Lines; i++ {
		rule, line := generatedLine(rng, opts.Profile, i)
		if _, err := writer.WriteString(line + "\n"); err != nil {
			_ = f.Close()
			return GenerateReport{}, err
		}
		if rule != "" {
			expected[rule]++
		}
	}
	if err := writer.Flush(); err != nil {
		_ = f.Close()
		return GenerateReport{}, err
	}
	if err := f.Close(); err != nil {
		return GenerateReport{}, err
	}
	return GenerateReport{Output: opts.Output, Lines: opts.Lines, Seed: opts.Seed, Profile: opts.Profile, Expected: expected, Generated: time.Now().UTC()}, nil
}

func generatedLine(rng *rand.Rand, profile string, index int) (string, string) {
	families := []string{"sshd", "nginx-http-auth", "apache-auth", "postfix-sasl", "dovecot", "traefik-auth", "negative"}
	if profile == "sshd" {
		families = []string{"sshd", "sshd", "negative"}
	} else if profile == "web" {
		families = []string{"nginx-http-auth", "apache-auth", "traefik-auth", "negative"}
	} else if profile == "mail" {
		families = []string{"postfix-sasl", "dovecot", "negative"}
	}
	family := families[rng.Intn(len(families))]
	ipv6 := rng.Intn(5) == 0
	ip := generatedIP(rng, ipv6)
	pid := 1000 + rng.Intn(50000)
	port := 1024 + rng.Intn(64000)
	second := index % 60
	switch family {
	case "sshd":
		return family, fmt.Sprintf("Aug  6 19:%02d:%02d host sshd[%d]: Failed password for invalid user user%d from %s port %d ssh2", (index/60)%60, second, pid, rng.Intn(10000), ip, port)
	case "nginx-http-auth":
		return family, fmt.Sprintf("%s - - [06/Aug/2026:19:%02d:%02d +0100] \"POST /login HTTP/1.1\" 401 153 \"-\" \"Mozilla/5.0\"", ip, (index/60)%60, second)
	case "apache-auth":
		client := ip
		if ipv6 {
			client = "[" + ip + "]"
		}
		return family, fmt.Sprintf("[Thu Aug 06 19:%02d:%02d.000000 2026] [auth_basic:error] [pid %d] [client %s:%d] AH01617: user user%d: authentication failure for /private", (index/60)%60, second, pid, client, port, rng.Intn(10000))
	case "postfix-sasl":
		return family, fmt.Sprintf("Aug  6 19:%02d:%02d mail postfix/smtpd[%d]: warning: unknown[%s]: SASL LOGIN authentication failed: authentication failure", (index/60)%60, second, pid, ip)
	case "dovecot":
		return family, fmt.Sprintf("Aug  6 19:%02d:%02d mail dovecot: imap-login: Disconnected (auth failed, 1 attempts in 2 secs): user=<user%d>, method=PLAIN, rip=%s, lip=192.0.2.10, TLS", (index/60)%60, second, rng.Intn(10000), ip)
	case "traefik-auth":
		return family, fmt.Sprintf("{\"ClientHost\":\"%s\",\"RequestMethod\":\"GET\",\"RequestPath\":\"/private\",\"DownstreamStatus\":401,\"RequestCount\":%d}", ip, index+1)
	default:
		negatives := []string{
			fmt.Sprintf("Aug  6 19:%02d:%02d host sshd[%d]: Accepted publickey for admin from %s port %d ssh2", (index/60)%60, second, pid, ip, port),
			fmt.Sprintf("%s - - [06/Aug/2026:19:%02d:%02d +0100] \"GET /health HTTP/1.1\" 200 2 \"-\" \"kube-probe\"", ip, (index/60)%60, second),
			fmt.Sprintf("Aug  6 19:%02d:%02d mail postfix/smtpd[%d]: connect from trusted[%s]", (index/60)%60, second, pid, ip),
			fmt.Sprintf("{\"ClientHost\":\"%s\",\"RequestPath\":\"/\",\"DownstreamStatus\":200}", ip),
		}
		return "", negatives[rng.Intn(len(negatives))]
	}
}

func generatedIP(rng *rand.Rand, ipv6 bool) string {
	if ipv6 {
		return fmt.Sprintf("2001:db8:%x:%x::%x", rng.Intn(0xffff), rng.Intn(0xffff), 1+rng.Intn(0xfffe))
	}
	return fmt.Sprintf("198.51.%d.%d", rng.Intn(100), 1+rng.Intn(253))
}
