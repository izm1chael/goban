package control

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// Client talks to a goban daemon over its unix socket.
type Client struct {
	socketPath string
	http       *http.Client
}

// NewClient constructs a Client that dials the given unix socket on every
// request. The underlying http.Client uses a 10s default timeout.
func NewClient(socketPath string) *Client {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socketPath)
		},
	}
	return &Client{
		socketPath: socketPath,
		http: &http.Client{
			Transport: tr,
			Timeout:   10 * time.Second,
		},
	}
}

// Status retrieves /status.
func (c *Client) Status(ctx context.Context) (StatusResp, error) {
	var out StatusResp
	err := c.get(ctx, "/status", &out)
	return out, err
}

// Rules retrieves /rules.
func (c *Client) Rules(ctx context.Context) ([]RuleInfo, error) {
	var out []RuleInfo
	err := c.get(ctx, "/rules", &out)
	return out, err
}

// Banned retrieves /banned.
func (c *Client) Banned(ctx context.Context) ([]BanInfo, error) {
	var out []BanInfo
	err := c.get(ctx, "/banned", &out)
	return out, err
}

// Unban posts to /unban.
func (c *Client) Unban(ctx context.Context, ip string) error {
	return c.post(ctx, "/unban", UnbanReq{IP: ip}, nil)
}

// Ban posts to /ban.
func (c *Client) Ban(ctx context.Context, ip, rule string, ttl time.Duration) error {
	return c.post(ctx, "/ban", BanReq{IP: ip, Rule: rule, TTL: ttl}, nil)
}

// Reload triggers a hot config reload on the daemon. Errors from validation,
// immutable-field checks, or runtime failures are returned verbatim from the
// daemon for the operator to see.
func (c *Client) Reload(ctx context.Context) error {
	return c.post(ctx, "/reload", struct{}{}, nil)
}

func (c *Client) get(ctx context.Context, path string, out any) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://goban"+path, nil)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("GET %s: %s: %s", path, resp.Status, string(body))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *Client) post(ctx context.Context, path string, body any, out any) error {
	buf, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://goban"+path, bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("POST %s: %s: %s", path, resp.Status, string(b))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
