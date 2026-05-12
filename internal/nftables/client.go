package nftables

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Client talks to the kernel nf_tables subsystem over a netfilter netlink
// socket. One Client serializes all requests onto the same socket; the
// kernel processes them in order. Safe for concurrent use — the mutex
// protects the underlying fd, sequence counter is atomic.
type Client struct {
	mu     sync.Mutex
	fd     int
	seq    atomic.Uint32
	closed bool
}

// New opens a NETLINK_NETFILTER socket and returns a Client.
func New() (*Client, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_NETFILTER)
	if err != nil {
		return nil, fmt.Errorf("netlink socket: %w", err)
	}
	addr := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	if err := unix.Bind(fd, addr); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("netlink bind: %w", err)
	}
	c := &Client{fd: fd}
	c.seq.Store(uint32(time.Now().UnixNano() & 0x7fffffff))
	return c, nil
}

// Close releases the underlying socket. Safe to call multiple times.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	return unix.Close(c.fd)
}

func (c *Client) nextSeq() uint32 { return c.seq.Add(1) }

// CreateTable creates one inet-family table.
func (c *Client) CreateTable(ctx context.Context, name string) error {
	if err := validName("table", name); err != nil {
		return err
	}
	seq := c.nextSeq()
	return c.sendOne(ctx, c.buildNewTable(seq, name), seq, false)
}

// CreateSet creates one timeout-bearing address set.
func (c *Client) CreateSet(ctx context.Context, table, name string, family EntryFamily) error {
	if err := validName("set", name); err != nil {
		return err
	}
	seq := c.nextSeq()
	return c.sendOne(ctx, c.buildNewSet(seq, table, name, family), seq, false)
}

// CreateChain creates the input-hooked filter chain.
func (c *Client) CreateChain(ctx context.Context, table, name string) error {
	if err := validName("chain", name); err != nil {
		return err
	}
	seq := c.nextSeq()
	return c.sendOne(ctx, c.buildNewChain(seq, table, name), seq, false)
}

// CreateDropRule creates one "saddr @set drop" rule.
func (c *Client) CreateDropRule(ctx context.Context, table, chain, setName string, family EntryFamily) error {
	seq := c.nextSeq()
	return c.sendOne(ctx, c.buildSetDropRule(seq, table, chain, setName, family), seq, false)
}

// Setup creates the table, sets, chain and drop rules. Idempotent — every
// object uses NLM_F_CREATE without NLM_F_EXCL so repeated calls after a
// daemon restart are no-ops.
func (c *Client) Setup(ctx context.Context, cfg SetupConfig) error {
	if err := validName("table", cfg.Table); err != nil {
		return err
	}
	if err := validName("set", cfg.SetV4); err != nil {
		return err
	}
	if cfg.IPv6 {
		if err := validName("set", cfg.SetV6); err != nil {
			return err
		}
	}
	if err := validName("chain", cfg.Chain); err != nil {
		return err
	}

	beginSeq := c.nextSeq()
	tableSeq := c.nextSeq()
	chainSeq := c.nextSeq()
	setV4Seq := c.nextSeq()
	ruleV4Seq := c.nextSeq()
	var setV6Seq, ruleV6Seq uint32
	if cfg.IPv6 {
		setV6Seq = c.nextSeq()
		ruleV6Seq = c.nextSeq()
	}
	endSeq := c.nextSeq()

	batch := batchBegin(beginSeq)
	batch = append(batch, c.buildNewTable(tableSeq, cfg.Table)...)
	batch = append(batch, c.buildNewChain(chainSeq, cfg.Table, cfg.Chain)...)
	batch = append(batch, c.buildNewSet(setV4Seq, cfg.Table, cfg.SetV4, IPv4)...)
	batch = append(batch, c.buildSetDropRule(ruleV4Seq, cfg.Table, cfg.Chain, cfg.SetV4, IPv4)...)
	if cfg.IPv6 {
		batch = append(batch, c.buildNewSet(setV6Seq, cfg.Table, cfg.SetV6, IPv6)...)
		batch = append(batch, c.buildSetDropRule(ruleV6Seq, cfg.Table, cfg.Chain, cfg.SetV6, IPv6)...)
	}
	batch = append(batch, batchEnd(endSeq)...)

	expectAcks := []uint32{tableSeq, chainSeq, setV4Seq, ruleV4Seq}
	if cfg.IPv6 {
		expectAcks = append(expectAcks, setV6Seq, ruleV6Seq)
	}
	return c.sendBatch(ctx, batch, expectAcks)
}

// AddElement inserts ip into the named set with a per-element TTL. If the
// kernel returns EEXIST, the client silently issues a del-then-add so the
// TTL is refreshed (matching the ipset backend's "refresh on duplicate"
// semantics that callers depend on).
func (c *Client) AddElement(ctx context.Context, table, setName string, family EntryFamily, ip netip.Addr, ttl time.Duration) error {
	addSeq := c.nextSeq()
	if err := c.sendOne(ctx, c.buildSetElemAdd(addSeq, table, setName, family, Entry{IP: ip, Timeout: secs(ttl)}), addSeq, false); err != nil {
		if errors.Is(err, syscall.EEXIST) {
			delSeq := c.nextSeq()
			if err := c.sendOne(ctx, c.buildSetElemDel(delSeq, table, setName, family, ip), delSeq, true); err != nil {
				return fmt.Errorf("refresh: del: %w", err)
			}
			addSeq2 := c.nextSeq()
			if err := c.sendOne(ctx, c.buildSetElemAdd(addSeq2, table, setName, family, Entry{IP: ip, Timeout: secs(ttl)}), addSeq2, false); err != nil {
				return fmt.Errorf("refresh: re-add: %w", err)
			}
			return nil
		}
		return err
	}
	return nil
}

// DelElement removes ip from the named set. ENOENT is tolerated (returning
// nil) so unbanning an IP that already aged out is not an error.
func (c *Client) DelElement(ctx context.Context, table, setName string, family EntryFamily, ip netip.Addr) error {
	seq := c.nextSeq()
	return c.sendOne(ctx, c.buildSetElemDel(seq, table, setName, family, ip), seq, true)
}

// ListElements returns every element currently in the named set, with each
// element's remaining timeout decoded from the response.
func (c *Client) ListElements(ctx context.Context, table, setName string) ([]ListedEntry, error) {
	seq := c.nextSeq()
	return c.dumpSetElements(ctx, seq, c.buildSetElemGet(seq, table, setName))
}

// DestroyTable removes the table and all its children. Used by Close(flush=true)
// — production callers usually leave the table in place so bans survive
// daemon restart.
func (c *Client) DestroyTable(ctx context.Context, name string) error {
	beginSeq := c.nextSeq()
	delSeq := c.nextSeq()
	endSeq := c.nextSeq()
	batch := batchBegin(beginSeq)
	batch = append(batch, c.buildDelTable(delSeq, name)...)
	batch = append(batch, batchEnd(endSeq)...)
	return c.sendBatch(ctx, batch, []uint32{delSeq})
}

// sendOne wraps one op in a BEGIN/END batch and waits for its ACK.
func (c *Client) sendOne(ctx context.Context, op []byte, opSeq uint32, tolerateENOENT bool) error {
	beginSeq := c.nextSeq()
	endSeq := c.nextSeq()
	batch := batchBegin(beginSeq)
	batch = append(batch, op...)
	batch = append(batch, batchEnd(endSeq)...)
	err := c.sendBatch(ctx, batch, []uint32{opSeq})
	if err != nil && tolerateENOENT && errors.Is(err, syscall.ENOENT) {
		return nil
	}
	return err
}

// sendBatch writes a fully-built batch to the kernel and waits for ACKs
// (or errors) for each op seq in expectAcks. The kernel processes the
// batch atomically and replies with one NLMSG_ERROR per message (errno=0
// for the BEGIN/END envelopes and the successful ops; non-zero for any
// op that failed).
func (c *Client) sendBatch(ctx context.Context, msg []byte, expectAcks []uint32) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return errors.New("nftables: client closed")
	}
	if err := c.setDeadlineFromContext(ctx); err != nil {
		return err
	}
	defer c.clearDeadline()
	if _, err := unix.Write(c.fd, msg); err != nil {
		return fmt.Errorf("netlink write: %w", err)
	}
	pending := make(map[uint32]struct{}, len(expectAcks))
	for _, s := range expectAcks {
		pending[s] = struct{}{}
	}
	buf := make([]byte, 16*1024)
	for len(pending) > 0 {
		n, err := unix.Read(c.fd, buf)
		if err != nil {
			return fmt.Errorf("netlink read: %w", err)
		}
		data := buf[:n]
		for len(data) >= nlMsghdrLen {
			msgLen := binary.LittleEndian.Uint32(data[0:4])
			if msgLen < nlMsghdrLen || int(msgLen) > len(data) {
				return fmt.Errorf("netlink: short or malformed message (len=%d, have=%d)", msgLen, len(data))
			}
			msgType := binary.LittleEndian.Uint16(data[4:6])
			msgSeq := binary.LittleEndian.Uint32(data[8:12])
			if uint32(msgType) == nlmsgError {
				if int(msgLen) < nlMsghdrLen+4 {
					return errors.New("netlink: truncated NLMSG_ERROR")
				}
				errno := int32(binary.LittleEndian.Uint32(data[nlMsghdrLen : nlMsghdrLen+4]))
				if _, want := pending[msgSeq]; want {
					if errno != 0 {
						return fmt.Errorf("nftables: %w", syscall.Errno(-errno))
					}
					delete(pending, msgSeq)
				}
			}
			data = data[alignTo(int(msgLen)):]
		}
	}
	return nil
}

// dumpSetElements writes a GETSETELEM and walks the kernel response,
// decoding one ListedEntry per set element until NLMSG_DONE arrives.
func (c *Client) dumpSetElements(ctx context.Context, seq uint32, msg []byte) ([]ListedEntry, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, errors.New("nftables: client closed")
	}
	if err := c.setDeadlineFromContext(ctx); err != nil {
		return nil, err
	}
	defer c.clearDeadline()
	if _, err := unix.Write(c.fd, msg); err != nil {
		return nil, fmt.Errorf("netlink write: %w", err)
	}
	var entries []ListedEntry
	buf := make([]byte, 64*1024)
	for {
		n, err := unix.Read(c.fd, buf)
		if err != nil {
			return nil, fmt.Errorf("netlink read: %w", err)
		}
		data := buf[:n]
		done, batch, err := parseSetElemChunk(seq, data)
		if err != nil {
			return nil, err
		}
		entries = append(entries, batch...)
		if done {
			return entries, nil
		}
	}
}

func (c *Client) setDeadlineFromContext(ctx context.Context) error {
	dl, ok := ctx.Deadline()
	if !ok {
		dl = time.Now().Add(5 * time.Second)
	}
	tv := unix.NsecToTimeval(time.Until(dl).Nanoseconds())
	if err := unix.SetsockoptTimeval(c.fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return fmt.Errorf("set rcvtimeo: %w", err)
	}
	if err := unix.SetsockoptTimeval(c.fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &tv); err != nil {
		return fmt.Errorf("set sndtimeo: %w", err)
	}
	return nil
}

func (c *Client) clearDeadline() {
	tv := unix.NsecToTimeval(0)
	_ = unix.SetsockoptTimeval(c.fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	_ = unix.SetsockoptTimeval(c.fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &tv)
}
