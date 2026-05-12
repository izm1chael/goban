package ipset

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

// IPSet kernel error codes (from include/uapi/linux/netfilter/ipset/ip_set.h).
// The kernel returns these as the errno in NLMSG_ERROR responses.
const (
	ipsetErrPrivate   = 4096
	ipsetErrProtocol  = 4097
	ipsetErrFindType  = 4098
	ipsetErrMaxSets   = 4099
	ipsetErrExist     = 4103 // entry already in set / set already exists
	ipsetErrInvalidIP = 4104
)

// Client talks to the kernel ipset subsystem over a netfilter netlink socket.
// One Client serializes all requests onto the same socket; the kernel
// processes them in order. Safe for concurrent use.
type Client struct {
	mu     sync.Mutex
	fd     int
	seq    atomic.Uint32
	closed bool
}

// New opens a NETLINK_NETFILTER socket and returns a Client. Caller must
// Close to release the file descriptor.
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

// ---- public commands ----

// Create issues an IPSET_CMD_CREATE message. NLM_F_CREATE without NLM_F_EXCL
// means "create or no-op if it already exists", which matches the `ipset
// create ... -exist` flag.
func (c *Client) Create(ctx context.Context, opts CreateOptions) error {
	if err := validIPSetName(opts.Name); err != nil {
		return err
	}
	seq := c.nextSeq()
	return c.doRequest(ctx, seq, c.buildCreate(seq, opts), false)
}

// Add inserts ip into the set. If the entry already exists, this is a no-op
// — we tolerate -IPSET_ERR_EXIST from the kernel since rebanning a
// known-bad IP is normal under our threshold semantics.
func (c *Client) Add(ctx context.Context, setName string, family Family, ip netip.Addr, timeout time.Duration) error {
	if err := validIPSetName(setName); err != nil {
		return err
	}
	seq := c.nextSeq()
	return c.doRequest(ctx, seq, c.buildAdd(seq, setName, family, Entry{IP: ip, Timeout: secs(timeout)}), true)
}

// AddBatch inserts many entries in one netlink message. All entries must
// share the same family and target set. Duplicate entries are tolerated.
func (c *Client) AddBatch(ctx context.Context, setName string, family Family, entries []Entry) error {
	if len(entries) == 0 {
		return nil
	}
	if err := validIPSetName(setName); err != nil {
		return err
	}
	seq := c.nextSeq()
	return c.doRequest(ctx, seq, c.buildAddBatch(seq, setName, family, entries), true)
}

// Del removes ip from the set. Missing entries are tolerated; ENOENT from
// the kernel is treated as success.
func (c *Client) Del(ctx context.Context, setName string, family Family, ip netip.Addr) error {
	if err := validIPSetName(setName); err != nil {
		return err
	}
	seq := c.nextSeq()
	return c.doRequest(ctx, seq, c.buildDel(seq, setName, family, ip), true)
}

// Flush removes every entry from the named set.
func (c *Client) Flush(ctx context.Context, setName string) error {
	if err := validIPSetName(setName); err != nil {
		return err
	}
	seq := c.nextSeq()
	return c.doRequest(ctx, seq, c.buildFlush(seq, setName), true)
}

// Destroy removes the entire set. Tolerates ENOENT.
func (c *Client) Destroy(ctx context.Context, setName string) error {
	if err := validIPSetName(setName); err != nil {
		return err
	}
	seq := c.nextSeq()
	return c.doRequest(ctx, seq, c.buildDestroy(seq, setName), true)
}

// List enumerates entries in the named set. Returns nil and no error when
// the set is empty.
func (c *Client) List(ctx context.Context, setName string) ([]Entry, error) {
	if err := validIPSetName(setName); err != nil {
		return nil, err
	}
	seq := c.nextSeq()
	msg := c.buildList(seq, setName)
	return c.doDump(ctx, seq, msg)
}

// ---- I/O ----

func (c *Client) doRequest(ctx context.Context, seq uint32, msg []byte, tolerateDuplicate bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return errors.New("ipset: client closed")
	}
	if err := c.setDeadlineFromContext(ctx); err != nil {
		return err
	}
	defer c.clearDeadline()

	if _, err := unix.Write(c.fd, msg); err != nil {
		return fmt.Errorf("netlink write: %w", err)
	}
	return c.readAck(seq, tolerateDuplicate)
}

func (c *Client) doDump(ctx context.Context, seq uint32, msg []byte) ([]Entry, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, errors.New("ipset: client closed")
	}
	if err := c.setDeadlineFromContext(ctx); err != nil {
		return nil, err
	}
	defer c.clearDeadline()

	if _, err := unix.Write(c.fd, msg); err != nil {
		return nil, fmt.Errorf("netlink write: %w", err)
	}

	var entries []Entry
	buf := make([]byte, 64*1024)
	for {
		n, err := unix.Read(c.fd, buf)
		if err != nil {
			return nil, fmt.Errorf("netlink read: %w", err)
		}
		data := buf[:n]
		done, batch, err := parseListChunk(seq, data)
		if err != nil {
			return nil, err
		}
		entries = append(entries, batch...)
		if done {
			return entries, nil
		}
	}
}

func (c *Client) readAck(seq uint32, tolerateDuplicate bool) error {
	buf := make([]byte, 8192)
	for {
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
			if uint32(msgType) == nlmsgError && msgSeq == seq {
				if int(msgLen) < nlMsghdrLen+4 {
					return errors.New("netlink: truncated NLMSG_ERROR")
				}
				errno := int32(binary.LittleEndian.Uint32(data[nlMsghdrLen : nlMsghdrLen+4]))
				if errno == 0 {
					return nil
				}
				code := -errno
				if tolerateDuplicate {
					// Add: tolerate IPSET_ERR_EXIST (entry already in set).
					// Del: tolerate ENOENT and IPSET_ERR_EXIST (semantics swap
					// between kernel versions for missing-entry-on-del).
					if code == ipsetErrExist || code == int32(syscall.ENOENT) {
						return nil
					}
				}
				return fmt.Errorf("ipset: %w", syscall.Errno(code))
			}
			data = data[alignTo(int(msgLen)):]
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

func secs(d time.Duration) uint32 {
	s := int64(d.Seconds())
	if s < 0 {
		return 0
	}
	if s > int64(^uint32(0)) {
		return ^uint32(0)
	}
	return uint32(s)
}
