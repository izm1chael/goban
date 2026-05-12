package ipset

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// CreateOptions controls hash:ip set creation.
type CreateOptions struct {
	Name     string
	Family   Family // IPv4 or IPv6
	HashSize uint32 // optional; 0 = kernel default (1024)
	MaxElem  uint32 // optional; 0 = kernel default (65536)
}

// Family selects the IP family of an ipset entry.
type Family uint8

const (
	IPv4 Family = Family(familyIPv4)
	IPv6 Family = Family(familyIPv6)
)

// FamilyOf returns the right Family for a netip.Addr (unmapped).
func FamilyOf(addr netip.Addr) Family {
	if addr.Is6() && !addr.Is4In6() {
		return IPv6
	}
	return IPv4
}

// Entry is one ipset entry: an IP plus optional kernel-side timeout.
type Entry struct {
	IP      netip.Addr
	Timeout uint32 // seconds; 0 = no kernel expiry (permanent)
}

// buildCreate constructs the netlink message for `ipset create NAME hash:ip
// family inet[6] timeout 0 -exist`. We always enable timeout support — even
// permanent bans use timeout=0 so the set definition is compatible.
//
// IPSET_FLAG_EXIST semantics (no-op if the set already exists) are achieved
// by NOT setting NLM_F_EXCL — the kernel checks the netlink header flag, not
// an IPSET_ATTR_FLAGS attribute. Earlier versions of this code added
// IPSET_ATTR_FLAGS at the top level which is rejected by modern kernels
// because that attribute isn't in ip_set_create_policy / ip_set_adt_policy.
func (c *Client) buildCreate(seq uint32, opts CreateOptions) []byte {
	flags := nlmFRequest | nlmFAck | nlmFCreate
	return buildMessage(cmdCreate, flags, seq, func(buf []byte) []byte {
		buf = encodeAttrU8(buf, attrProtocol, protocolVersion)
		buf = encodeAttrString(buf, attrSetName, opts.Name)
		buf = encodeAttrString(buf, attrTypeName, "hash:ip")
		buf = encodeAttrU8(buf, attrRevision, 1)
		buf = encodeAttrU8(buf, attrFamily, uint8(opts.Family))
		buf = nested(buf, attrData, func(buf []byte) []byte {
			if opts.HashSize > 0 {
				buf = encodeAttrU32BE(buf, attrHashSize, opts.HashSize)
			}
			if opts.MaxElem > 0 {
				buf = encodeAttrU32BE(buf, attrMaxElem, opts.MaxElem)
			}
			// Enable per-entry timeout support (mandatory for our use case).
			buf = encodeAttrU32BE(buf, attrTimeout, 0)
			return buf
		})
		return buf
	})
}

// buildAdd constructs the netlink message for `ipset add NAME IP timeout N
// -exist`. Family is required because the same ipset name can be either v4
// or v6 (we use separate v4/v6 sets, so the caller picks).
//
// Duplicate-Add semantics: the kernel returns -IPSET_ERR_EXIST when the IP
// is already in the set. Client.Add tolerates that errno so callers don't
// have to. Stricter behavior (error on duplicate) is not needed by GoBan.
func (c *Client) buildAdd(seq uint32, setName string, family Family, e Entry) []byte {
	flags := nlmFRequest | nlmFAck
	return buildMessage(cmdAdd, flags, seq, func(buf []byte) []byte {
		buf = encodeAttrU8(buf, attrProtocol, protocolVersion)
		buf = encodeAttrString(buf, attrSetName, setName)
		buf = nested(buf, attrData, func(buf []byte) []byte {
			buf = encodeIP(buf, family, e.IP)
			if e.Timeout > 0 {
				buf = encodeAttrU32BE(buf, attrTimeout, e.Timeout)
			}
			return buf
		})
		return buf
	})
}

// buildAddBatch constructs one netlink message containing multiple entries
// nested under IPSET_ATTR_ADT — the same mechanism `ipset restore` uses.
// All entries must share the same set name and family. Per-entry duplicate
// handling is delegated to the kernel's batch semantics: it processes each
// entry independently and we tolerate -IPSET_ERR_EXIST at the Client.AddBatch
// level (callers don't need to dedupe).
func (c *Client) buildAddBatch(seq uint32, setName string, family Family, entries []Entry) []byte {
	flags := nlmFRequest | nlmFAck
	return buildMessage(cmdAdd, flags, seq, func(buf []byte) []byte {
		buf = encodeAttrU8(buf, attrProtocol, protocolVersion)
		buf = encodeAttrString(buf, attrSetName, setName)
		buf = nested(buf, attrADT, func(buf []byte) []byte {
			for _, e := range entries {
				buf = nested(buf, attrData, func(buf []byte) []byte {
					buf = encodeIP(buf, family, e.IP)
					if e.Timeout > 0 {
						buf = encodeAttrU32BE(buf, attrTimeout, e.Timeout)
					}
					return buf
				})
			}
			return buf
		})
		return buf
	})
}

// buildDel constructs the netlink message for `ipset del NAME IP -exist`.
// "Missing entry is OK" semantics are handled by Client.Del which tolerates
// -ENOENT and -IPSET_ERR_EXIST from the kernel.
func (c *Client) buildDel(seq uint32, setName string, family Family, ip netip.Addr) []byte {
	flags := nlmFRequest | nlmFAck
	return buildMessage(cmdDel, flags, seq, func(buf []byte) []byte {
		buf = encodeAttrU8(buf, attrProtocol, protocolVersion)
		buf = encodeAttrString(buf, attrSetName, setName)
		buf = nested(buf, attrData, func(buf []byte) []byte {
			return encodeIP(buf, family, ip)
		})
		return buf
	})
}

// buildList constructs `ipset list NAME` (returns all entries via DUMP).
func (c *Client) buildList(seq uint32, setName string) []byte {
	flags := nlmFRequest | nlmFAck | nlmFDump
	return buildMessage(cmdList, flags, seq, func(buf []byte) []byte {
		buf = encodeAttrU8(buf, attrProtocol, protocolVersion)
		buf = encodeAttrString(buf, attrSetName, setName)
		return buf
	})
}

// buildFlush constructs `ipset flush NAME` (drop every entry, keep the set).
func (c *Client) buildFlush(seq uint32, setName string) []byte {
	flags := nlmFRequest | nlmFAck
	return buildMessage(cmdFlush, flags, seq, func(buf []byte) []byte {
		buf = encodeAttrU8(buf, attrProtocol, protocolVersion)
		buf = encodeAttrString(buf, attrSetName, setName)
		return buf
	})
}

// buildDestroy constructs `ipset destroy NAME`.
func (c *Client) buildDestroy(seq uint32, setName string) []byte {
	flags := nlmFRequest | nlmFAck
	return buildMessage(cmdDestroy, flags, seq, func(buf []byte) []byte {
		buf = encodeAttrU8(buf, attrProtocol, protocolVersion)
		buf = encodeAttrString(buf, attrSetName, setName)
		return buf
	})
}

// encodeIP appends a nested IPSET_ATTR_IP attribute containing either an
// IPv4 (4 bytes) or IPv6 (16 bytes) raw address in network byte order.
func encodeIP(buf []byte, family Family, ip netip.Addr) []byte {
	return nested(buf, attrIP, func(buf []byte) []byte {
		switch family {
		case IPv4:
			ip4 := ip.As4()
			return encodeAttrBytesBE(buf, attrIPv4, ip4[:])
		case IPv6:
			ip6 := ip.As16()
			return encodeAttrBytesBE(buf, attrIPv6, ip6[:])
		}
		return buf
	})
}

// validIPSetName mirrors the kernel's constraints on set names: 1-31 bytes,
// no '/' or whitespace. We do a cheap pre-check so misuse fails locally
// instead of via an opaque NLMSG_ERROR.
func validIPSetName(name string) error {
	if len(name) == 0 || len(name) > 31 {
		return fmt.Errorf("ipset name %q: must be 1-31 bytes", name)
	}
	for _, c := range []byte(name) {
		if c == '/' || c == ' ' || c == '\t' || c == 0 {
			return fmt.Errorf("ipset name %q: contains invalid byte", name)
		}
	}
	return nil
}

// asBigEndianU32 is a tiny helper used in tests.
func asBigEndianU32(v uint32) [4]byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return b
}
