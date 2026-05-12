// Package ipset is a tiny netlink-direct client for the kernel ipset
// subsystem. It replaces the per-ban fork+exec of the ipset(8) binary that
// the v1 banner used, which the benchmark showed dominating the daemon's CPU
// under sustained load.
//
// The protocol constants and message layout transcribe the public ipset
// kernel ABI from `include/uapi/linux/netfilter/ipset/ip_set.h` (kernel
// version-stable since 3.x). We support exactly the commands GoBan needs:
//
//	CREATE, ADD, DEL, LIST, FLUSH, DESTROY
//
// Anything else (RENAME, SWAP, TEST, etc.) is intentionally absent — adding
// them later is straightforward, but keeping the surface area small reduces
// the bug budget for code that talks raw netlink.
package ipset

import (
	"encoding/binary"
)

// Netfilter netlink subsystem id for ipset (NFNL_SUBSYS_IPSET).
const subsysIPSet = 6

// IPSet wire protocol version we speak. The kernel accepts both 6 and 7;
// version 7 (since kernel 4.x) is the well-supported current value.
const protocolVersion = 7

// ipset command types. Encoded into the top 8 bits of nlmsghdr.Type along
// with the subsystem id in the bottom 8 bits.
const (
	cmdCreate  uint8 = 2
	cmdDestroy uint8 = 3
	cmdFlush   uint8 = 4
	cmdList    uint8 = 7
	cmdAdd     uint8 = 9
	cmdDel     uint8 = 10
)

// Top-level netlink attribute IDs (IPSET_ATTR_*).
const (
	attrProtocol uint16 = 1
	attrSetName  uint16 = 2
	attrTypeName uint16 = 3
	attrRevision uint16 = 4
	attrFamily   uint16 = 5
	attrFlags    uint16 = 6
	attrData     uint16 = 7 // nested
	attrADT      uint16 = 8 // nested (multiple entries for batched ADD)
	attrLineNo   uint16 = 9
)

// Attribute IDs that live inside IPSET_ATTR_DATA for hash:ip sets.
const (
	attrIP        uint16 = 1 // nested (contains IPV4 or IPV6)
	attrTimeout   uint16 = 6 // u32, network byte order
	attrHashSize  uint16 = 9 // u32, network byte order
	attrMaxElem   uint16 = 10
)

// IP address attribute IDs (inside IPSET_ATTR_IP).
const (
	attrIPv4 uint16 = 1
	attrIPv6 uint16 = 2
)

// Netfilter protocol family values used in IPSET_ATTR_FAMILY.
const (
	familyIPv4 uint8 = 2  // NFPROTO_IPV4
	familyIPv6 uint8 = 10 // NFPROTO_IPV6
)

// IPSET_FLAG_EXIST signals "no-op if already exists" semantics, matching the
// ipset(8) binary's `-exist` flag. Without this, the kernel returns
// -IPSET_ERR_EXIST when creating an existing set or adding an existing entry.
const flagExist uint32 = 1 << 0

// Netlink attribute flags.
const (
	nlaFNested       uint16 = 0x8000
	nlaFNetByteOrder uint16 = 0x4000
)

// Standard netlink message flags we use.
const (
	nlmFRequest uint16 = 0x0001
	nlmFAck     uint16 = 0x0004
	nlmFExcl    uint16 = 0x0200
	nlmFCreate  uint16 = 0x0400
	nlmFDump    uint16 = 0x0300 // ROOT | MATCH
)

// Standard netlink message types we look for in responses.
const (
	nlmsgError uint32 = 2
	nlmsgDone  uint32 = 3
)

// alignTo aligns n up to a 4-byte boundary, the netlink alignment rule.
func alignTo(n int) int { return (n + 3) &^ 3 }

// nlMsghdrLen is the size of a netlink message header (struct nlmsghdr).
const nlMsghdrLen = 16

// nfgenmsgLen is the size of the netfilter generic message header.
const nfgenmsgLen = 4

// encodeAttrU8 appends a u8 attribute and pads to 4-byte alignment.
func encodeAttrU8(buf []byte, typ uint16, v uint8) []byte {
	hdr := [4]byte{}
	binary.LittleEndian.PutUint16(hdr[0:2], 4+1) // length: 4 header + 1 payload
	binary.LittleEndian.PutUint16(hdr[2:4], typ)
	buf = append(buf, hdr[:]...)
	buf = append(buf, v, 0, 0, 0) // 1 byte + 3 pad
	return buf
}

// encodeAttrU16BE appends a u16 attribute in network byte order.
func encodeAttrU16BE(buf []byte, typ uint16, v uint16) []byte {
	hdr := [4]byte{}
	binary.LittleEndian.PutUint16(hdr[0:2], 4+2)
	binary.LittleEndian.PutUint16(hdr[2:4], typ|nlaFNetByteOrder)
	buf = append(buf, hdr[:]...)
	var val [4]byte
	binary.BigEndian.PutUint16(val[0:2], v)
	buf = append(buf, val[:]...)
	return buf
}

// encodeAttrU32BE appends a u32 attribute in network byte order.
func encodeAttrU32BE(buf []byte, typ uint16, v uint32) []byte {
	hdr := [4]byte{}
	binary.LittleEndian.PutUint16(hdr[0:2], 4+4)
	binary.LittleEndian.PutUint16(hdr[2:4], typ|nlaFNetByteOrder)
	buf = append(buf, hdr[:]...)
	var val [4]byte
	binary.BigEndian.PutUint32(val[:], v)
	buf = append(buf, val[:]...)
	return buf
}

// encodeAttrString appends a null-terminated string attribute.
func encodeAttrString(buf []byte, typ uint16, s string) []byte {
	payload := []byte(s)
	payload = append(payload, 0) // null terminator
	total := 4 + len(payload)
	pad := alignTo(total) - total
	hdr := [4]byte{}
	binary.LittleEndian.PutUint16(hdr[0:2], uint16(total))
	binary.LittleEndian.PutUint16(hdr[2:4], typ)
	buf = append(buf, hdr[:]...)
	buf = append(buf, payload...)
	for i := 0; i < pad; i++ {
		buf = append(buf, 0)
	}
	return buf
}

// encodeAttrBytesBE appends a raw byte attribute with NET_BYTEORDER flag.
// Used for IPv4 (4 bytes) and IPv6 (16 bytes) address payloads.
func encodeAttrBytesBE(buf []byte, typ uint16, data []byte) []byte {
	total := 4 + len(data)
	pad := alignTo(total) - total
	hdr := [4]byte{}
	binary.LittleEndian.PutUint16(hdr[0:2], uint16(total))
	binary.LittleEndian.PutUint16(hdr[2:4], typ|nlaFNetByteOrder)
	buf = append(buf, hdr[:]...)
	buf = append(buf, data...)
	for i := 0; i < pad; i++ {
		buf = append(buf, 0)
	}
	return buf
}

// nested wraps a function that appends inner attributes and emits a nested
// container attribute with the correct length. Used for ATTR_IP / ATTR_DATA /
// ATTR_ADT.
func nested(buf []byte, typ uint16, fn func([]byte) []byte) []byte {
	hdrStart := len(buf)
	buf = append(buf, 0, 0, 0, 0) // placeholder; length filled below
	binary.LittleEndian.PutUint16(buf[hdrStart+2:hdrStart+4], typ|nlaFNested)
	bodyStart := len(buf)
	buf = fn(buf)
	bodyLen := len(buf) - bodyStart
	totalLen := 4 + bodyLen
	binary.LittleEndian.PutUint16(buf[hdrStart:hdrStart+2], uint16(totalLen))
	pad := alignTo(totalLen) - totalLen
	for i := 0; i < pad; i++ {
		buf = append(buf, 0)
	}
	return buf
}

// buildMessage assembles a complete netlink + nfnetlink + body message and
// fills in the length and sequence number. seq is the per-client request id.
func buildMessage(cmd uint8, flags uint16, seq uint32, body func([]byte) []byte) []byte {
	msg := make([]byte, 0, 64)
	// nlmsghdr placeholder — 16 bytes
	msg = append(msg, make([]byte, nlMsghdrLen)...)
	// type = (subsysIPSet << 8) | cmd
	binary.LittleEndian.PutUint16(msg[4:6], uint16(subsysIPSet)<<8|uint16(cmd))
	binary.LittleEndian.PutUint16(msg[6:8], flags)
	binary.LittleEndian.PutUint32(msg[8:12], seq)
	binary.LittleEndian.PutUint32(msg[12:16], 0) // pid (kernel fills in)

	// nfgenmsg — 4 bytes: family, version, res_id(BE)
	nfgen := []byte{0, 0, 0, 0} // family=NFPROTO_UNSPEC by default
	nfgen[1] = 0                // version (NFNETLINK_V0)
	// res_id holds the netfilter subsystem id; we use 0 (kernel ignores for ipset)
	msg = append(msg, nfgen...)

	// command-specific body
	msg = body(msg)

	// fill total length
	binary.LittleEndian.PutUint32(msg[0:4], uint32(len(msg)))
	return msg
}
