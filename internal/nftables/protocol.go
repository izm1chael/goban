// Package nftables is a small netlink-direct client for the kernel nf_tables
// subsystem. It is the v1.0.0 alternative to internal/ipset's iptables+ipset
// backend for operators on nftables-only Linux hosts.
//
// The package speaks just enough of the protocol to satisfy GoBan's needs:
//
//   - one table (family inet, configurable name)
//   - two timeout-bearing address sets (ipv4_addr + ipv6_addr)
//   - one chain hooked into NF_INET_LOCAL_IN (input)
//   - two drop rules (one per address family) that match the set membership
//   - add/del/list set elements (the per-ban hot path)
//
// Anything else (nat tables, counters, expression-tree introspection, etc.)
// is intentionally out of scope; nftables is large and the bug budget for
// code that talks raw netlink is small. We mirror the philosophy of
// internal/ipset, which carries the same warning.
//
// Wire format references:
//
//   - include/uapi/linux/netfilter/nf_tables.h
//   - include/uapi/linux/netfilter/nfnetlink.h
//   - libnftnl source (the userspace canonical encoder)
//
// nftables wraps every mutating message in NFNL_MSG_BATCH_BEGIN /
// NFNL_MSG_BATCH_END envelopes so the kernel applies the contained
// operations atomically. We use the envelope for every multi-step
// operation; single-step requests omit it for simplicity (the kernel
// accepts unbatched messages too).
package nftables

import (
	"encoding/binary"
)

// Netfilter netlink subsystems used by this client.
const (
	subsysNone     = 0  // NFNL_SUBSYS_NONE — used for BATCH envelopes
	subsysNFTables = 10 // NFNL_SUBSYS_NFTABLES
)

// Netfilter generic batch message types (NFNL_MSG_BATCH_*).
const (
	msgBatchBegin uint8 = 0x10
	msgBatchEnd   uint8 = 0x11
)

// nf_tables command types (NFT_MSG_*). Encoded into the top 8 bits of
// nlmsghdr.Type along with subsysNFTables in the bottom 8 bits.
const (
	cmdNewTable    uint8 = 0
	cmdDelTable    uint8 = 2
	cmdNewChain    uint8 = 3
	cmdNewRule     uint8 = 6
	cmdNewSet      uint8 = 9
	cmdGetSet      uint8 = 10
	cmdNewSetElem  uint8 = 12
	cmdGetSetElem  uint8 = 13
	cmdDelSetElem  uint8 = 14
)

// Netfilter address families used in nfgenmsg.nfgen_family.
const (
	familyUnspec uint8 = 0
	familyIPv4   uint8 = 2  // NFPROTO_IPV4
	familyIPv6   uint8 = 10 // NFPROTO_IPV6
	familyInet   uint8 = 1  // NFPROTO_INET (covers v4+v6)
)

// FamilyOf returns the right family byte for an IP.
func FamilyOf(is6 bool) uint8 {
	if is6 {
		return familyIPv6
	}
	return familyIPv4
}

// NFTA_TABLE_* — table attribute IDs.
const (
	attrTableName uint16 = 1
)

// NFTA_CHAIN_* — chain attribute IDs.
const (
	attrChainTable  uint16 = 1
	attrChainName   uint16 = 3
	attrChainHook   uint16 = 4
	attrChainPolicy uint16 = 5
	attrChainType   uint16 = 7
)

// NFTA_HOOK_* — chain-hook nested attribute IDs.
const (
	attrHookNum      uint16 = 1
	attrHookPriority uint16 = 2
)

// NF_INET_* — hook numbers.
const (
	hookInput uint8 = 1 // NF_INET_LOCAL_IN
)

// nftables priority constants. The kernel uses a signed int32; negative
// values are higher priority (run earlier). filter = 0, so filter-300
// means "300 slots earlier than the standard filter chain" — early enough
// to drop before late rules but after conntrack.
const (
	priorityFilterMinus300 int32 = -300
)

// NF_* — chain policies and verdicts.
const (
	policyAccept uint32 = 1 // NF_ACCEPT
)

// NFTA_RULE_* — rule attribute IDs.
const (
	attrRuleTable       uint16 = 1
	attrRuleChain       uint16 = 2
	attrRuleExpressions uint16 = 4
)

// NFTA_EXPR_* — expression nested attribute IDs.
const (
	attrExprName uint16 = 1
	attrExprData uint16 = 2
)

// NFTA_LIST_ELEM — list element wrapper used for rule expressions.
const attrListElem uint16 = 1

// NFTA_PAYLOAD_* — payload-extraction expression attributes.
const (
	attrPayloadDReg   uint16 = 1
	attrPayloadBase   uint16 = 2
	attrPayloadOffset uint16 = 3
	attrPayloadLen    uint16 = 4
)

// NFT_PAYLOAD_* — payload base values.
const (
	payloadNetworkHeader uint32 = 1
)

// NFTA_LOOKUP_* — set-membership expression attributes.
const (
	attrLookupSet  uint16 = 1
	attrLookupSReg uint16 = 2
)

// NFTA_META_* — meta-load expression attributes (read packet metadata into
// a register so a subsequent cmp can test it).
const (
	attrMetaDReg uint16 = 1
	attrMetaKey  uint16 = 2
)

// NFT_META_* — meta-key values.
const (
	metaKeyNFProto uint32 = 8 // NFT_META_NFPROTO
)

// NFTA_CMP_* — register-value comparison expression attributes.
const (
	attrCmpSReg uint16 = 1
	attrCmpOp   uint16 = 2
	attrCmpData uint16 = 3
)

// NFT_CMP_* — comparison operators.
const (
	cmpEq uint32 = 0 // NFT_CMP_EQ
)

// NFTA_IMMEDIATE_* — verdict-loading expression attributes.
const (
	attrImmediateDReg uint16 = 1
	attrImmediateData uint16 = 2
)

// NFTA_DATA_* — wrapper for values and verdicts inside immediate / set keys.
const (
	attrDataValue   uint16 = 1
	attrDataVerdict uint16 = 2
)

// NFTA_VERDICT_* — verdict nested-attribute IDs.
const (
	attrVerdictCode uint16 = 1
)

// nft register constants (NFT_REG_*).
const (
	regVerdict uint32 = 0
	reg1       uint32 = 1
)

// Verdict codes (NF_DROP is 0, but the userspace value passed via netlink is
// the signed encoding the kernel expects).
const verdictDrop int32 = 0 // NF_DROP

// IPv4/IPv6 saddr extraction parameters (NF_INET_LOCAL_IN sees the network
// header at offset 0).
const (
	ipv4SaddrOffset uint32 = 12
	ipv4SaddrLen    uint32 = 4
	ipv6SaddrOffset uint32 = 8
	ipv6SaddrLen    uint32 = 16
)

// NFTA_SET_* — set attribute IDs.
const (
	attrSetTable    uint16 = 1
	attrSetName     uint16 = 2
	attrSetFlags    uint16 = 3
	attrSetKeyType  uint16 = 4
	attrSetKeyLen   uint16 = 5
	attrSetID       uint16 = 10
	attrSetTimeout  uint16 = 11
)

// nft set flags.
const (
	setFlagTimeout uint32 = 0x10 // NFT_SET_TIMEOUT
)

// nft data-type identifiers used as NFTA_SET_KEY_TYPE values. These come
// from the userspace TYPE_* enumeration in nft's source; the kernel uses
// them as opaque tokens so we just need the well-known values.
const (
	keyTypeIPv4Addr uint32 = 7
	keyTypeIPv6Addr uint32 = 8
)

// NFTA_SET_ELEM_LIST_* — top-level attributes of a setelem request.
const (
	attrSetElemListTable    uint16 = 1
	attrSetElemListSet      uint16 = 2
	attrSetElemListElements uint16 = 3
)

// NFTA_SET_ELEM_* — per-element attribute IDs.
const (
	attrSetElemKey     uint16 = 1
	attrSetElemTimeout uint16 = 4
	attrSetElemExpire  uint16 = 5
)

// Netlink attribute flags.
const (
	nlaFNested       uint16 = 0x8000
	nlaFNetByteOrder uint16 = 0x4000
)

// Standard netlink message flags.
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

// Sizes of the netlink + nfnetlink fixed headers.
const (
	nlMsghdrLen = 16
	nfgenmsgLen = 4
)

// encodeAttrU8 appends a u8 attribute padded to 4 bytes.
func encodeAttrU8(buf []byte, typ uint16, v uint8) []byte {
	var hdr [4]byte
	binary.LittleEndian.PutUint16(hdr[0:2], 4+1)
	binary.LittleEndian.PutUint16(hdr[2:4], typ)
	buf = append(buf, hdr[:]...)
	buf = append(buf, v, 0, 0, 0)
	return buf
}

// encodeAttrU32BE appends a u32 attribute in network byte order.
func encodeAttrU32BE(buf []byte, typ uint16, v uint32) []byte {
	var hdr [4]byte
	binary.LittleEndian.PutUint16(hdr[0:2], 4+4)
	binary.LittleEndian.PutUint16(hdr[2:4], typ|nlaFNetByteOrder)
	buf = append(buf, hdr[:]...)
	var val [4]byte
	binary.BigEndian.PutUint32(val[:], v)
	buf = append(buf, val[:]...)
	return buf
}

// encodeAttrU64BE appends a u64 attribute in network byte order. Used for
// NFTA_SET_TIMEOUT and NFTA_SET_ELEM_TIMEOUT (milliseconds).
func encodeAttrU64BE(buf []byte, typ uint16, v uint64) []byte {
	var hdr [4]byte
	binary.LittleEndian.PutUint16(hdr[0:2], 4+8)
	binary.LittleEndian.PutUint16(hdr[2:4], typ|nlaFNetByteOrder)
	buf = append(buf, hdr[:]...)
	var val [8]byte
	binary.BigEndian.PutUint64(val[:], v)
	buf = append(buf, val[:]...)
	return buf
}

// encodeAttrS32BE appends a signed i32 in network byte order. Used for the
// hook priority (negative values run earlier).
func encodeAttrS32BE(buf []byte, typ uint16, v int32) []byte {
	return encodeAttrU32BE(buf, typ, uint32(v))
}

// encodeAttrString appends a null-terminated string attribute.
func encodeAttrString(buf []byte, typ uint16, s string) []byte {
	payload := append([]byte(s), 0)
	total := 4 + len(payload)
	pad := alignTo(total) - total
	var hdr [4]byte
	binary.LittleEndian.PutUint16(hdr[0:2], uint16(total))
	binary.LittleEndian.PutUint16(hdr[2:4], typ)
	buf = append(buf, hdr[:]...)
	buf = append(buf, payload...)
	for i := 0; i < pad; i++ {
		buf = append(buf, 0)
	}
	return buf
}

// encodeAttrBytes appends a raw byte attribute. Pads to 4-byte alignment.
// Used for IPv4 (4 bytes) and IPv6 (16 bytes) set keys and verdict payloads.
func encodeAttrBytes(buf []byte, typ uint16, data []byte) []byte {
	total := 4 + len(data)
	pad := alignTo(total) - total
	var hdr [4]byte
	binary.LittleEndian.PutUint16(hdr[0:2], uint16(total))
	binary.LittleEndian.PutUint16(hdr[2:4], typ)
	buf = append(buf, hdr[:]...)
	buf = append(buf, data...)
	for i := 0; i < pad; i++ {
		buf = append(buf, 0)
	}
	return buf
}

// nested wraps a function that appends inner attributes and emits a nested
// container attribute with the correct length.
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
// subsys selects the netfilter subsystem; family is the address family
// recorded in nfgenmsg.
func buildMessage(subsys uint8, cmd uint8, family uint8, flags uint16, seq uint32, body func([]byte) []byte) []byte {
	msg := make([]byte, 0, 64)
	msg = append(msg, make([]byte, nlMsghdrLen)...)
	binary.LittleEndian.PutUint16(msg[4:6], uint16(subsys)<<8|uint16(cmd))
	binary.LittleEndian.PutUint16(msg[6:8], flags)
	binary.LittleEndian.PutUint32(msg[8:12], seq)
	binary.LittleEndian.PutUint32(msg[12:16], 0) // pid filled in by kernel

	// nfgenmsg: u8 family, u8 version (=0), u16 res_id (BE, =0)
	msg = append(msg, family, 0, 0, 0)

	msg = body(msg)

	binary.LittleEndian.PutUint32(msg[0:4], uint32(len(msg)))
	return msg
}

// batchEnvelope builds an NFNL_MSG_BATCH_BEGIN or _END marker. The nfgenmsg
// res_id field carries the target subsystem id (BE u16) so the kernel knows
// which subsystem the batched commands belong to. We use this for every
// mutating operation so the kernel applies them atomically.
func batchEnvelope(cmd uint8, seq uint32) []byte {
	msg := buildMessage(subsysNone, cmd, familyUnspec, nlmFRequest, seq, func(buf []byte) []byte {
		return buf
	})
	// nfgenmsg sits at offset nlMsghdrLen; res_id is at offset
	// nlMsghdrLen+2 and is encoded big-endian.
	binary.BigEndian.PutUint16(msg[nlMsghdrLen+2:nlMsghdrLen+4], uint16(subsysNFTables))
	return msg
}

func batchBegin(seq uint32) []byte { return batchEnvelope(msgBatchBegin, seq) }
func batchEnd(seq uint32) []byte   { return batchEnvelope(msgBatchEnd, seq) }
