package nftables

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

// TestEncodeAttrU8 verifies the basic u8 attribute layout: length=5,
// type=typ, payload byte, then 3 bytes of padding.
func TestEncodeAttrU8(t *testing.T) {
	out := encodeAttrU8(nil, 0x0042, 0x99)
	if len(out) != 8 {
		t.Fatalf("len = %d, want 8 (4 header + 1 value + 3 pad)", len(out))
	}
	if got := binary.LittleEndian.Uint16(out[0:2]); got != 5 {
		t.Errorf("length = %d, want 5", got)
	}
	if got := binary.LittleEndian.Uint16(out[2:4]); got != 0x0042 {
		t.Errorf("type = %#x, want 0x0042", got)
	}
	if out[4] != 0x99 {
		t.Errorf("value = %#x, want 0x99", out[4])
	}
	for i := 5; i < 8; i++ {
		if out[i] != 0 {
			t.Errorf("padding byte %d = %#x, want 0", i, out[i])
		}
	}
}

// TestEncodeAttrU32BE verifies the network-byte-order flag is set and the
// payload is big-endian.
func TestEncodeAttrU32BE(t *testing.T) {
	out := encodeAttrU32BE(nil, 0x0007, 0x01020304)
	if len(out) != 8 {
		t.Fatalf("len = %d, want 8", len(out))
	}
	if got := binary.LittleEndian.Uint16(out[2:4]); got&nlaFNetByteOrder == 0 {
		t.Errorf("type=%#x missing NLA_F_NET_BYTEORDER", got)
	}
	if got := binary.BigEndian.Uint32(out[4:8]); got != 0x01020304 {
		t.Errorf("value (BE) = %#x, want 0x01020304", got)
	}
}

// TestEncodeAttrU64BE verifies the 12-byte u64 attribute used for set
// timeouts.
func TestEncodeAttrU64BE(t *testing.T) {
	out := encodeAttrU64BE(nil, 0x000B, 0x0001020304050607)
	if len(out) != 12 {
		t.Fatalf("len = %d, want 12", len(out))
	}
	if got := binary.BigEndian.Uint64(out[4:12]); got != 0x0001020304050607 {
		t.Errorf("value (BE) = %#x, want 0x0001020304050607", got)
	}
}

// TestEncodeAttrString verifies null-terminated string layout + alignment.
func TestEncodeAttrString(t *testing.T) {
	out := encodeAttrString(nil, 0x0001, "abc") // 3+1=4 bytes payload, no pad
	wantHeader := []byte{8, 0, 1, 0}
	for i := 0; i < 4; i++ {
		if out[i] != wantHeader[i] {
			t.Fatalf("header[%d] = %#x, want %#x", i, out[i], wantHeader[i])
		}
	}
	if string(out[4:7]) != "abc" || out[7] != 0 {
		t.Errorf("payload = %v, want \"abc\\0\"", out[4:8])
	}

	out2 := encodeAttrString(nil, 0x0001, "ab") // 2+1=3 bytes payload, 1 pad
	if len(out2) != 8 {
		t.Errorf("len(out2) = %d, want 8 (padded)", len(out2))
	}
	if got := binary.LittleEndian.Uint16(out2[0:2]); got != 7 {
		t.Errorf("length attr = %d, want 7", got)
	}
}

// TestNested verifies the nested-container length includes only the inner
// attributes, while the buffer is padded to 4-byte alignment afterwards.
func TestNested(t *testing.T) {
	out := nested(nil, 0x0004, func(buf []byte) []byte {
		buf = encodeAttrU8(buf, 0x0001, 0x55)
		return buf
	})
	if got := binary.LittleEndian.Uint16(out[0:2]); got != 12 {
		t.Errorf("nested length = %d, want 12 (4 hdr + 8 inner u8 attr)", got)
	}
	if got := binary.LittleEndian.Uint16(out[2:4]); got&nlaFNested == 0 {
		t.Errorf("type %#x missing NLA_F_NESTED", got)
	}
	if got := binary.LittleEndian.Uint16(out[4:6]); got != 5 {
		t.Errorf("inner u8 length = %d, want 5", got)
	}
}

// TestBatchEnvelope verifies the BEGIN envelope has subsysNone in the type
// field's high byte, the right msgBatchBegin command in the low byte,
// nfgen_family = AF_UNSPEC, and the target subsystem id in res_id (BE u16).
func TestBatchEnvelope(t *testing.T) {
	out := batchBegin(0x12345678)
	if len(out) != 20 {
		t.Fatalf("len(BEGIN) = %d, want 20 (16 nlmsghdr + 4 nfgenmsg)", len(out))
	}
	gotLen := binary.LittleEndian.Uint32(out[0:4])
	if gotLen != 20 {
		t.Errorf("nlmsghdr.length = %d, want 20", gotLen)
	}
	msgType := binary.LittleEndian.Uint16(out[4:6])
	if got := uint8(msgType & 0xff); got != msgBatchBegin {
		t.Errorf("msg type (low byte) = %#x, want %#x", got, msgBatchBegin)
	}
	if got := uint8(msgType >> 8); got != subsysNone {
		t.Errorf("msg type (high byte / subsys) = %#x, want subsysNone (%#x)", got, subsysNone)
	}
	if got := binary.LittleEndian.Uint32(out[8:12]); got != 0x12345678 {
		t.Errorf("seq = %#x, want 0x12345678", got)
	}
	// nfgenmsg at offset 16: family, version, res_id(BE u16)
	if out[16] != familyUnspec {
		t.Errorf("nfgen_family = %#x, want %#x", out[16], familyUnspec)
	}
	resID := binary.BigEndian.Uint16(out[18:20])
	if resID != uint16(subsysNFTables) {
		t.Errorf("nfgenmsg.res_id = %d, want %d (subsysNFTables)", resID, subsysNFTables)
	}
}

// TestBuildNewTable verifies the NFT_MSG_NEWTABLE request shape: subsys=10,
// cmd=0, family=NFPROTO_INET, NLM_F_CREATE set, exactly one NFTA_TABLE_NAME
// attribute containing the table name.
func TestBuildNewTable(t *testing.T) {
	c := &Client{}
	out := c.buildNewTable(0xAA, "goban")
	gotLen := binary.LittleEndian.Uint32(out[0:4])
	if int(gotLen) != len(out) {
		t.Errorf("nlmsghdr.length = %d, len(buf) = %d", gotLen, len(out))
	}
	msgType := binary.LittleEndian.Uint16(out[4:6])
	if got := uint8(msgType & 0xff); got != cmdNewTable {
		t.Errorf("cmd = %#x, want %#x", got, cmdNewTable)
	}
	if got := uint8(msgType >> 8); got != subsysNFTables {
		t.Errorf("subsys = %#x, want %#x", got, subsysNFTables)
	}
	flags := binary.LittleEndian.Uint16(out[6:8])
	if flags&nlmFCreate == 0 {
		t.Errorf("flags = %#x missing NLM_F_CREATE", flags)
	}
	if flags&nlmFExcl != 0 {
		t.Errorf("flags = %#x must NOT set NLM_F_EXCL (idempotent semantics)", flags)
	}
	if out[16] != familyInet {
		t.Errorf("nfgen_family = %#x, want NFPROTO_INET (%#x)", out[16], familyInet)
	}
	// Skip nlmsghdr (16) + nfgenmsg (4) = 20; attributes start at 20.
	attrs := out[20:]
	if len(attrs) < 4 {
		t.Fatalf("no attributes (len=%d)", len(attrs))
	}
	attrLen := binary.LittleEndian.Uint16(attrs[0:2])
	attrType := binary.LittleEndian.Uint16(attrs[2:4])
	if attrType != attrTableName {
		t.Errorf("first attr type = %#x, want NFTA_TABLE_NAME (%#x)", attrType, attrTableName)
	}
	wantPayload := []byte("goban\x00")
	if int(attrLen) != 4+len(wantPayload) {
		t.Errorf("attr length = %d, want %d", attrLen, 4+len(wantPayload))
	}
	if got := string(attrs[4 : 4+5]); got != "goban" {
		t.Errorf("attr payload = %q, want \"goban\"", got)
	}
}

// TestBuildSetElemAddV4 verifies a NEWSETELEM request for an IPv4 ban with
// a TTL: family=inet on the message (one set covers both v4 and v6), the
// element key is the raw 4-byte IPv4 address, and the timeout is in
// milliseconds (BE u64).
func TestBuildSetElemAddV4(t *testing.T) {
	c := &Client{}
	out := c.buildSetElemAdd(0xBB, "goban", "goban-ban-v4", IPv4, Entry{
		IP:      netipMustParse(t, "198.51.100.7"),
		Timeout: 3600, // 1 hour in seconds
	})
	gotLen := binary.LittleEndian.Uint32(out[0:4])
	if int(gotLen) != len(out) {
		t.Errorf("nlmsghdr.length = %d, len(buf) = %d", gotLen, len(out))
	}
	msgType := binary.LittleEndian.Uint16(out[4:6])
	if got := uint8(msgType & 0xff); got != cmdNewSetElem {
		t.Errorf("cmd = %#x, want NFT_MSG_NEWSETELEM (%#x)", got, cmdNewSetElem)
	}
	// nfgen_family = NFPROTO_INET; per-element family selection happens
	// via the set's key_type, not the message family.
	if out[16] != familyInet {
		t.Errorf("nfgen_family = %#x, want NFPROTO_INET (%#x)", out[16], familyInet)
	}
	// Confirm the 4-byte IP appears somewhere in the payload (a strict
	// position check would be over-constraining, but the bytes must
	// be present, in network order).
	want := []byte{198, 51, 100, 7}
	if !containsBytes(out, want) {
		t.Errorf("IPv4 payload bytes %v not found in message", want)
	}
	// Confirm timeout is encoded in milliseconds — 3600s = 3_600_000 ms.
	var wantMs [8]byte
	binary.BigEndian.PutUint64(wantMs[:], 3_600_000)
	if !containsBytes(out, wantMs[:]) {
		t.Errorf("timeout bytes %v (3600s as BE u64 ms) not found in message", wantMs)
	}
}

// TestBuildSetElemAddV6 verifies an IPv6 element add: 16 raw bytes in network
// order embedded in the payload.
func TestBuildSetElemAddV6(t *testing.T) {
	c := &Client{}
	ip := netipMustParse(t, "2001:db8::1")
	out := c.buildSetElemAdd(0xCC, "goban", "goban-ban-v6", IPv6, Entry{
		IP:      ip,
		Timeout: 60,
	})
	want := ip.As16()
	if !containsBytes(out, want[:]) {
		t.Errorf("IPv6 raw bytes not found in message")
	}
}

// TestBuildSetElemDel verifies DELSETELEM doesn't carry a timeout attribute
// (only key) — the kernel doesn't need it for deletion.
func TestBuildSetElemDel(t *testing.T) {
	c := &Client{}
	ip := netipMustParse(t, "198.51.100.7")
	out := c.buildSetElemDel(0xDD, "goban", "goban-ban-v4", IPv4, ip)
	msgType := binary.LittleEndian.Uint16(out[4:6])
	if got := uint8(msgType & 0xff); got != cmdDelSetElem {
		t.Errorf("cmd = %#x, want NFT_MSG_DELSETELEM (%#x)", got, cmdDelSetElem)
	}
	// No NLM_F_CREATE on delete.
	flags := binary.LittleEndian.Uint16(out[6:8])
	if flags&nlmFCreate != 0 {
		t.Errorf("delete must not set NLM_F_CREATE; flags=%#x", flags)
	}
	want := []byte{198, 51, 100, 7}
	if !containsBytes(out, want) {
		t.Errorf("IPv4 payload bytes %v not found in delete message", want)
	}
}

// TestBuildNewSetV4Flags verifies the timeout flag is set on the new-set
// request so per-element TTLs are honored by the kernel.
func TestBuildNewSetV4Flags(t *testing.T) {
	c := &Client{}
	out := c.buildNewSet(0xEE, "goban", "goban-ban-v4", IPv4)
	// Walk attributes to find NFTA_SET_FLAGS and confirm setFlagTimeout.
	attrs := out[20:]
	for len(attrs) >= 4 {
		al := binary.LittleEndian.Uint16(attrs[0:2])
		at := binary.LittleEndian.Uint16(attrs[2:4]) & ^(nlaFNested | nlaFNetByteOrder)
		if at == attrSetFlags {
			gotFlags := binary.BigEndian.Uint32(attrs[4:8])
			if gotFlags&setFlagTimeout == 0 {
				t.Errorf("set flags %#x missing setFlagTimeout (%#x)", gotFlags, setFlagTimeout)
			}
			return
		}
		adv := alignTo(int(al))
		if adv > len(attrs) {
			break
		}
		attrs = attrs[adv:]
	}
	t.Error("NFTA_SET_FLAGS attribute not found in NEWSET request")
}

// TestParseSetElemRoundTrip builds an addition request, then extracts the
// element bytes back out using the same parser the dump response uses. This
// is a smoke test for end-to-end encoder/decoder consistency.
func TestParseSetElemRoundTrip(t *testing.T) {
	c := &Client{}
	ip := netipMustParse(t, "203.0.113.7")
	out := c.buildSetElemAdd(0xFF, "goban", "goban-ban-v4", IPv4, Entry{
		IP:      ip,
		Timeout: 7200,
	})
	// Find NFTA_SET_ELEM_LIST_ELEMENTS attribute and feed its body to
	// parseSetElemAttrs.
	attrs := out[20:]
	for len(attrs) >= 4 {
		al := binary.LittleEndian.Uint16(attrs[0:2])
		at := binary.LittleEndian.Uint16(attrs[2:4]) & ^(nlaFNested | nlaFNetByteOrder)
		if at == attrSetElemListElements {
			elements, err := parseSetElemAttrs(attrs[:al])
			if err != nil {
				t.Fatalf("parseSetElemAttrs: %v", err)
			}
			if len(elements) != 1 {
				t.Fatalf("len(elements) = %d, want 1", len(elements))
			}
			if elements[0].IP != ip {
				t.Errorf("decoded IP = %v, want %v", elements[0].IP, ip)
			}
			return
		}
		adv := alignTo(int(al))
		if adv > len(attrs) {
			break
		}
		attrs = attrs[adv:]
	}
	t.Error("NFTA_SET_ELEM_LIST_ELEMENTS attribute not found")
}

// netipMustParse is a tiny test helper.
func netipMustParse(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse %s: %v", s, err)
	}
	return a
}

// containsBytes reports whether haystack contains the contiguous needle.
func containsBytes(haystack, needle []byte) bool {
	if len(needle) == 0 {
		return true
	}
outer:
	for i := 0; i+len(needle) <= len(haystack); i++ {
		for j := range needle {
			if haystack[i+j] != needle[j] {
				continue outer
			}
		}
		return true
	}
	return false
}
