package ipset

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
)

// These tests verify the wire-format encoders alone — no kernel socket is
// touched. We assert the byte layout of generated messages against the ipset
// kernel ABI, which is stable.

func TestEncodeAttrU8(t *testing.T) {
	got := encodeAttrU8(nil, attrProtocol, protocolVersion)
	want := []byte{
		0x05, 0x00, // length = 5
		0x01, 0x00, // type = attrProtocol = 1
		protocolVersion, 0, 0, 0, // u8 payload + 3 pad
	}
	if !bytes.Equal(got, want) {
		t.Errorf("encodeAttrU8 = %x, want %x", got, want)
	}
}

func TestEncodeAttrU32BE(t *testing.T) {
	got := encodeAttrU32BE(nil, attrTimeout, 3600)
	if len(got) != 8 {
		t.Fatalf("len = %d, want 8", len(got))
	}
	gotLen := binary.LittleEndian.Uint16(got[0:2])
	gotType := binary.LittleEndian.Uint16(got[2:4]) &^ nlaFNetByteOrder
	if gotLen != 8 {
		t.Errorf("length = %d, want 8", gotLen)
	}
	if gotType != attrTimeout {
		t.Errorf("type = %d, want %d", gotType, attrTimeout)
	}
	if binary.BigEndian.Uint32(got[4:8]) != 3600 {
		t.Errorf("payload = %x, want big-endian 3600", got[4:8])
	}
}

func TestEncodeAttrString(t *testing.T) {
	got := encodeAttrString(nil, attrSetName, "goban-ban-v4")
	// 4 (hdr) + 12 (name) + 1 (null) = 17 → pad to 20
	if len(got) != 20 {
		t.Fatalf("len = %d, want 20", len(got))
	}
	gotLen := binary.LittleEndian.Uint16(got[0:2])
	if gotLen != 17 {
		t.Errorf("nla_len = %d, want 17 (includes null but not padding)", gotLen)
	}
	if string(got[4:16]) != "goban-ban-v4" {
		t.Errorf("name = %q", string(got[4:16]))
	}
	if got[16] != 0 {
		t.Errorf("expected null terminator at byte 16, got %d", got[16])
	}
}

func TestEncodeAttrBytesBE_IPv4(t *testing.T) {
	addr := netip.MustParseAddr("198.51.100.7").As4()
	got := encodeAttrBytesBE(nil, attrIPv4, addr[:])
	// 4 (hdr) + 4 (payload) = 8, already aligned
	if len(got) != 8 {
		t.Fatalf("len = %d, want 8", len(got))
	}
	gotType := binary.LittleEndian.Uint16(got[2:4])
	if gotType&nlaFNetByteOrder == 0 {
		t.Errorf("NLA_F_NET_BYTEORDER not set")
	}
	if !bytes.Equal(got[4:8], []byte{198, 51, 100, 7}) {
		t.Errorf("payload = %x", got[4:8])
	}
}

func TestNested_Empty(t *testing.T) {
	got := nested(nil, attrData, func(buf []byte) []byte { return buf })
	if len(got) != 4 {
		t.Fatalf("empty nested attr len = %d, want 4", len(got))
	}
	gotLen := binary.LittleEndian.Uint16(got[0:2])
	if gotLen != 4 {
		t.Errorf("nla_len = %d, want 4", gotLen)
	}
	gotType := binary.LittleEndian.Uint16(got[2:4])
	if gotType&nlaFNested == 0 {
		t.Errorf("NLA_F_NESTED not set")
	}
}

func TestNested_Padded(t *testing.T) {
	// Inner attribute with 1-byte u8 payload (5 bytes nla + 3 pad = 8).
	// Outer length must be 4 (header) + 8 (inner with pad) = 12.
	got := nested(nil, attrData, func(buf []byte) []byte {
		return encodeAttrU8(buf, attrProtocol, protocolVersion)
	})
	if len(got) != 12 {
		t.Fatalf("nested-with-u8 len = %d, want 12", len(got))
	}
}

func TestBuildAdd_IPv4(t *testing.T) {
	c := &Client{}
	c.seq.Store(99)
	ip := netip.MustParseAddr("198.51.100.7")
	msg := c.buildAdd(100, "goban-ban-v4", IPv4, Entry{IP: ip, Timeout: 60})

	// Total length must match prefix
	gotTotal := binary.LittleEndian.Uint32(msg[0:4])
	if int(gotTotal) != len(msg) {
		t.Errorf("total = %d, msg len = %d", gotTotal, len(msg))
	}
	// Type = (subsysIPSet << 8) | cmdAdd
	gotType := binary.LittleEndian.Uint16(msg[4:6])
	wantType := uint16(subsysIPSet)<<8 | uint16(cmdAdd)
	if gotType != wantType {
		t.Errorf("type = %#x, want %#x", gotType, wantType)
	}
	// Flags should include REQUEST | ACK but NOT EXCL
	gotFlags := binary.LittleEndian.Uint16(msg[6:8])
	if gotFlags&nlmFRequest == 0 || gotFlags&nlmFAck == 0 {
		t.Errorf("flags missing REQUEST|ACK: %#x", gotFlags)
	}
	if gotFlags&nlmFExcl != 0 {
		t.Errorf("flags include EXCL — should be -exist semantics: %#x", gotFlags)
	}
	// Seq matches what we passed in
	gotSeq := binary.LittleEndian.Uint32(msg[8:12])
	if gotSeq != 100 {
		t.Errorf("seq = %d, want 100", gotSeq)
	}
	// Find the IP bytes somewhere in the payload
	if !bytes.Contains(msg, []byte{198, 51, 100, 7}) {
		t.Errorf("ipv4 bytes not in message: %x", msg)
	}
	// Find the 60-second timeout (big endian)
	if !bytes.Contains(msg, []byte{0, 0, 0, 60}) {
		t.Errorf("timeout (BE 60) not in message: %x", msg)
	}
}

func TestBuildAddBatch_HasEntries(t *testing.T) {
	c := &Client{}
	c.seq.Store(0)
	entries := []Entry{
		{IP: netip.MustParseAddr("198.51.100.1"), Timeout: 30},
		{IP: netip.MustParseAddr("198.51.100.2"), Timeout: 60},
		{IP: netip.MustParseAddr("198.51.100.3"), Timeout: 90},
	}
	msg := c.buildAddBatch(1, "goban-ban-v4", IPv4, entries)
	// All three IPs should be present in the message.
	for _, e := range entries {
		ip4 := e.IP.As4()
		if !bytes.Contains(msg, ip4[:]) {
			t.Errorf("ipv4 bytes for %s not in batched message", e.IP)
		}
	}
}

func TestBuildList_HasDumpFlag(t *testing.T) {
	c := &Client{}
	msg := c.buildList(1, "goban-ban-v4")
	gotFlags := binary.LittleEndian.Uint16(msg[6:8])
	if gotFlags&nlmFDump != nlmFDump {
		t.Errorf("LIST missing NLM_F_DUMP flag: %#x", gotFlags)
	}
}

func TestValidIPSetName(t *testing.T) {
	cases := map[string]struct {
		name    string
		wantErr bool
	}{
		"normal":         {"goban-ban-v4", false},
		"empty":          {"", true},
		"too_long":       {"this-name-is-thirty-two-chars-1234", true},
		"with_slash":     {"goban/ban", true},
		"with_space":     {"goban ban", true},
		"with_null":      {"goban\x00ban", true},
	}
	for n, tc := range cases {
		t.Run(n, func(t *testing.T) {
			err := validIPSetName(tc.name)
			if (err != nil) != tc.wantErr {
				t.Errorf("validIPSetName(%q) err=%v, wantErr=%v", tc.name, err, tc.wantErr)
			}
		})
	}
}

func TestParseListChunk_Done(t *testing.T) {
	// Build a minimal NLMSG_DONE message: 16-byte header, type=3, seq=42.
	msg := make([]byte, nlMsghdrLen)
	binary.LittleEndian.PutUint32(msg[0:4], nlMsghdrLen)
	binary.LittleEndian.PutUint16(msg[4:6], 3) // NLMSG_DONE
	binary.LittleEndian.PutUint32(msg[8:12], 42)
	done, entries, err := parseListChunk(42, msg)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if !done {
		t.Error("expected done")
	}
	if len(entries) != 0 {
		t.Errorf("entries = %v, want none", entries)
	}
}

func TestParseListChunk_ErrorWithErrno(t *testing.T) {
	// Build NLMSG_ERROR with errno = -ENOENT (-2).
	msg := make([]byte, nlMsghdrLen+4)
	binary.LittleEndian.PutUint32(msg[0:4], uint32(len(msg)))
	binary.LittleEndian.PutUint16(msg[4:6], 2) // NLMSG_ERROR
	binary.LittleEndian.PutUint32(msg[8:12], 99)
	errnoVal := int32(-2) // -ENOENT
	binary.LittleEndian.PutUint32(msg[nlMsghdrLen:nlMsghdrLen+4], uint32(errnoVal))
	done, _, err := parseListChunk(99, msg)
	if err == nil {
		t.Fatal("expected error for ENOENT errno")
	}
	if done {
		t.Error("expected done=false on error")
	}
}

func TestParseListChunk_AckSuccess(t *testing.T) {
	// NLMSG_ERROR with errno = 0 is the success ack.
	msg := make([]byte, nlMsghdrLen+4)
	binary.LittleEndian.PutUint32(msg[0:4], uint32(len(msg)))
	binary.LittleEndian.PutUint16(msg[4:6], 2)
	binary.LittleEndian.PutUint32(msg[8:12], 7)
	// errno bytes are all zero
	done, _, err := parseListChunk(7, msg)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if !done {
		t.Error("ack with errno=0 should be done")
	}
}
