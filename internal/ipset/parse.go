package ipset

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"syscall"
)

// parseListChunk processes one read() worth of bytes from a DUMP and returns
// the entries decoded from it plus a "done" flag (set when the kernel sent
// NLMSG_DONE). NLMSG_ERROR with errno=0 also counts as done; non-zero errno
// is returned as an error.
func parseListChunk(seq uint32, data []byte) (done bool, entries []Entry, err error) {
	for len(data) >= nlMsghdrLen {
		msgLen := binary.LittleEndian.Uint32(data[0:4])
		if msgLen < nlMsghdrLen || int(msgLen) > len(data) {
			return false, nil, fmt.Errorf("netlink: short or malformed message (len=%d, have=%d)", msgLen, len(data))
		}
		msgType := binary.LittleEndian.Uint16(data[4:6])
		msgSeq := binary.LittleEndian.Uint32(data[8:12])

		payload := data[nlMsghdrLen:msgLen]

		switch uint32(msgType) {
		case nlmsgDone:
			return true, entries, nil
		case nlmsgError:
			if msgSeq != seq {
				// stale message from a prior request — skip
				break
			}
			if len(payload) < 4 {
				return false, nil, errors.New("netlink: truncated NLMSG_ERROR")
			}
			errno := int32(binary.LittleEndian.Uint32(payload[:4]))
			if errno == 0 {
				return true, entries, nil
			}
			return false, nil, fmt.Errorf("ipset: %w", syscall.Errno(-errno))
		default:
			// LIST response message — skip nfgenmsg header then walk attrs.
			if len(payload) < nfgenmsgLen {
				break
			}
			attrs := payload[nfgenmsgLen:]
			batch, perr := parseListEntries(attrs)
			if perr != nil {
				return false, nil, perr
			}
			entries = append(entries, batch...)
		}
		data = data[alignTo(int(msgLen)):]
	}
	return false, entries, nil
}

// parseListEntries walks the top-level attributes of one LIST response and
// pulls out the IPSET_ATTR_ADT nested list (one IPSET_ATTR_DATA per entry).
// Older kernels emit just IPSET_ATTR_DATA at the top level when the set has
// a single entry; we handle that too.
func parseListEntries(attrs []byte) ([]Entry, error) {
	var entries []Entry
	for len(attrs) > 0 {
		if len(attrs) < 4 {
			return nil, errors.New("netlink: truncated attribute header")
		}
		attrLen := binary.LittleEndian.Uint16(attrs[0:2])
		attrType := binary.LittleEndian.Uint16(attrs[2:4]) & ^(nlaFNested | nlaFNetByteOrder)
		if int(attrLen) > len(attrs) || attrLen < 4 {
			return nil, fmt.Errorf("netlink: bad attribute length %d", attrLen)
		}
		body := attrs[4:attrLen]

		switch attrType {
		case attrADT:
			// nested list of entries; each is an IPSET_ATTR_DATA blob
			inner := body
			for len(inner) > 0 {
				if len(inner) < 4 {
					return nil, errors.New("netlink: truncated ADT entry")
				}
				innerLen := binary.LittleEndian.Uint16(inner[0:2])
				innerType := binary.LittleEndian.Uint16(inner[2:4]) & ^(nlaFNested | nlaFNetByteOrder)
				if int(innerLen) > len(inner) || innerLen < 4 {
					return nil, fmt.Errorf("netlink: bad ADT inner length %d", innerLen)
				}
				if innerType == attrData {
					e, err := parseEntryData(inner[4:innerLen])
					if err != nil {
						return nil, err
					}
					// Skip entries that don't carry an IP — the kernel
					// sometimes returns DATA blocks here that are set
					// metadata rather than entries.
					if e.IP.IsValid() {
						entries = append(entries, e)
					}
				}
				adv := alignTo(int(innerLen))
				if adv > len(inner) {
					adv = len(inner)
				}
				inner = inner[adv:]
			}
		case attrData:
			// Top-level IPSET_ATTR_DATA in a LIST response is the SET'S
			// HEADER (hashsize, maxelem, timeout default) — NOT an entry.
			// Real entries always live under IPSET_ATTR_ADT. So we only
			// emit an entry if this DATA block contains an IP; otherwise
			// it's the header and we ignore it.
			e, err := parseEntryData(body)
			if err != nil {
				return nil, err
			}
			if e.IP.IsValid() {
				entries = append(entries, e)
			}
		}
		adv := alignTo(int(attrLen))
		if adv > len(attrs) {
			adv = len(attrs)
		}
		attrs = attrs[adv:]
	}
	return entries, nil
}

// parseEntryData decodes one IPSET_ATTR_DATA blob into an Entry. We only
// look at IPSET_ATTR_IP (mandatory) and IPSET_ATTR_TIMEOUT (optional).
func parseEntryData(body []byte) (Entry, error) {
	var e Entry
	attrs := body
	for len(attrs) >= 4 {
		attrLen := binary.LittleEndian.Uint16(attrs[0:2])
		attrType := binary.LittleEndian.Uint16(attrs[2:4]) & ^(nlaFNested | nlaFNetByteOrder)
		if int(attrLen) > len(attrs) || attrLen < 4 {
			return e, fmt.Errorf("netlink: bad data attr length %d", attrLen)
		}
		payload := attrs[4:attrLen]
		switch attrType {
		case attrIP:
			ip, err := parseIPAttr(payload)
			if err != nil {
				return e, err
			}
			e.IP = ip
		case attrTimeout:
			if len(payload) >= 4 {
				e.Timeout = binary.BigEndian.Uint32(payload[:4])
			}
		}
		adv := alignTo(int(attrLen))
		if adv > len(attrs) {
			adv = len(attrs)
		}
		attrs = attrs[adv:]
	}
	return e, nil
}

// parseIPAttr extracts a netip.Addr from a nested IPSET_ATTR_IP container.
func parseIPAttr(body []byte) (netip.Addr, error) {
	attrs := body
	for len(attrs) >= 4 {
		attrLen := binary.LittleEndian.Uint16(attrs[0:2])
		attrType := binary.LittleEndian.Uint16(attrs[2:4]) & ^(nlaFNested | nlaFNetByteOrder)
		if int(attrLen) > len(attrs) || attrLen < 4 {
			return netip.Addr{}, fmt.Errorf("netlink: bad ip attr length %d", attrLen)
		}
		payload := attrs[4:attrLen]
		switch attrType {
		case attrIPv4:
			if len(payload) >= 4 {
				return netip.AddrFrom4([4]byte{payload[0], payload[1], payload[2], payload[3]}), nil
			}
		case attrIPv6:
			if len(payload) >= 16 {
				var b [16]byte
				copy(b[:], payload[:16])
				return netip.AddrFrom16(b), nil
			}
		}
		adv := alignTo(int(attrLen))
		if adv > len(attrs) {
			adv = len(attrs)
		}
		attrs = attrs[adv:]
	}
	return netip.Addr{}, errors.New("netlink: ipset entry missing IP")
}
