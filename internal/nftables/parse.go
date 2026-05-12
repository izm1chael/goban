package nftables

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"syscall"
	"time"
)

// ListedEntry is one set element decoded from a GETSETELEM dump.
type ListedEntry struct {
	IP        netip.Addr
	Timeout   time.Duration // total TTL configured for this element (0 == permanent)
	ExpiresIn time.Duration // remaining time until expiration (0 if not bounded)
}

// parseSetElemChunk decodes one read() worth of bytes from a GETSETELEM dump
// and returns the entries found plus a "done" flag (set when NLMSG_DONE
// arrives, or when NLMSG_ERROR with errno=0 acks the request).
func parseSetElemChunk(seq uint32, data []byte) (done bool, entries []ListedEntry, err error) {
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
				// stale from a prior request
				break
			}
			if len(payload) < 4 {
				return false, nil, errors.New("netlink: truncated NLMSG_ERROR")
			}
			errno := int32(binary.LittleEndian.Uint32(payload[:4]))
			if errno == 0 {
				return true, entries, nil
			}
			return false, nil, fmt.Errorf("nftables: %w", syscall.Errno(-errno))
		default:
			// NFT_MSG_NEWSETELEM response message. Skip the 4-byte
			// nfgenmsg header and walk the attribute list.
			if len(payload) < nfgenmsgLen {
				break
			}
			attrs := payload[nfgenmsgLen:]
			batch, perr := parseSetElemAttrs(attrs)
			if perr != nil {
				return false, nil, perr
			}
			entries = append(entries, batch...)
		}
		data = data[alignTo(int(msgLen)):]
	}
	return false, entries, nil
}

// parseSetElemAttrs walks the top-level attributes of one GETSETELEM
// response and pulls the elements out of NFTA_SET_ELEM_LIST_ELEMENTS.
func parseSetElemAttrs(attrs []byte) ([]ListedEntry, error) {
	var entries []ListedEntry
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
		if attrType == attrSetElemListElements {
			inner := body
			for len(inner) > 0 {
				if len(inner) < 4 {
					return nil, errors.New("netlink: truncated list elem")
				}
				innerLen := binary.LittleEndian.Uint16(inner[0:2])
				innerType := binary.LittleEndian.Uint16(inner[2:4]) & ^(nlaFNested | nlaFNetByteOrder)
				if int(innerLen) > len(inner) || innerLen < 4 {
					return nil, fmt.Errorf("netlink: bad list elem length %d", innerLen)
				}
				if innerType == attrListElem {
					e, perr := parseOneElem(inner[4:innerLen])
					if perr != nil {
						return nil, perr
					}
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
		}
		adv := alignTo(int(attrLen))
		if adv > len(attrs) {
			adv = len(attrs)
		}
		attrs = attrs[adv:]
	}
	return entries, nil
}

// parseOneElem decodes one NFTA_LIST_ELEM (a single set element) into a
// ListedEntry. We pull NFTA_SET_ELEM_KEY (mandatory), NFTA_SET_ELEM_TIMEOUT
// (configured TTL), and NFTA_SET_ELEM_EXPIRATION (remaining time).
func parseOneElem(body []byte) (ListedEntry, error) {
	var e ListedEntry
	attrs := body
	for len(attrs) >= 4 {
		attrLen := binary.LittleEndian.Uint16(attrs[0:2])
		attrType := binary.LittleEndian.Uint16(attrs[2:4]) & ^(nlaFNested | nlaFNetByteOrder)
		if int(attrLen) > len(attrs) || attrLen < 4 {
			return e, fmt.Errorf("netlink: bad elem attr length %d", attrLen)
		}
		payload := attrs[4:attrLen]
		switch attrType {
		case attrSetElemKey:
			ip, err := parseKeyAttr(payload)
			if err != nil {
				return e, err
			}
			e.IP = ip
		case attrSetElemTimeout:
			if len(payload) >= 8 {
				ms := binary.BigEndian.Uint64(payload[:8])
				e.Timeout = time.Duration(ms) * time.Millisecond
			}
		case attrSetElemExpire:
			if len(payload) >= 8 {
				ms := binary.BigEndian.Uint64(payload[:8])
				e.ExpiresIn = time.Duration(ms) * time.Millisecond
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

// parseKeyAttr extracts the raw IP bytes from a NFTA_SET_ELEM_KEY blob.
// The key is a nested NFTA_DATA_VALUE attribute whose payload is the raw
// network-byte-order IP (4 bytes for v4, 16 bytes for v6).
func parseKeyAttr(body []byte) (netip.Addr, error) {
	attrs := body
	for len(attrs) >= 4 {
		attrLen := binary.LittleEndian.Uint16(attrs[0:2])
		attrType := binary.LittleEndian.Uint16(attrs[2:4]) & ^(nlaFNested | nlaFNetByteOrder)
		if int(attrLen) > len(attrs) || attrLen < 4 {
			return netip.Addr{}, fmt.Errorf("netlink: bad key attr length %d", attrLen)
		}
		payload := attrs[4:attrLen]
		if attrType == attrDataValue {
			switch len(payload) {
			case 4:
				return netip.AddrFrom4([4]byte{payload[0], payload[1], payload[2], payload[3]}), nil
			case 16:
				var b [16]byte
				copy(b[:], payload[:16])
				return netip.AddrFrom16(b).Unmap(), nil
			}
		}
		adv := alignTo(int(attrLen))
		if adv > len(attrs) {
			adv = len(attrs)
		}
		attrs = attrs[adv:]
	}
	return netip.Addr{}, errors.New("netlink: set element missing key")
}
