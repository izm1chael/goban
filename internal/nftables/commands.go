package nftables

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"
)

// SetupConfig describes the table, sets, and chain objects the daemon needs.
// All four are created idempotently at daemon start (NLM_F_CREATE without
// NLM_F_EXCL — repeated invocations are no-ops on objects that already
// exist).
type SetupConfig struct {
	Table     string
	SetV4     string
	SetV6     string
	Chain     string
	IPv6      bool
	HookInput bool // true (default); reserved for future variants
}

// EntryFamily selects the IP family of a set element.
type EntryFamily uint8

const (
	IPv4 EntryFamily = EntryFamily(familyIPv4)
	IPv6 EntryFamily = EntryFamily(familyIPv6)
)

// Entry is one set element: an IP plus optional kernel-side TTL in seconds.
// Timeout == 0 means "permanent" (no kernel expiration).
type Entry struct {
	IP      netip.Addr
	Timeout uint32
}

// buildNewTable builds an NFT_MSG_NEWTABLE request for an `inet` family
// table. Inet covers both IPv4 and IPv6 traffic through one table — the
// individual sets are still typed per-family but they share a chain.
func (c *Client) buildNewTable(seq uint32, name string) []byte {
	flags := nlmFRequest | nlmFAck | nlmFCreate
	return buildMessage(subsysNFTables, cmdNewTable, familyInet, flags, seq, func(buf []byte) []byte {
		return encodeAttrString(buf, attrTableName, name)
	})
}

// buildNewChain builds an NFT_MSG_NEWCHAIN request for a base chain hooked
// into NF_INET_LOCAL_IN. We always use type "filter" and policy ACCEPT;
// individual rules inside the chain do the dropping.
func (c *Client) buildNewChain(seq uint32, table, chain string) []byte {
	flags := nlmFRequest | nlmFAck | nlmFCreate
	return buildMessage(subsysNFTables, cmdNewChain, familyInet, flags, seq, func(buf []byte) []byte {
		buf = encodeAttrString(buf, attrChainTable, table)
		buf = encodeAttrString(buf, attrChainName, chain)
		buf = nested(buf, attrChainHook, func(buf []byte) []byte {
			buf = encodeAttrU32BE(buf, attrHookNum, uint32(hookInput))
			buf = encodeAttrS32BE(buf, attrHookPriority, priorityFilterMinus300)
			return buf
		})
		buf = encodeAttrU32BE(buf, attrChainPolicy, policyAccept)
		buf = encodeAttrString(buf, attrChainType, "filter")
		return buf
	})
}

// buildNewSet builds an NFT_MSG_NEWSET request for a timeout-bearing set of
// IPv4 or IPv6 addresses. The default per-set timeout is 0 (caller-supplied
// per element) which matches the iptables backend's contract.
//
// NFTA_SET_ID is required by the kernel (the validation in
// nf_tables_newset() returns -EINVAL when ID is missing). It is also
// used by rules in the same batch to reference the set without a name
// lookup — we don't rely on that path, but the field is still required.
// We derive the ID from the sequence number so it is unique per request
// within a process and never collides with another GoBan request on the
// same socket.
func (c *Client) buildNewSet(seq uint32, table, name string, family EntryFamily) []byte {
	flags := nlmFRequest | nlmFAck | nlmFCreate
	keyType := keyTypeIPv4Addr
	keyLen := uint32(4)
	if family == IPv6 {
		keyType = keyTypeIPv6Addr
		keyLen = 16
	}
	return buildMessage(subsysNFTables, cmdNewSet, familyInet, flags, seq, func(buf []byte) []byte {
		buf = encodeAttrString(buf, attrSetTable, table)
		buf = encodeAttrString(buf, attrSetName, name)
		buf = encodeAttrU32BE(buf, attrSetFlags, setFlagTimeout)
		buf = encodeAttrU32BE(buf, attrSetKeyType, keyType)
		buf = encodeAttrU32BE(buf, attrSetKeyLen, keyLen)
		buf = encodeAttrU32BE(buf, attrSetID, seq)
		return buf
	})
}

// buildSetDropRule builds an NFT_MSG_NEWRULE request: extract the source
// address from the network header, look it up in the named set, and if it
// matches drop the packet. One rule per address family; the table is inet
// so the family attribute on the rule selects which (NFPROTO_IPV4 or
// NFPROTO_IPV6).
//
// The expression list is the heart of nftables. We emit three expressions:
//   - payload: load saddr into register 1
//   - lookup:  if register 1 is in @set, fall through (no early verdict);
//              otherwise jump to end of chain
//   - immediate: load NF_DROP verdict into the verdict register
//
// The kernel encodes lookup "match" semantics as: if the key IS in the
// set, evaluation continues to the next expression; if NOT in the set,
// the rule terminates without verdict. So putting `drop` after `lookup`
// drops only when the IP IS in the set.
func (c *Client) buildSetDropRule(seq uint32, table, chain, setName string, family EntryFamily) []byte {
	flags := nlmFRequest | nlmFAck | nlmFCreate
	// The table is family inet, so a single chain sees both v4 and v6
	// traffic. The rule's nfgen_family MUST be NFPROTO_INET — using
	// NFPROTO_IPV4 / NFPROTO_IPV6 makes the kernel's table lookup return
	// ENOENT. Family-specific dispatch is encoded in the expression list
	// via a meta+cmp prelude.
	saddrOff := ipv4SaddrOffset
	saddrLen := ipv4SaddrLen
	wantFamily := uint8(familyIPv4)
	if family == IPv6 {
		saddrOff = ipv6SaddrOffset
		saddrLen = ipv6SaddrLen
		wantFamily = uint8(familyIPv6)
	}
	return buildMessage(subsysNFTables, cmdNewRule, familyInet, flags, seq, func(buf []byte) []byte {
		buf = encodeAttrString(buf, attrRuleTable, table)
		buf = encodeAttrString(buf, attrRuleChain, chain)
		buf = nested(buf, attrRuleExpressions, func(buf []byte) []byte {
			// meta: load nfproto → reg1 (1-byte value)
			buf = nested(buf, attrListElem, func(buf []byte) []byte {
				buf = encodeAttrString(buf, attrExprName, "meta")
				buf = nested(buf, attrExprData, func(buf []byte) []byte {
					buf = encodeAttrU32BE(buf, attrMetaDReg, reg1)
					buf = encodeAttrU32BE(buf, attrMetaKey, metaKeyNFProto)
					return buf
				})
				return buf
			})
			// cmp: reg1 == wantFamily (1-byte compare)
			buf = nested(buf, attrListElem, func(buf []byte) []byte {
				buf = encodeAttrString(buf, attrExprName, "cmp")
				buf = nested(buf, attrExprData, func(buf []byte) []byte {
					buf = encodeAttrU32BE(buf, attrCmpSReg, reg1)
					buf = encodeAttrU32BE(buf, attrCmpOp, cmpEq)
					buf = nested(buf, attrCmpData, func(buf []byte) []byte {
						return encodeAttrBytes(buf, attrDataValue, []byte{wantFamily})
					})
					return buf
				})
				return buf
			})
			// payload: load saddr → reg1
			buf = nested(buf, attrListElem, func(buf []byte) []byte {
				buf = encodeAttrString(buf, attrExprName, "payload")
				buf = nested(buf, attrExprData, func(buf []byte) []byte {
					buf = encodeAttrU32BE(buf, attrPayloadDReg, reg1)
					buf = encodeAttrU32BE(buf, attrPayloadBase, payloadNetworkHeader)
					buf = encodeAttrU32BE(buf, attrPayloadOffset, saddrOff)
					buf = encodeAttrU32BE(buf, attrPayloadLen, saddrLen)
					return buf
				})
				return buf
			})
			// lookup: test reg1 against @set (match continues; miss ends rule)
			buf = nested(buf, attrListElem, func(buf []byte) []byte {
				buf = encodeAttrString(buf, attrExprName, "lookup")
				buf = nested(buf, attrExprData, func(buf []byte) []byte {
					buf = encodeAttrString(buf, attrLookupSet, setName)
					buf = encodeAttrU32BE(buf, attrLookupSReg, reg1)
					return buf
				})
				return buf
			})
			// immediate: load NF_DROP into the verdict register
			buf = nested(buf, attrListElem, func(buf []byte) []byte {
				buf = encodeAttrString(buf, attrExprName, "immediate")
				buf = nested(buf, attrExprData, func(buf []byte) []byte {
					buf = encodeAttrU32BE(buf, attrImmediateDReg, regVerdict)
					buf = nested(buf, attrImmediateData, func(buf []byte) []byte {
						buf = nested(buf, attrDataVerdict, func(buf []byte) []byte {
							return encodeAttrU32BE(buf, attrVerdictCode, uint32(verdictDrop))
						})
						return buf
					})
					return buf
				})
				return buf
			})
			return buf
		})
		return buf
	})
}

// buildSetElemAdd builds an NFT_MSG_NEWSETELEM request adding one entry to
// the named set, with a per-element timeout (milliseconds). Used by the
// Ban hot path.
//
// NLM_F_EXCL is set so the kernel returns EEXIST on duplicate-add instead
// of silently no-op'ing. Client.AddElement catches EEXIST and refreshes
// the TTL via a del-then-add pair so callers see "ban an already-banned
// IP" as a refresh, matching the ipset backend's contract.
func (c *Client) buildSetElemAdd(seq uint32, table, setName string, family EntryFamily, e Entry) []byte {
	flags := nlmFRequest | nlmFAck | nlmFCreate | nlmFExcl
	return buildMessage(subsysNFTables, cmdNewSetElem, familyInet, flags, seq, func(buf []byte) []byte {
		buf = encodeAttrString(buf, attrSetElemListTable, table)
		buf = encodeAttrString(buf, attrSetElemListSet, setName)
		buf = nested(buf, attrSetElemListElements, func(buf []byte) []byte {
			buf = nested(buf, attrListElem, func(buf []byte) []byte {
				buf = encodeAttrSetKey(buf, family, e.IP)
				if e.Timeout > 0 {
					buf = encodeAttrU64BE(buf, attrSetElemTimeout, uint64(e.Timeout)*1000)
				}
				return buf
			})
			return buf
		})
		return buf
	})
}

// buildSetElemDel builds an NFT_MSG_DELSETELEM request removing one entry
// from the named set. ENOENT is tolerated at the Client layer.
func (c *Client) buildSetElemDel(seq uint32, table, setName string, family EntryFamily, ip netip.Addr) []byte {
	flags := nlmFRequest | nlmFAck
	return buildMessage(subsysNFTables, cmdDelSetElem, familyInet, flags, seq, func(buf []byte) []byte {
		buf = encodeAttrString(buf, attrSetElemListTable, table)
		buf = encodeAttrString(buf, attrSetElemListSet, setName)
		buf = nested(buf, attrSetElemListElements, func(buf []byte) []byte {
			return nested(buf, attrListElem, func(buf []byte) []byte {
				return encodeAttrSetKey(buf, family, ip)
			})
		})
		return buf
	})
}

// buildSetElemGet builds an NFT_MSG_GETSETELEM dump request for a named
// set. The kernel responds with one message per element, terminated by
// NLMSG_DONE.
func (c *Client) buildSetElemGet(seq uint32, table, setName string) []byte {
	flags := nlmFRequest | nlmFAck | nlmFDump
	return buildMessage(subsysNFTables, cmdGetSetElem, familyInet, flags, seq, func(buf []byte) []byte {
		buf = encodeAttrString(buf, attrSetElemListTable, table)
		buf = encodeAttrString(buf, attrSetElemListSet, setName)
		return buf
	})
}

// buildDelTable builds an NFT_MSG_DELTABLE request. Used by Close(flush=true)
// to tear down the whole nftables installation on shutdown.
func (c *Client) buildDelTable(seq uint32, name string) []byte {
	flags := nlmFRequest | nlmFAck
	return buildMessage(subsysNFTables, cmdDelTable, familyInet, flags, seq, func(buf []byte) []byte {
		return encodeAttrString(buf, attrTableName, name)
	})
}

// encodeAttrSetKey emits a NFTA_SET_ELEM_KEY attribute containing a nested
// NFTA_DATA_VALUE blob with the raw IPv4 (4 bytes) or IPv6 (16 bytes) bytes.
func encodeAttrSetKey(buf []byte, family EntryFamily, ip netip.Addr) []byte {
	return nested(buf, attrSetElemKey, func(buf []byte) []byte {
		if family == IPv6 || (ip.Is6() && !ip.Is4In6()) {
			b := ip.As16()
			return encodeAttrBytes(buf, attrDataValue, b[:])
		}
		b := ip.As4()
		return encodeAttrBytes(buf, attrDataValue, b[:])
	})
}

// secs converts a Duration to seconds (clamped to uint32 range, used by
// callers that want to pass time-based TTLs into Entry.Timeout).
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

// validName mirrors the kernel's constraint on nftables identifier names:
// 1-31 bytes, no '/' or whitespace. The cheap pre-check keeps misuse from
// reaching the kernel as an opaque NLMSG_ERROR.
func validName(kind, name string) error {
	if len(name) == 0 || len(name) > 31 {
		return fmt.Errorf("nftables %s name %q: must be 1-31 bytes", kind, name)
	}
	for _, c := range []byte(name) {
		if c == '/' || c == ' ' || c == '\t' || c == 0 {
			return fmt.Errorf("nftables %s name %q: contains invalid byte", kind, name)
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
