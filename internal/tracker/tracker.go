// Package tracker implements a per-rule sliding-window strike counter.
//
// State is sharded across N small maps each with its own mutex, keyed by a
// cheap hash of the IP. The single-mutex pattern in v1 was fine but became a
// gratuitous contention point as soon as we started imagining concurrent
// rules sharing a source; sharding removes that ceiling at no cost when only
// one goroutine is calling Hit (one shard is just as fast as the v1 mutex).
//
// Each Hit records a single offence by an IP. The Hit returns true when the
// IP has accumulated at least Threshold offences within the FindTime window
// — the caller is then expected to ban the IP and call Reset for that IP.
//
// A Sweep operation drops records whose newest strike is older than FindTime
// so the map doesn't grow unboundedly under sustained attack.
package tracker

import (
	crand "crypto/rand"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sync"
	"time"
)

// shardCount must be a power of two. 8 is enough headroom for any realistic
// rule count without bloating the struct.
const shardCount = 8

// Tracker counts strikes per IP within a sliding time window.
type Tracker struct {
	threshold int
	findtime  time.Duration

	shards [shardCount]shard

	// hashSalt makes the shard distribution adversary-resistant — an
	// attacker can't construct IPs that all land on one shard. Generated
	// once at construction via crypto/rand.
	hashSalt uint64

	// Now is the clock; tests inject a fake. Defaults to time.Now.
	Now func() time.Time
}

type shard struct {
	mu      sync.Mutex
	records map[netip.Addr]*record
}

type record struct {
	// strikes holds timestamps of recent offences within findtime; older
	// entries are pruned on each Hit and during Sweep.
	strikes []time.Time
}

// New constructs a Tracker.
func New(threshold int, findtime time.Duration) *Tracker {
	var saltBytes [8]byte
	_, _ = crand.Read(saltBytes[:])
	t := &Tracker{
		threshold: threshold,
		findtime:  findtime,
		hashSalt:  binary.LittleEndian.Uint64(saltBytes[:]),
		Now:       time.Now,
	}
	for i := range t.shards {
		t.shards[i].records = make(map[netip.Addr]*record)
	}
	return t
}

// shardCountLog2 must match shardCount: log2(shardCount).
const shardCountLog2 = 3

// shardFor returns the shard the IP belongs to. Uses an inline XOR-fold of
// the 16-byte address plus a per-Tracker random salt and a Fibonacci-hashing
// multiplier; the index is the TOP shardCountLog2 bits of the product, which
// is how Fibonacci hashing is supposed to be consumed (the multiplier scatters
// input differences across all output bits but the *high* bits show the
// strongest separation).
//
// Zero allocations per call. Earlier versions used hash/maphash.Hash which
// allocated a Hash value per call — that allocation showed up at 10K hits/sec.
func (t *Tracker) shardFor(addr netip.Addr) *shard {
	b := addr.As16()
	lo := binary.LittleEndian.Uint64(b[0:8])
	hi := binary.LittleEndian.Uint64(b[8:16])
	h := (lo ^ hi ^ t.hashSalt) * 0x9E3779B97F4A7C15
	return &t.shards[h>>(64-shardCountLog2)]
}

// Hit registers a single offence at wall-clock time and returns true when the
// strike count within the sliding window has reached the threshold. The
// caller is responsible for calling Reset after a successful ban so the
// record is cleared.
//
// Thin shim around HitAt for callers that don't have an external event time.
func (t *Tracker) Hit(addr netip.Addr) bool {
	return t.HitAt(addr, t.Now())
}

// HitAt registers a single offence with an explicit event time. The strike
// is recorded at eventTime; pruning still uses wall-clock so backfilled
// events don't artificially extend the sliding window.
//
// eventTime should be the time the log entry was generated (parsed from the
// line via the rule's datepattern), not the time GoBan received it. Rules
// that don't have a datepattern simply pass time.Now() — equivalent to Hit.
func (t *Tracker) HitAt(addr netip.Addr, eventTime time.Time) bool {
	s := t.shardFor(addr)
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := t.Now().Add(-t.findtime)
	r, ok := s.records[addr]
	if !ok {
		r = &record{}
		s.records[addr] = r
	}
	// prune in place — drop strikes whose recorded time is older than the
	// sliding window. eventTime itself is checked against the cutoff so
	// that a backfilled event from outside the window does NOT count.
	kept := r.strikes[:0]
	for _, ts := range r.strikes {
		if ts.After(cutoff) {
			kept = append(kept, ts)
		}
	}
	if eventTime.After(cutoff) {
		kept = append(kept, eventTime)
	}
	r.strikes = kept
	return len(r.strikes) >= t.threshold
}

// Reset removes all strike state for addr.
func (t *Tracker) Reset(addr netip.Addr) {
	s := t.shardFor(addr)
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.records, addr)
}

// Sweep removes records whose newest strike is older than findtime. Returns
// the number of records dropped (useful for metrics/tests). Iterates each
// shard independently so a long sweep on one shard doesn't block Hits on
// others.
func (t *Tracker) Sweep() int {
	cutoff := t.Now().Add(-t.findtime)
	dropped := 0
	for i := range t.shards {
		s := &t.shards[i]
		s.mu.Lock()
		for addr, r := range s.records {
			if len(r.strikes) == 0 || !r.strikes[len(r.strikes)-1].After(cutoff) {
				delete(s.records, addr)
				dropped++
			}
		}
		s.mu.Unlock()
	}
	return dropped
}

// Size returns the number of tracked IPs across all shards.
func (t *Tracker) Size() int {
	n := 0
	for i := range t.shards {
		s := &t.shards[i]
		s.mu.Lock()
		n += len(s.records)
		s.mu.Unlock()
	}
	return n
}

// Snapshot returns a copy of current strike counts per IP across all shards.
// Strikes outside the window are pruned in the snapshot view.
func (t *Tracker) Snapshot() map[netip.Addr]int {
	cutoff := t.Now().Add(-t.findtime)
	out := make(map[netip.Addr]int, t.Size())
	for i := range t.shards {
		s := &t.shards[i]
		s.mu.Lock()
		for addr, r := range s.records {
			count := 0
			for _, ts := range r.strikes {
				if ts.After(cutoff) {
					count++
				}
			}
			if count > 0 {
				out[addr] = count
			}
		}
		s.mu.Unlock()
	}
	return out
}

// Threshold returns the configured threshold.
func (t *Tracker) Threshold() int { return t.threshold }

// FindTime returns the configured sliding-window length.
func (t *Tracker) FindTime() time.Duration { return t.findtime }

// stateVersion is the schema version of the gob-serialized tracker state.
// Bump on any change to savedState's shape. A loader that sees a different
// version discards the state with a warning rather than risking misdecoding.
const stateVersion uint32 = 1

// savedState is what Save/Load serialize. Each shard's records are flattened
// into a flat map keyed by IP so the gob output doesn't carry the internal
// shardCount as part of the wire shape — if we ever change shardCount,
// existing state still loads (it just re-distributes on Hit).
type savedState struct {
	Version uint32
	SavedAt time.Time
	Records map[netip.Addr][]time.Time
}

// Save writes the tracker's strike state to w as a gob-encoded blob. Safe
// for concurrent use with Hit/Reset — each shard's snapshot is taken under
// its own mutex.
func (t *Tracker) Save(w io.Writer) error {
	flat := make(map[netip.Addr][]time.Time)
	for i := range t.shards {
		s := &t.shards[i]
		s.mu.Lock()
		for addr, r := range s.records {
			if len(r.strikes) == 0 {
				continue
			}
			cp := make([]time.Time, len(r.strikes))
			copy(cp, r.strikes)
			flat[addr] = cp
		}
		s.mu.Unlock()
	}
	enc := gob.NewEncoder(w)
	return enc.Encode(savedState{
		Version: stateVersion,
		SavedAt: t.Now(),
		Records: flat,
	})
}

// Load reads a previously-Saved state from r and merges it into the tracker.
// A version mismatch returns a non-nil error AND leaves the tracker unchanged
// — callers should log a warning and continue with a clean start.
//
// Load is not concurrency-safe with Hit; callers should invoke it before
// the daemon starts processing lines (typically right after construction).
func (t *Tracker) Load(r io.Reader) error {
	dec := gob.NewDecoder(r)
	var st savedState
	if err := dec.Decode(&st); err != nil {
		if errors.Is(err, io.EOF) {
			return nil // empty file == clean state
		}
		return fmt.Errorf("decode state: %w", err)
	}
	if st.Version != stateVersion {
		return fmt.Errorf("state version %d does not match expected %d", st.Version, stateVersion)
	}
	for addr, strikes := range st.Records {
		s := t.shardFor(addr)
		s.mu.Lock()
		s.records[addr] = &record{strikes: append([]time.Time(nil), strikes...)}
		s.mu.Unlock()
	}
	return nil
}
