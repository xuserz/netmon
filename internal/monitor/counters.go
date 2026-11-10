package monitor

import (
	"context"
	"errors"
	"math"
	"net/netip"
	"sync/atomic"
	"time"

	"netmon/internal/store"
)

var errSnapshotContended = errors.New("counter snapshot changed during sampling")

// Capture owns the index. Snapshot publication only reads stable slots and
// atomic values, never iterating a Go map or holding capture's mutex.
type counterBatch struct {
	index    map[netip.Addr]*counterEntry
	slots    []atomic.Pointer[counterEntry]
	size     atomic.Uint32
	requests atomic.Uint64
	since    atomic.Int64
}
type counterEntry struct {
	ip                    netip.Addr
	sequence              atomic.Uint64
	requests, first, last atomic.Int64
}

func newCounterBatch(limit int) *counterBatch {
	return &counterBatch{index: make(map[netip.Addr]*counterEntry), slots: make([]atomic.Pointer[counterEntry], limit)}
}
func (b *counterBatch) len() int { return int(b.size.Load()) }
func (b *counterBatch) add(ip netip.Addr, n, ts int64) {
	e := b.index[ip]
	if e == nil {
		if b.size.Load() == 0 {
			b.since.Store(time.Now().UnixNano())
		}
		e = &counterEntry{ip: ip}
		e.requests.Store(n)
		e.first.Store(ts)
		e.last.Store(ts)
		b.index[ip] = e
		pos := b.size.Load()
		b.slots[pos].Store(e)
		b.size.Store(pos + 1)
	} else {
		e.sequence.Add(1)
		old := e.requests.Load()
		if n > math.MaxInt64-old {
			e.requests.Store(math.MaxInt64)
		} else {
			e.requests.Store(old + n)
		}
		if ts < e.first.Load() {
			e.first.Store(ts)
		}
		if ts > e.last.Load() {
			e.last.Store(ts)
		}
		e.sequence.Add(1)
	}
	count := b.requests.Load()
	if uint64(n) > math.MaxUint64-count {
		b.requests.Store(math.MaxUint64)
	} else {
		b.requests.Store(count + uint64(n))
	}
}
func (e *counterEntry) load() (store.Delta, bool) {
	for attempt := 0; attempt < 32; attempt++ {
		before := e.sequence.Load()
		if before&1 != 0 {
			continue
		}
		d := store.Delta{Requests: e.requests.Load(), First: e.first.Load(), Last: e.last.Load()}
		if e.sequence.Load() == before {
			return d, true
		}
	}
	return store.Delta{}, false
}
func (b *counterBatch) snapshot(ctx context.Context) (map[netip.Addr]store.Delta, error) {
	result := make(map[netip.Addr]store.Delta, b.len())
	for i, n := 0, b.len(); i < n; i++ {
		if i%256 == 0 {
			if e := ctx.Err(); e != nil {
				return nil, e
			}
		}
		entry := b.slots[i].Load()
		if entry == nil {
			continue
		}
		d, ok := entry.load()
		if !ok {
			return nil, errSnapshotContended
		}
		result[entry.ip] = d
	}
	return result, nil
}
func (b *counterBatch) reset() {
	for i, n := 0, b.len(); i < n; i++ {
		b.slots[i].Store(nil)
	}
	clear(b.index)
	b.requests.Store(0)
	b.size.Store(0)
	b.since.Store(0)
}
