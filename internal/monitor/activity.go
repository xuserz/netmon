package monitor

import (
	"container/heap"
	"container/list"
	"math"
	"net/netip"
	"sync/atomic"
	"time"

	"netmon/internal/live"
)

const activityBuckets = 61 // 60 complete seconds plus the second in progress.
type activityEntry struct {
	ip   netip.Addr // immutable, including when its cache slot is replaced
	seq  atomic.Uint64
	last atomic.Int64
	bins [activityBuckets]atomic.Uint64
}
type activitySlot struct {
	index int
	entry *activityEntry
}
type activityTracker struct {
	limit     int
	index     map[netip.Addr]*list.Element // capture-owned, under batcher.mu
	lru       *list.List
	slots     []atomic.Pointer[activityEntry]
	size      atomic.Int64
	evictions atomic.Uint64
	evictedAt atomic.Int64
	total     activityEntry
}

func newActivity(limit int) *activityTracker {
	return &activityTracker{limit: limit, index: make(map[netip.Addr]*list.Element), lru: list.New(), slots: make([]atomic.Pointer[activityEntry], limit)}
}
func saturating(a, b uint64) uint64 {
	if b > math.MaxUint64-a {
		return math.MaxUint64
	}
	return a + b
}
func (e *activityEntry) add(n uint64, sec int64) {
	if sec < 0 {
		return
	}
	e.seq.Add(1)
	last := e.last.Load()
	if sec > last {
		if sec-last >= activityBuckets {
			for i := range e.bins {
				e.bins[i].Store(0)
			}
		} else {
			for at := last + 1; at <= sec; at++ {
				e.bins[at%activityBuckets].Store(0)
			}
		}
		e.last.Store(sec)
	}
	if sec >= e.last.Load()-60 {
		bin := &e.bins[sec%activityBuckets]
		bin.Store(saturating(bin.Load(), n))
	}
	e.seq.Add(1)
}
func (a *activityTracker) add(ip netip.Addr, n int64, sec int64) {
	if a.limit == 0 {
		return
	}
	a.total.add(uint64(n), sec)
	if element := a.index[ip]; element != nil {
		a.lru.MoveToBack(element)
		element.Value.(activitySlot).entry.add(uint64(n), sec)
		return
	}
	slot := int(a.size.Load())
	if slot == a.limit {
		element := a.lru.Front()
		value := element.Value.(activitySlot)
		slot = value.index
		delete(a.index, value.entry.ip)
		a.lru.Remove(element)
		a.evictions.Add(1)
		a.evictedAt.Store(time.Now().Unix())
	}
	entry := &activityEntry{ip: ip}
	entry.last.Store(sec)
	entry.add(uint64(n), sec)
	a.index[ip] = a.lru.PushBack(activitySlot{slot, entry})
	a.slots[slot].Store(entry)
	if a.size.Load() < int64(a.limit) {
		a.size.Add(1)
	}
}
func (e *activityEntry) window(now int64) (five, minute uint64, ok bool) {
	for attempt := 0; attempt < 8; attempt++ {
		before := e.seq.Load()
		if before&1 != 0 {
			continue
		}
		last := e.last.Load()
		five, minute = 0, 0
		for sec := now - 60; sec < now; sec++ {
			if sec < 0 || sec > last || sec < last-60 {
				continue
			}
			count := e.bins[sec%activityBuckets].Load()
			minute = saturating(minute, count)
			if sec >= now-5 {
				five = saturating(five, count)
			}
		}
		if e.seq.Load() == before {
			return five, minute, true
		}
	}
	return 0, 0, false
}

type activitySnapshot struct {
	rate, minute []live.ActivityClient
	at           time.Time
	partial      bool
}
type activityHeap struct {
	rows     []live.ActivityClient
	byMinute bool
}

func activityBetter(a, b live.ActivityClient, minute bool) bool {
	if minute && a.Minute != b.Minute {
		return a.Minute > b.Minute
	}
	if a.Rate != b.Rate {
		return a.Rate > b.Rate
	}
	if a.Minute != b.Minute {
		return a.Minute > b.Minute
	}
	return a.IP < b.IP
}
func (h activityHeap) Len() int           { return len(h.rows) }
func (h activityHeap) Less(i, j int) bool { return activityBetter(h.rows[j], h.rows[i], h.byMinute) }
func (h activityHeap) Swap(i, j int)      { h.rows[i], h.rows[j] = h.rows[j], h.rows[i] }
func (h *activityHeap) Push(v any)        { h.rows = append(h.rows, v.(live.ActivityClient)) }
func (h *activityHeap) Pop() any {
	last := h.rows[len(h.rows)-1]
	h.rows = h.rows[:len(h.rows)-1]
	return last
}
func (h *activityHeap) add(row live.ActivityClient) {
	if h.Len() < 1000 {
		heap.Push(h, row)
	} else if activityBetter(row, h.rows[0], h.byMinute) {
		h.rows[0] = row
		heap.Fix(h, 0)
	}
}
func (h *activityHeap) sorted() []live.ActivityClient {
	result := make([]live.ActivityClient, h.Len())
	for i := len(result) - 1; i >= 0; i-- {
		result[i] = heap.Pop(h).(live.ActivityClient)
	}
	return result
}
func (a *activityTracker) snapshot(now time.Time) *activitySnapshot {
	sec := now.Unix()
	generation := a.evictions.Load()
	result := &activitySnapshot{at: now, partial: generation > 0 && a.evictedAt.Load() >= sec-60}
	sampled := make(map[string]live.ActivityClient, int(a.size.Load()))
	for i, n := int64(0), a.size.Load(); i < n; i++ {
		entry := a.slots[i].Load()
		if entry == nil {
			continue
		}
		five, count, ok := entry.window(sec)
		if !ok {
			result.partial = true
			continue
		}
		if count == 0 {
			continue
		}
		key := entry.ip.String()
		row := sampled[key]
		row.IP = key
		row.Rate += float64(five) / 5
		row.Minute = saturating(row.Minute, count)
		sampled[key] = row
	}
	_, total, ok := a.total.window(sec)
	result.partial = result.partial || !ok || a.evictions.Load() != generation
	rate, minute := &activityHeap{}, &activityHeap{byMinute: true}
	for _, row := range sampled {
		if total > 0 {
			row.Share = min(100, 100*float64(row.Minute)/float64(total))
		}
		rate.add(row)
		minute.add(row)
	}
	result.rate, result.minute = rate.sorted(), minute.sorted()
	return result
}
