package network

import (
	"container/list"
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"

	"netmon/internal/observation"
)

type pending struct {
	sample   observation.Sample
	raw      []byte
	revision uint64
	ack      *atomic.Int64
}
type memoryQueue struct {
	mu           sync.Mutex
	items        map[string]*list.Element
	order        *list.List
	bytes, limit int
	next         uint64
	notify       chan struct{}
	rejected     atomic.Uint64
	discarded    atomic.Uint64
}

func newQueue(limit int) *memoryQueue {
	return &memoryQueue{items: map[string]*list.Element{}, order: list.New(), limit: limit, notify: make(chan struct{}, 1)}
}
func (q *memoryQueue) put(s observation.Sample, ack *atomic.Int64) bool {
	s.Ports = append([]uint16(nil), s.Ports...)
	raw, _ := json.Marshal(s)
	q.mu.Lock()
	defer q.mu.Unlock()
	size := len(raw) + 256
	old := q.items[s.ID]
	previous := 0
	if old != nil {
		previous = len(old.Value.(pending).raw) + 256
	}
	if q.bytes-previous+size > q.limit {
		q.rejected.Add(1)
		return false
	}
	q.next++
	item := pending{s, raw, q.next, ack}
	if old != nil {
		old.Value = item
	} else {
		q.items[s.ID] = q.order.PushBack(item)
	}
	q.bytes = q.bytes - previous + size
	select {
	case q.notify <- struct{}{}:
	default:
	}
	return true
}
func (q *memoryQueue) peek(n int, retention time.Duration) []pending {
	q.mu.Lock()
	defer q.mu.Unlock()
	var out []pending
	for at := q.order.Front(); at != nil && len(out) < n; {
		next := at.Next()
		p := at.Value.(pending)
		if retention > 0 && p.sample.Window+60 <= time.Now().Add(-retention).Unix() {
			delete(q.items, p.sample.ID)
			q.bytes -= len(p.raw) + 256
			q.order.Remove(at)
			q.discarded.Add(1)
		} else {
			out = append(out, p)
		}
		at = next
	}
	return out
}
func (q *memoryQueue) confirm(items []pending) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for _, p := range items {
		if p.ack != nil {
			for {
				old := p.ack.Load()
				if old >= p.sample.Packets || p.ack.CompareAndSwap(old, p.sample.Packets) {
					break
				}
			}
		}
		at := q.items[p.sample.ID]
		if at == nil {
			continue
		}
		current := at.Value.(pending)
		if current.revision != p.revision {
			continue
		}
		delete(q.items, p.sample.ID)
		q.bytes -= len(current.raw) + 256
		q.order.Remove(at)
	}
}
func (q *memoryQueue) size() (int, int) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.items), q.bytes
}
