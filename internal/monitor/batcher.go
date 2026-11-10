package monitor

import (
	"context"
	"fmt"
	"math"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"dnsmon/internal/config"
	"dnsmon/internal/live"
	"dnsmon/internal/packet"
	"dnsmon/internal/store"
	"golang.org/x/sys/unix"
)

type batcher struct {
	mu sync.Mutex
	// view protects the commit/overlay boundary. Capture only takes mu and can
	// continue while a transaction is on disk or a live snapshot is read.
	view                    sync.RWMutex
	active, inflight, spare map[netip.Addr]store.Delta
	jobs                    chan map[netip.Addr]store.Delta
	changed                 chan struct{}
	finished                chan struct{}
	closeOnce               sync.Once
	closeErr                error
	err                     error
	totals                  store.Totals
	health                  live.Health
	limit                   int
	reader                  *store.Store
	flush                   func(map[netip.Addr]store.Delta) (store.Change, error)
}

func newBatcher(c config.Config, db *store.Store) (*batcher, error) {
	totals, e := db.Totals(context.Background())
	if e != nil {
		return nil, e
	}
	reader, e := store.Open(c.Database, false, 0, 0)
	if e != nil {
		return nil, e
	}
	b := &batcher{active: make(map[netip.Addr]store.Delta), jobs: make(chan map[netip.Addr]store.Delta, 1), changed: make(chan struct{}, 1), finished: make(chan struct{}), totals: totals, limit: c.MaxPending, reader: reader, flush: db.FlushBatch,
		health: live.Health{PID: os.Getpid(), Started: time.Now(), Interface: c.Interface, Port: c.Port, RequestedBuffer: c.SocketBufferMB << 20}}
	go b.writer()
	return b, nil
}
func (b *batcher) writer() {
	defer close(b.finished)
	for batch := range b.jobs {
		b.view.Lock()
		start := time.Now()
		change, e := b.flush(batch)
		b.mu.Lock()
		b.health.FlushDuration = time.Since(start)
		if e != nil {
			b.err = e
			b.health.FlushError = e.Error()
		} else {
			b.totals = b.totals.With(change)
			b.health.LastFlush = time.Now()
			b.health.Flushes++
			b.inflight = nil
			clear(batch)
			b.spare = batch
		}
		b.mu.Unlock()
		b.view.Unlock()
		select {
		case b.changed <- struct{}{}:
		default:
		}
	}
}
func (b *batcher) rotateLocked() {
	if len(b.active) == 0 || b.inflight != nil || b.err != nil {
		return
	}
	b.inflight = b.active
	b.active = b.spare
	b.spare = nil
	if b.active == nil {
		b.active = make(map[netip.Addr]store.Delta)
	}
	b.jobs <- b.inflight
}
func (b *batcher) Rotate()      { b.mu.Lock(); b.rotateLocked(); b.mu.Unlock() }
func (b *batcher) Error() error { b.mu.Lock(); defer b.mu.Unlock(); return b.err }
func (b *batcher) Add(ip netip.Addr, n, ts int64) error {
	waited := false
	for {
		b.mu.Lock()
		if b.err != nil {
			e := b.err
			b.mu.Unlock()
			return e
		}
		_, exists := b.active[ip]
		if exists || len(b.active) < b.limit {
			store.Add(b.active, ip, n, ts)
			b.health.Counted += uint64(n)
			b.health.LastRequest = time.Unix(ts, 0)
			b.mu.Unlock()
			return nil
		}
		b.rotateLocked()
		if len(b.active) == 0 {
			b.mu.Unlock()
			continue
		}
		if !waited {
			b.health.Backpressure++
			waited = true
		}
		b.mu.Unlock()
		<-b.changed // Two full portions: apply backpressure instead of allocating.
	}
}
func (b *batcher) Close() error { b.closeOnce.Do(func() { b.closeErr = b.drain() }); return b.closeErr }
func (b *batcher) drain() error {
	for {
		b.mu.Lock()
		e := b.err
		if e != nil || (len(b.active) == 0 && b.inflight == nil) {
			b.mu.Unlock()
			close(b.jobs)
			<-b.finished
			b.reader.Close()
			return e
		}
		b.rotateLocked()
		b.mu.Unlock()
		<-b.changed
	}
}
func (b *batcher) update(engine *packet.Engine, received, dropped uint64, actual int) {
	flows, tcp, frags, frag := engine.Memory()
	var usage unix.Rusage
	unix.Getrusage(unix.RUSAGE_SELF, &usage)
	cpu := float64(usage.Utime.Sec+usage.Stime.Sec) + float64(usage.Utime.Usec+usage.Stime.Usec)/1e6
	var rss uint64
	if data, e := os.ReadFile("/proc/self/statm"); e == nil {
		fields := strings.Fields(string(data))
		if len(fields) > 1 {
			pages, _ := strconv.ParseUint(fields[1], 10, 64)
			rss = pages * uint64(os.Getpagesize())
		}
	}
	// Keep diagnostics independent of SQLite and preserve a fresh health response
	// even while the writer is blocked on disk.
	b.mu.Lock()
	defer b.mu.Unlock()
	b.health.Updated = time.Now()
	b.health.Received = received
	b.health.KernelDrops = dropped
	b.health.TCPFlows = flows
	b.health.TCPBytes = tcp
	b.health.Fragments = frags
	b.health.FragmentBytes = frag
	b.health.Parser = engine.Counters
	b.health.ActualBuffer = actual
	b.health.RSSBytes = rss
	b.health.CPUSeconds = cpu
}
func (b *batcher) healthLocked() live.Health {
	h := b.health
	h.PendingIPs = len(b.active) + len(b.inflight)
	h.Writing = b.inflight != nil
	var requests uint64
	for _, batch := range []map[netip.Addr]store.Delta{b.active, b.inflight} {
		for _, d := range batch {
			if uint64(d.Requests) > math.MaxUint64-requests {
				requests = math.MaxUint64
			} else {
				requests += uint64(d.Requests)
			}
		}
	}
	h.PendingRequests = requests
	return h
}
func (b *batcher) Snapshot(ctx context.Context, req live.Request) live.Response {
	if req.Op == "health" {
		b.mu.Lock()
		defer b.mu.Unlock()
		return live.Response{Health: b.healthLocked(), Totals: b.totals, Source: "live"}
	}
	b.view.RLock()
	defer b.view.RUnlock()
	if e := ctx.Err(); e != nil {
		return live.Response{Error: e.Error()}
	}
	b.mu.Lock()
	h := b.healthLocked()
	totals := b.totals
	overlay := make(map[netip.Addr]store.Delta, len(b.active)+len(b.inflight))
	for _, batch := range []map[netip.Addr]store.Delta{b.active, b.inflight} {
		for ip, d := range batch {
			store.Add(overlay, ip, d.Requests, d.First)
			if old := overlay[ip]; d.Last > old.Last {
				old.Last = d.Last
				overlay[ip] = old
			}
		}
	}
	b.mu.Unlock()
	rows, totals, e := b.reader.View(ctx, req.Limit, overlay, totals)
	if e != nil {
		return live.Response{Error: fmt.Sprintf("snapshot: %v", e), Health: h}
	}
	return live.Response{Health: h, Totals: totals, Clients: rows, Source: "live"}
}
