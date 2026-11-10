package monitor

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"dnsmon/internal/config"
	"dnsmon/internal/live"
	"dnsmon/internal/store"
)

type batcher struct {
	mu                      sync.Mutex
	active, inflight, spare *counterBatch
	jobs                    chan *counterBatch
	changed, finished       chan struct{}
	closeOnce               sync.Once
	closeErr                error
	closed                  bool
	err                     error
	captureErr              error
	capture                 atomic.Pointer[captureSample]
	blockedSince            time.Time
	activity                *activityTracker
	activityPublished       atomic.Pointer[activitySnapshot]
	totals                  store.Totals
	health                  live.Health
	limit                   int
	retryTimeout            time.Duration
	shutdownAt              atomic.Int64
	reader                  *store.Store
	prepare                 func(context.Context, map[netip.Addr]store.Delta) (*store.PreparedBatch, error)
	flush                   func(context.Context, *store.PreparedBatch) error
	acknowledge             func(*store.PreparedBatch)
	// Odd revision means a commit is in flight or its outcome is uncertain.
	// Publication is optimistic; no snapshot reader can block the writer.
	revision    atomic.Uint64
	published   atomic.Pointer[live.Response]
	demandUntil atomic.Int64
	wake        chan struct{}
	pubCancel   context.CancelFunc
	pubDone     chan struct{}
}

func newBatcher(c config.Config, db *store.Store) (*batcher, error) {
	db.ConfigureCache(c.HotCacheIPs)
	totals, e := db.Totals(context.Background())
	if e != nil {
		return nil, e
	}
	reader, e := store.Open(c.Database, false, 0, 0)
	if e != nil {
		return nil, e
	}
	rows, _, e := reader.View(context.Background(), 1000, nil, totals)
	if e != nil {
		reader.Close()
		return nil, e
	}
	ctx, cancel := context.WithCancel(context.Background())
	b := &batcher{active: newCounterBatch(c.MaxPending), jobs: make(chan *counterBatch, 1), changed: make(chan struct{}, 1), finished: make(chan struct{}), totals: totals, limit: c.MaxPending, retryTimeout: c.WriteRetryTimeout, reader: reader,
		prepare: db.PrepareBatch, flush: db.ApplyPrepared, acknowledge: db.Acknowledge, wake: make(chan struct{}, 1), pubCancel: cancel, pubDone: make(chan struct{}),
		health: live.Health{SQLiteVersion: store.SQLiteVersion(), PID: os.Getpid(), Started: time.Now(), Interface: c.Interface, Port: c.Port, RequestedBuffer: c.SocketBufferMB << 20}}
	b.activity = newActivity(c.MaxActivityIPs)
	b.activityPublished.Store(&activitySnapshot{})
	b.published.Store(&live.Response{Clients: rows, Totals: totals, Source: "live", SnapshotAt: time.Now()})
	go b.writer()
	go b.publisher(ctx)
	return b, nil
}
func (b *batcher) retry(fn func(context.Context) error) error {
	deadline := time.Now().Add(b.retryTimeout)
	backoff := 50 * time.Millisecond
	for {
		if stop := b.shutdownAt.Load(); stop != 0 {
			earlier := time.Unix(0, stop).Add(5 * time.Second)
			if earlier.Before(deadline) {
				deadline = earlier
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("writer retry budget exhausted: %s", b.retryTimeout)
		}
		ctx, cancel := context.WithDeadline(context.Background(), deadline)
		e := fn(ctx)
		cancel()
		if e == nil {
			return nil
		}
		if !store.Retryable(e) {
			return e
		}
		b.mu.Lock()
		b.health.FlushError = e.Error()
		b.health.WriteRetries++
		b.mu.Unlock()
		log.Printf("WARNING: transient SQLite failure; retaining batch for idempotent retry: %v", e)
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return e
		}
		time.Sleep(min(backoff, remaining))
		backoff = min(backoff*2, time.Second)
	}
}
func (b *batcher) writer() {
	defer close(b.finished)
	for batch := range b.jobs {
		start := time.Now()
		deltas, e := batch.snapshot(context.Background())
		var prepared *store.PreparedBatch
		if e == nil {
			e = b.retry(func(ctx context.Context) error { var err error; prepared, err = b.prepare(ctx, deltas); return err })
		}
		if e == nil {
			b.revision.Add(1)
			e = b.retry(func(ctx context.Context) error { return b.flush(ctx, prepared) })
		}
		if e == nil {
			b.acknowledge(prepared)
			batch.reset()
		}
		b.mu.Lock()
		b.health.FlushDuration = time.Since(start)
		if e != nil {
			b.err = e
			b.health.FlushError = e.Error()
		} else {
			b.totals = b.totals.With(prepared.Change)
			b.health.LastFlush = time.Now()
			b.health.Flushes++
			b.health.FlushError = ""
			b.inflight = nil
			b.spare = batch
		}
		b.mu.Unlock()
		if e == nil {
			b.revision.Add(1)
			b.requestPublish()
		}
		select {
		case b.changed <- struct{}{}:
		default:
		}
	}
}
func (b *batcher) rotateLocked() {
	if b.active.len() == 0 || b.inflight != nil || b.err != nil {
		return
	}
	b.inflight = b.active
	b.active = b.spare
	b.spare = nil
	if b.active == nil {
		b.active = newCounterBatch(b.limit)
	}
	b.jobs <- b.inflight
}
func (b *batcher) Rotate() {
	b.mu.Lock()
	if !b.closed {
		b.rotateLocked()
	}
	b.mu.Unlock()
}
func (b *batcher) Error() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	return errors.Join(b.err, b.captureErr)
}
func (b *batcher) Add(ip netip.Addr, n, ts int64) error {
	return b.AddContext(context.Background(), ip, n, ts)
}
func (b *batcher) AddContext(ctx context.Context, ip netip.Addr, n, ts int64) error {
	if n < 0 {
		return errors.New("negative request count")
	}
	waited := false
	for {
		b.mu.Lock()
		if b.err != nil || b.captureErr != nil || b.closed {
			e := errors.Join(b.err, b.captureErr)
			if e == nil {
				e = errors.New("writer is closed")
			}
			b.mu.Unlock()
			return e
		}
		_, exists := b.active.index[ip]
		if exists || b.active.len() < b.limit {
			b.active.add(ip, n, ts)
			b.activity.add(ip, n, ts)
			if uint64(n) > math.MaxUint64-b.health.Counted {
				b.health.Counted = math.MaxUint64
			} else {
				b.health.Counted += uint64(n)
			}
			b.health.LastRequest = time.Unix(ts, 0)
			b.mu.Unlock()
			return nil
		}
		b.rotateLocked()
		if b.active.len() == 0 {
			b.mu.Unlock()
			continue
		}
		if !waited {
			b.health.Backpressure++
			b.blockedSince = time.Now()
			defer func() { b.mu.Lock(); b.blockedSince = time.Time{}; b.mu.Unlock() }()
			waited = true
		}
		b.mu.Unlock()
		select {
		case <-b.changed:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
func (b *batcher) Close() error {
	b.closeOnce.Do(func() {
		b.shutdownAt.Store(time.Now().UnixNano())
		b.pubCancel()
		<-b.pubDone
		b.mu.Lock()
		b.closed = true
		b.mu.Unlock()
		b.closeErr = b.drain()
	})
	return b.closeErr
}
func (b *batcher) drain() error {
	for {
		b.mu.Lock()
		e := b.err
		if e != nil || (b.active.len() == 0 && b.inflight == nil) {
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
func (b *batcher) healthLocked() live.Health {
	h := b.health
	if !b.blockedSince.IsZero() {
		h.BlockedFor = time.Since(b.blockedSince)
	}
	oldest := b.active.since.Load()
	if b.inflight != nil {
		if other := b.inflight.since.Load(); other != 0 && (oldest == 0 || other < oldest) {
			oldest = other
		}
	}
	if oldest != 0 {
		h.PendingAge = max(0, time.Since(time.Unix(0, oldest)))
	}
	h.ActivityEntries = int(b.activity.size.Load())
	h.ActivityLimit = b.activity.limit
	h.ActivityEvictions = b.activity.evictions.Load()
	h.PendingIPs = b.active.len()
	h.PendingRequests = b.active.requests.Load()
	h.Writing = b.inflight != nil
	if b.inflight != nil {
		h.PendingIPs += b.inflight.len()
		n := b.inflight.requests.Load()
		if n > math.MaxUint64-h.PendingRequests {
			h.PendingRequests = math.MaxUint64
		} else {
			h.PendingRequests += n
		}
	}
	return h
}
func (b *batcher) requestPublish() {
	select {
	case b.wake <- struct{}{}:
	default:
	}
}
func (b *batcher) Snapshot(_ context.Context, req live.Request) live.Response {
	if req.Op == "top" {
		b.demandUntil.Store(time.Now().Add(5 * time.Second).UnixNano())
		b.requestPublish()
	}
	b.mu.Lock()
	h := b.healthLocked()
	total := b.totals
	b.mu.Unlock()
	if req.Op == "health" {
		return live.Response{Health: h, Totals: total, Source: "live"}
	}
	r := *b.published.Load()
	r.Sort = req.Sort
	if req.Sort == "rate" || req.Sort == "minute" {
		r.Totals = total // activity views label these acknowledged totals as saved
		activity := b.activityPublished.Load()
		r.SnapshotAt = activity.at
		r.ActivityPartial = activity.partial
		r.Activity = activity.rate
		if req.Sort == "minute" {
			r.Activity = activity.minute
		}
		if req.Limit > 0 && len(r.Activity) > req.Limit {
			r.Activity = r.Activity[:req.Limit]
		}
		r.Clients = nil
	}

	r.Health = h
	if req.Limit > 0 && len(r.Clients) > req.Limit {
		r.Clients = r.Clients[:req.Limit]
	}
	return r
}
func (b *batcher) publisher(ctx context.Context) {
	defer close(b.pubDone)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var attempted time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-b.wake:
		}
		if time.Now().UnixNano() > b.demandUntil.Load() || time.Since(attempted) < time.Second {
			continue
		}
		attempted = time.Now()
		b.activityPublished.Store(b.activity.snapshot(time.Now()))
		b.publish(ctx)
	}
}
func (b *batcher) publish(ctx context.Context) bool {
	revision := b.revision.Load()
	if revision&1 != 0 {
		return false
	}
	b.mu.Lock()
	active, inflight, total := b.active, b.inflight, b.totals
	b.mu.Unlock()
	sampleCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	sampled := time.Now()
	overlay, e := active.snapshot(sampleCtx)
	if e != nil {
		return false
	}
	if inflight != nil {
		deltas, err := inflight.snapshot(sampleCtx)
		if err != nil {
			return false
		}
		for ip, d := range deltas {
			store.Add(overlay, ip, d.Requests, d.First)
			old := overlay[ip]
			old.Last = max(old.Last, d.Last)
			overlay[ip] = old
		}
	}
	rows, total, e := b.reader.View(sampleCtx, 1000, overlay, total)
	if e != nil || b.revision.Load() != revision {
		return false
	}
	b.published.Store(&live.Response{Clients: rows, Totals: total, Source: "live", SnapshotAt: sampled})
	return true
}
