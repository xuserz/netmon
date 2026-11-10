package monitor

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"dnsmon/internal/config"
	"dnsmon/internal/live"
	"dnsmon/internal/store"
	"github.com/mattn/go-sqlite3"
)

func setupBatcher(t *testing.T, limit int) (*batcher, *store.Store) {
	t.Helper()
	c := config.Default()
	c.Database = filepath.Join(t.TempDir(), "stats.db")
	c.MaxPending = limit
	s, e := store.Open(c.Database, true, 8, 2)
	if e != nil {
		t.Fatal(e)
	}
	b, e := newBatcher(c, s)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { b.Close(); s.Close() })
	return b, s
}
func TestCaptureContinuesWhileWriterIsBlockedAndQueueIsBounded(t *testing.T) {
	b, s := setupBatcher(t, 1)
	entered := make(chan struct{})
	release := make(chan struct{})
	original := b.flush
	b.flush = func(ctx context.Context, batch *store.PreparedBatch) error {
		select {
		case <-entered:
		default:
			close(entered)
			<-release
		}
		return original(ctx, batch)
	}
	a := netip.MustParseAddr("192.0.2.1")
	b.Add(a, 1, 1)
	b.Rotate()
	<-entered
	second := make(chan error, 1)
	go func() { second <- b.Add(netip.MustParseAddr("192.0.2.2"), 1, 2) }()
	select {
	case e := <-second:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("capture blocked before both portions filled")
	}
	h := b.Snapshot(context.Background(), live.Request{Op: "health"}).Health
	if h.PendingIPs != 2 || h.PendingRequests != 2 || !h.Writing {
		t.Fatal(h)
	}
	third := make(chan error, 1)
	go func() { third <- b.Add(netip.MustParseAddr("192.0.2.3"), 1, 3) }()
	select {
	case <-third:
		t.Fatal("queue exceeded its bound")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if e := <-third; e != nil {
		t.Fatal(e)
	}
	if e := b.Close(); e != nil {
		t.Fatal(e)
	}
	total, _ := s.Totals(context.Background())
	if total.Requests != "3" || total.Unique != 3 {
		t.Fatal(total)
	}
}
func TestLiveSnapshotBeforeAndAfterCommitDoesNotDoubleCount(t *testing.T) {
	b, s := setupBatcher(t, 100)
	ip := netip.MustParseAddr("192.0.2.1")
	for i := 0; i < 10; i++ {
		if e := b.Add(ip, 1, int64(i+1)); e != nil {
			t.Fatal(e)
		}
	}
	refreshSnapshot(t, b)
	r := b.Snapshot(context.Background(), live.Request{Op: "top", Limit: 20})
	if r.Totals.Requests != "10" || r.Totals.Unique != 1 || len(r.Clients) != 1 || r.Clients[0].Requests != 10 {
		t.Fatal(r)
	}
	total, _ := s.Totals(context.Background())
	if total.Requests != "0" {
		t.Fatal(total)
	}
	b.Rotate()
	for i := 0; i < 100; i++ {
		b.Add(ip, 1, 11)
		refreshSnapshot(t, b)
		r = b.Snapshot(context.Background(), live.Request{Op: "top", Limit: 20})
		if r.Error != "" || r.Totals.Requests != fmt.Sprint(11+i) {
			t.Fatal(i, r)
		}
	}
	if e := b.Close(); e != nil {
		t.Fatal(e)
	}
	total, _ = s.Totals(context.Background())
	if total.Requests != "110" {
		t.Fatal(total)
	}
}
func TestWriterFailureRetainsDiagnosticAndStopsIngestion(t *testing.T) {
	b, _ := setupBatcher(t, 2)
	b.flush = func(context.Context, *store.PreparedBatch) error { return errors.New("disk full") }
	ip := netip.MustParseAddr("::1")
	b.Add(ip, 1, 1)
	b.Rotate()
	<-b.changed
	if b.Add(ip, 1, 2) == nil {
		t.Fatal("writer failure ignored")
	}
	r := b.Snapshot(context.Background(), live.Request{Op: "health"})
	if r.Health.FlushError != "disk full" || r.Health.PendingRequests != 1 {
		t.Fatal(r)
	}
	if b.Close() == nil {
		t.Fatal("shutdown hid failure")
	}
}
func refreshSnapshot(t *testing.T, b *batcher) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !b.publish(context.Background()) {
		if time.Now().After(deadline) {
			t.Fatal("snapshot was never published")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestAmbiguousCommitRetriesSameTargetsAndKeepsCaptureRunning(t *testing.T) {
	b, s := setupBatcher(t, 4)
	original := b.flush
	attempted := make(chan struct{})
	resume := make(chan struct{})
	attempts := 0
	b.flush = func(ctx context.Context, p *store.PreparedBatch) error {
		attempts++
		if e := original(ctx, p); e != nil {
			return e
		}
		if attempts == 1 {
			close(attempted)
			<-resume
			return sqlite3.Error{Code: sqlite3.ErrIoErr}
		}
		return nil
	}
	ip := netip.MustParseAddr("192.0.2.1")
	b.Add(ip, 7, 10)
	b.Rotate()
	<-attempted
	b.Add(ip, 3, 20)
	// No SQL/map copy per RPC: even a closed snapshot reader does not affect serving.
	b.reader.Close()
	for i := 0; i < 1000; i++ {
		if r := b.Snapshot(context.Background(), live.Request{Op: "top", Limit: 20}); r.Error != "" {
			t.Fatal(r)
		}
	}
	close(resume)
	if e := b.Close(); e != nil {
		t.Fatal(e)
	}
	total, e := s.Totals(context.Background())
	if e != nil || total.Requests != "10" || total.Unique != 1 {
		t.Fatal(total, e)
	}
	if attempts != 3 {
		t.Fatal("one replay and one subsequent batch expected", attempts)
	}
	if b.health.WriteRetries != 1 {
		t.Fatal(b.health)
	}
}
func TestPublishedSnapshotSurvivesBatchReuse(t *testing.T) {
	b, _ := setupBatcher(t, 2)
	ip := netip.MustParseAddr("::1")
	b.Add(ip, 7, 10)
	refreshSnapshot(t, b)
	old := b.Snapshot(context.Background(), live.Request{Op: "top", Limit: 1})
	for i := 0; i < 5; i++ {
		b.Rotate()
		<-b.changed
		b.Add(ip, 1, 20)
	}
	refreshSnapshot(t, b)
	if old.Clients[0].Requests != 7 || old.Totals.Requests != "7" {
		t.Fatal("published rows were mutated", old)
	}
	if r := b.Snapshot(context.Background(), live.Request{Op: "top", Limit: 1}); r.Totals.Requests != "12" {
		t.Fatal(r)
	}
}
func TestConcurrentSamplingNeverTearsOneCounter(t *testing.T) {
	b := newCounterBatch(1)
	ip := netip.MustParseAddr("::1")
	b.add(ip, 1, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := int64(2); i <= 50000; i++ {
			b.add(ip, 1, i)
		}
	}()
	for {
		rows, e := b.snapshot(context.Background())
		if e == nil {
			d := rows[ip]
			if d.Requests != d.Last || d.First != 1 {
				t.Fatal(d)
			}
		}
		select {
		case <-done:
			return
		default:
		}
	}
}

func TestSlowPublisherDoesNotBlockCaptureOrWriter(t *testing.T) {
	b, s := setupBatcher(t, 4)
	// Occupy the reader's only connection: publication must wait for SQL outside
	// the capture mutex, and must not hold a writer revision lock.
	conn, e := b.reader.DB.Conn(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	published := make(chan bool, 1)
	go func() { published <- b.publish(context.Background()) }()
	deadline := time.Now().Add(time.Second)
	for b.reader.DB.Stats().WaitCount == 0 {
		if time.Now().After(deadline) {
			t.Fatal("publisher did not request SQL connection")
		}
		time.Sleep(time.Millisecond)
	}
	ip := netip.MustParseAddr("::1")
	added := make(chan error, 1)
	go func() { added <- b.Add(ip, 1, 10) }()
	select {
	case e := <-added:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("slow publication blocked capture")
	}
	b.Rotate()
	select {
	case <-b.changed:
	case <-time.After(300 * time.Millisecond):
		t.Fatal("slow publication blocked writer")
	}
	conn.Close()
	<-published
	if e = b.Close(); e != nil {
		t.Fatal(e)
	}
	total, e := s.Totals(context.Background())
	if e != nil || total.Requests != "1" {
		t.Fatal(total, e)
	}
}
func TestRealSQLiteBusyRecoversWithoutLosingBatch(t *testing.T) {
	b, s := setupBatcher(t, 4)
	// A second writer owns SQLite's write lock while WAL readers stay available.
	blocker, e := sql.Open("sqlite3", sPath(s))
	if e != nil {
		t.Fatal(e)
	}
	defer blocker.Close()
	if _, e = blocker.Exec("BEGIN IMMEDIATE"); e != nil {
		t.Fatal(e)
	}
	defer blocker.Exec("ROLLBACK")
	ip := netip.MustParseAddr("::1")
	b.Add(ip, 7, 10)
	b.Rotate()
	deadline := time.Now().Add(2 * time.Second)
	for b.Snapshot(context.Background(), live.Request{Op: "health"}).Health.WriteRetries == 0 {
		if time.Now().After(deadline) {
			t.Fatal("SQLite lock was not retried")
		}
		time.Sleep(time.Millisecond)
	}
	b.Add(ip, 3, 20)
	if _, e = blocker.Exec("ROLLBACK"); e != nil {
		t.Fatal(e)
	}
	if e = b.Close(); e != nil {
		t.Fatal(e)
	}
	total, e := s.Totals(context.Background())
	if e != nil || total.Requests != "10" {
		t.Fatal(total, e)
	}
}
func sPath(s *store.Store) string {
	var seq int
	var name, path string
	if e := s.DB.QueryRow("PRAGMA database_list").Scan(&seq, &name, &path); e != nil {
		panic(e)
	}
	return path
}

func TestPersistentBusyExhaustsBudgetAndRetainsPendingCounters(t *testing.T) {
	b, _ := setupBatcher(t, 2)
	b.retryTimeout = time.Second
	b.flush = func(context.Context, *store.PreparedBatch) error { return sqlite3.Error{Code: sqlite3.ErrBusy} }
	b.Add(netip.MustParseAddr("::1"), 7, 10)
	b.Rotate()
	select {
	case <-b.changed:
	case <-time.After(3 * time.Second):
		t.Fatal("unbounded retries")
	}
	if b.Error() == nil {
		t.Fatal("persistent lock was hidden")
	}
	h := b.Snapshot(context.Background(), live.Request{Op: "health"}).Health
	if h.WriteRetries < 2 || h.PendingRequests != 7 || h.FlushError == "" {
		t.Fatal(h)
	}
	if e := b.Close(); e == nil {
		t.Fatal("shutdown hid exhausted retry budget")
	}
}
