package monitor

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"dnsmon/internal/config"
	"dnsmon/internal/live"
	"dnsmon/internal/store"
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
	b.flush = func(batch map[netip.Addr]store.Delta) (store.Change, error) {
		select {
		case <-entered:
		default:
			close(entered)
			<-release
		}
		return original(batch)
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
	b.flush = func(map[netip.Addr]store.Delta) (store.Change, error) { return store.Change{}, errors.New("disk full") }
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
func TestReceiveBufferCapAccountsForLinuxDoubling(t *testing.T) {
	for _, tc := range []struct {
		actual int
		capped bool
	}{{16 << 20, false}, {8 << 20, true}, {12 << 20, true}, {24 << 20, false}} {
		if got := BufferCapped(8<<20, tc.actual); got != tc.capped {
			t.Fatal(tc, got)
		}
	}
}
