package monitor

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"dnsmon/internal/live"
	"dnsmon/internal/store"
)

func TestSlowDiskKeepsHeartbeatResponsiveWhileCaptureIsBlocked(t *testing.T) {
	b, s := setupBatcher(t, 1)
	original := b.flush
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	defer once.Do(func() { close(release) })
	b.flush = func(ctx context.Context, p *store.PreparedBatch) error {
		onceEntered := false
		select {
		case <-entered:
		default:
			close(entered)
			onceEntered = true
		}
		if onceEntered {
			<-release
		}
		return original(ctx, p)
	}
	stop := b.startHealth(context.Background(), &fakeSource{}, 0, false)
	defer stop()
	b.Add(netip.MustParseAddr("::1"), 1, 10)
	b.Rotate()
	<-entered
	b.Add(netip.MustParseAddr("::2"), 1, 10)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	added := make(chan error, 1)
	go func() { added <- b.AddContext(ctx, netip.MustParseAddr("::3"), 1, 10) }()
	deadline := time.Now().Add(2 * time.Second)
	for b.Snapshot(ctx, live.Request{Op: "health"}).Health.BlockedFor == 0 {
		if time.Now().After(deadline) {
			t.Fatal("capture never blocked")
		}
		time.Sleep(time.Millisecond)
	}
	before := b.Snapshot(ctx, live.Request{Op: "health"}).Health
	deadline = time.Now().Add(2 * time.Second)
	for {
		after := b.Snapshot(ctx, live.Request{Op: "health"}).Health
		if after.Updated.After(before.Updated) {
			if after.BlockedFor <= 0 || after.PendingAge <= 0 || after.PendingRequests != 2 {
				t.Fatal(after)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("health heartbeat stopped with capture")
		}
		time.Sleep(time.Millisecond)
	}
	once.Do(func() { close(release) })
	if e := <-added; e != nil {
		t.Fatal(e)
	}
	if e := b.Close(); e != nil {
		t.Fatal(e)
	}
	total, e := s.Totals(ctx)
	if e != nil || total.Requests != "3" {
		t.Fatal(total, e)
	}
}
func TestBurstOfUniqueIPsBoundsBothBatchesAndActivity(t *testing.T) {
	b, s := setupBatcher(t, 64)
	b.activity = newActivity(32)
	const requests = 20000
	for i := 0; i < requests; i++ {
		ip := netip.MustParseAddr(fmt.Sprintf("2001:db8::%x", i))
		if e := b.Add(ip, 1, time.Now().Unix()); e != nil {
			t.Fatal(e)
		}
		if i%100 == 0 {
			h := b.Snapshot(context.Background(), live.Request{Op: "health"}).Health
			if h.PendingIPs > 128 || h.ActivityEntries > 32 {
				t.Fatal(h)
			}
		}
	}
	if e := b.Close(); e != nil {
		t.Fatal(e)
	}
	total, e := s.Totals(context.Background())
	if e != nil || total.Unique != requests || total.Requests != "20000" {
		t.Fatal(total, e)
	}
	if b.activity.evictions.Load() != requests-32 {
		t.Fatal(b.activity.evictions.Load())
	}
}
