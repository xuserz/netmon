package monitor

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestActivityWindowsRankingAndExpiry(t *testing.T) {
	a := newActivity(4)
	ip1 := netip.MustParseAddr("192.0.2.1")
	ip2 := netip.MustParseAddr("192.0.2.2")
	a.add(ip1, 100, 100)
	a.add(ip2, 10, 159)
	a.add(ip2, 50, 160)
	s := a.snapshot(time.Unix(160, 0))
	if len(s.rate) != 2 || s.rate[0].IP != ip2.String() || s.rate[0].Rate != 2 || s.rate[0].Minute != 10 {
		t.Fatal(s.rate)
	}
	if s.minute[0].IP != ip1.String() || s.minute[0].Minute != 100 {
		t.Fatal(s.minute)
	}
	if got := s.rate[0].Share; got < 9.09 || got > 9.1 {
		t.Fatal(got)
	}
	s = a.snapshot(time.Unix(161, 0))
	if len(s.minute) != 1 || s.minute[0].Minute != 60 || s.rate[0].Rate != 12 {
		t.Fatal(s)
	}
	if len(a.snapshot(time.Unix(221, 0)).rate) != 0 {
		t.Fatal("expired activity retained")
	}
	// A late packet within the window belongs to its arrival second.
	a.add(ip2, 5, 158)
	if got := a.snapshot(time.Unix(161, 0)).rate[0]; got.Minute != 65 || got.Rate != 13 {
		t.Fatal(got)
	}
}
func TestActivityEvictionIsBoundedAndDoesNotAffectDurableCounts(t *testing.T) {
	a := newActivity(1)
	now := time.Now().Unix()
	a.add(netip.MustParseAddr("192.0.2.1"), 5, now-1)
	a.add(netip.MustParseAddr("192.0.2.2"), 10, now-1)
	s := a.snapshot(time.Unix(now, 0))
	if len(a.index) != 1 || a.size.Load() != 1 || a.evictions.Load() != 1 || !s.partial || len(s.rate) != 1 {
		t.Fatal(a.size.Load(), s)
	}
	if s.rate[0].Share < 66.66 || s.rate[0].Share > 66.67 {
		t.Fatal(s.rate)
	}
	b, store := setupBatcher(t, 2)
	b.activity = newActivity(1)
	for i := 1; i <= 20; i++ {
		if e := b.Add(netip.MustParseAddr(fmt.Sprint("192.0.2.", i)), 1, now-1); e != nil {
			t.Fatal(e)
		}
	}
	if e := b.Close(); e != nil {
		t.Fatal(e)
	}
	totals, e := store.Totals(context.Background())
	if e != nil || totals.Requests != "20" || totals.Unique != 20 {
		t.Fatal(totals, e)
	}
}
func TestActivityConcurrentSamplingAndCacheReplacement(t *testing.T) {
	a := newActivity(16)
	done := make(chan struct{})
	var mu sync.Mutex
	go func() {
		defer close(done)
		for i := 0; i < 20000; i++ {
			mu.Lock()
			a.add(netip.AddrFrom4([4]byte{192, 0, 2, byte(i % 32)}), 1, 100)
			mu.Unlock()
		}
	}()
	for {
		snapshot := a.snapshot(time.Unix(101, 0))
		seen := map[string]bool{}
		for _, row := range snapshot.rate {
			if seen[row.IP] || row.Share > 100 {
				t.Fatal(row)
			}
			seen[row.IP] = true
		}
		select {
		case <-done:
			return
		default:
		}
	}
}
func TestActivityDisabledAndAllClientsWindowTracked(t *testing.T) {
	a := newActivity(0)
	a.add(netip.MustParseAddr("::1"), 1, 1)
	if a.size.Load() != 0 || len(a.snapshot(time.Unix(2, 0)).rate) != 0 {
		t.Fatal("disabled cache populated")
	}
}
