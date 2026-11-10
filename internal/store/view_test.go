package store

import (
	"context"
	"math"
	"net/netip"
	"path/filepath"
	"testing"
)

func TestLiveTopOverlayPromotesPreviouslyHiddenClient(t *testing.T) {
	s := openTest(t, filepath.Join(t.TempDir(), "stats.db"))
	a := netip.MustParseAddr("192.0.2.1")
	b := netip.MustParseAddr("192.0.2.2")
	c := netip.MustParseAddr("2001:db8::1")
	if e := s.Flush(map[netip.Addr]Delta{a: {100, 10, 20}, b: {1, 10, 20}}); e != nil {
		t.Fatal(e)
	}
	total, e := s.Totals(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	overlay := map[netip.Addr]Delta{b: {150, 5, 30}, c: {2, 25, 25}}
	rows, live, e := s.View(context.Background(), 1, overlay, total)
	if e != nil {
		t.Fatal(e)
	}
	if len(rows) != 1 || rows[0].IP != b.String() || rows[0].Requests != 151 || live.Unique != 3 || live.Requests != "253" || live.First != 5 || live.Last != 30 {
		t.Fatal(rows, live)
	}
	committed, _ := s.Totals(context.Background())
	if committed.Requests != "101" {
		t.Fatal("live view wrote data", committed)
	}
	change, e := s.FlushBatch(overlay)
	if e != nil {
		t.Fatal(e)
	}
	if got := total.With(change); got != live {
		t.Fatal("cached summary diverged", got, live)
	}
}
func TestSummarySaturationAndLargeTotals(t *testing.T) {
	s := openTest(t, filepath.Join(t.TempDir(), "stats.db"))
	a := netip.MustParseAddr("::1")
	b := netip.MustParseAddr("::2")
	s.Flush(map[netip.Addr]Delta{a: {math.MaxInt64 - 1, 1, 1}, b: {math.MaxInt64, 1, 1}})
	total, _ := s.Totals(context.Background())
	change, e := s.FlushBatch(map[netip.Addr]Delta{a: {10, 1, 2}, b: {10, 1, 2}})
	if e != nil {
		t.Fatal(e)
	}
	got := total.With(change)
	actual, _ := s.Totals(context.Background())
	if got != actual || got.Requests != "18446744073709551614" || change.Added != "1" {
		t.Fatal(got, actual, change)
	}
}
