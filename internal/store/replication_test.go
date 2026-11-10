package store

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"
)

func TestSourceFeedSeedsCoalescesAndPaginatesBatch(t *testing.T) {
	s := openTest(t, filepath.Join(t.TempDir(), "stats.db"))
	ctx := context.Background()
	ip1 := netip.MustParseAddr("192.0.2.1")
	ip2 := netip.MustParseAddr("192.0.2.2")
	if e := s.Flush(map[netip.Addr]Delta{ip1: {7, 1, 2}}); e != nil {
		t.Fatal(e)
	}
	node, e := s.EnableReplication()
	if e != nil {
		t.Fatal(e)
	}
	p, e := s.SourceChanges(ctx, SourceCursor{}, 1)
	if e != nil || len(p.Clients) != 1 || p.Clients[0].Requests != 7 {
		t.Fatal(p, e)
	}
	prepared, e := s.PrepareBatch(ctx, map[netip.Addr]Delta{ip1: {3, 3, 3}, ip2: {5, 3, 3}})
	if e != nil {
		t.Fatal(e)
	}
	if e = s.ApplyPrepared(ctx, prepared); e != nil {
		t.Fatal(e)
	}
	// An ambiguous acknowledgement replay must not publish another increment.
	if e = s.ApplyPrepared(ctx, prepared); e != nil {
		t.Fatal(e)
	}
	next, e := s.SourceChanges(ctx, p.Cursor, 1)
	if e != nil || len(next.Clients) != 1 || next.Clients[0].Requests != 10 {
		t.Fatal(next, e)
	}
	last, e := s.SourceChanges(ctx, next.Cursor, 1)
	if e != nil || len(last.Clients) != 1 || last.Clients[0].IP != ip2.String() {
		t.Fatal(last, e)
	}
	empty, e := s.SourceChanges(ctx, last.Cursor, 1)
	if e != nil || len(empty.Clients) != 0 {
		t.Fatal(empty, e)
	}
	s.Close()
	s = openTest(t, s.path)
	again, e := s.EnableReplication()
	if e != nil || again != node {
		t.Fatal(again, node, e)
	}
	empty, e = s.SourceChanges(ctx, last.Cursor, 512)
	if e != nil || len(empty.Clients) != 0 {
		t.Fatal(empty, e)
	}
}

func TestDisabledNetworkingStillTracksChangesAfterReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stats.db")
	s := openTest(t, path)
	if _, e := s.EnableReplication(); e != nil {
		t.Fatal(e)
	}
	s.Close()
	s = openTest(t, path)
	ip := netip.MustParseAddr("::1")
	if e := s.Flush(map[netip.Addr]Delta{ip: {9, 1, 2}}); e != nil {
		t.Fatal(e)
	}
	page, e := s.SourceChanges(context.Background(), SourceCursor{}, 512)
	if e != nil || len(page.Clients) != 1 || page.Clients[0].Requests != 9 {
		t.Fatal(page, e)
	}
}
