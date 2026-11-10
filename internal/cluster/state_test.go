package cluster

import (
	"context"
	"errors"
	"fmt"
	"github.com/mattn/go-sqlite3"
	"net/netip"
	"path/filepath"
	"testing"

	"netmon/internal/store"
)

func testState(t *testing.T) *state {
	t.Helper()
	s, e := openState(filepath.Join(t.TempDir(), "replica.db"), store.RandomID(), 16, 2)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(s.close)
	return s
}
func component(node string, n int64) Component {
	return Component{Origin: node, Name: "node", Client: store.Client{IP: "192.0.2.1", Requests: n, First: 10, Last: 20}}
}
func assertTotal(t *testing.T, s *state, want string) {
	t.Helper()
	rows, total, e := s.view(context.Background())
	if e != nil || total.Requests != want || total.Unique != 1 || len(rows) != 1 {
		t.Fatal(total, rows, e)
	}
}
func TestMergeIsIdempotentCommutativeAndTransitive(t *testing.T) {
	ctx := context.Background()
	a, b, c := testState(t), testState(t), testState(t)
	x, y := store.RandomID(), store.RandomID()
	if e := a.merge(ctx, []Component{component(x, 7), component(y, 3)}, nil, nil); e != nil {
		t.Fatal(e)
	}
	assertTotal(t, a, "10")
	for i := 0; i < 3; i++ {
		if e := a.merge(ctx, []Component{component(y, 1), component(x, 7)}, nil, nil); e != nil {
			t.Fatal(e)
		}
	}
	assertTotal(t, a, "10")
	page, cursor, e := a.changes(ctx, 0)
	if e != nil || cursor == 0 {
		t.Fatal(page, cursor, e)
	}
	if e = b.merge(ctx, page, nil, nil); e != nil {
		t.Fatal(e)
	}
	forwarded, _, e := b.changes(ctx, 0)
	if e != nil {
		t.Fatal(e)
	}
	if e = c.merge(ctx, forwarded, nil, nil); e != nil {
		t.Fatal(e)
	}
	if e = c.merge(ctx, page, nil, nil); e != nil {
		t.Fatal(e)
	}
	assertTotal(t, c, "10")
	if e = a.merge(ctx, []Component{component(y, 8)}, nil, nil); e != nil {
		t.Fatal(e)
	}
	update, _, e := a.changes(ctx, cursor)
	if e != nil || len(update) != 1 {
		t.Fatal(update, e)
	}
	if e = c.merge(ctx, update, nil, nil); e != nil {
		t.Fatal(e)
	}
	assertTotal(t, c, "15")
}
func TestMergeRollbackRetainsCursorAndFourFieldTotals(t *testing.T) {
	s := testState(t)
	ctx := context.Background()
	node := store.RandomID()
	if e := s.merge(ctx, []Component{component(node, 7)}, nil, nil); e != nil {
		t.Fatal(e)
	}
	var pages int
	s.w.DB.QueryRow("PRAGMA page_count").Scan(&pages)
	s.w.DB.Exec(fmt.Sprint("PRAGMA max_page_count=", pages+1))
	var items []Component
	for i := 0; i < 512; i++ {
		c := component(node, 1)
		c.IP = netip.MustParseAddr(fmt.Sprintf("2001:db8::%x", i)).String()
		items = append(items, c)
	}
	cursor := store.SourceCursor{Sequence: 99, Key: "::1"}
	e := s.merge(ctx, items, &cursor, nil)
	var failure sqlite3.Error
	if !errors.As(e, &failure) || failure.Code != sqlite3.ErrFull {
		t.Fatal("expected SQLITE_FULL", e)
	}
	actual, e := s.sourceCursor(ctx)
	if e != nil || actual.Sequence != 0 {
		t.Fatal(actual, e)
	}
	assertTotal(t, s, "7")
	var count int
	s.w.DB.QueryRow("SELECT count(*) FROM pragma_table_info('clients')").Scan(&count)
	if count != 4 {
		t.Fatal(count)
	}
}

func TestCoalescedChangesCrossPageBoundaryAndReplayAfterRestart(t *testing.T) {
	ctx := context.Background()
	s := testState(t)
	target := testState(t)
	origin := store.RandomID()
	for batch := 0; batch < 3; batch++ {
		var items []Component
		for i := 0; i < 300; i++ {
			c := component(origin, 1)
			c.IP = netip.MustParseAddr(fmt.Sprintf("2001:db8::%x", batch*300+i)).String()
			items = append(items, c)
		}
		if e := s.merge(ctx, items, nil, nil); e != nil {
			t.Fatal(e)
		}
	}
	after := int64(0)
	count := 0
	for {
		page, next, e := s.changes(ctx, after)
		if e != nil {
			t.Fatal(e)
		}
		if len(page) == 0 {
			break
		}
		if next <= after {
			t.Fatal("cursor failed to advance")
		}
		if e = target.merge(ctx, page, nil, nil); e != nil {
			t.Fatal(e)
		}
		if e = target.merge(ctx, page, nil, nil); e != nil {
			t.Fatal(e)
		}
		count += len(page)
		after = next
	}
	rows, totals, e := target.view(ctx)
	if e != nil || count != 900 || totals.Requests != "900" || len(rows) != 900 {
		t.Fatal(count, totals, len(rows), e)
	}
}

func TestLocalRewindIsRejectedWithoutAdvancingCursor(t *testing.T) {
	s := testState(t)
	ctx := context.Background()
	if e := s.merge(ctx, []Component{component(s.node, 10)}, nil, nil); e != nil {
		t.Fatal(e)
	}
	cursor := store.SourceCursor{Sequence: 7, Key: "192.0.2.1"}
	if e := s.merge(ctx, []Component{component(s.node, 3)}, &cursor, nil); !errors.Is(e, ErrSourceRewind) {
		t.Fatal("local rollback not detected", e)
	}
	assertTotal(t, s, "10")
	actual, e := s.sourceCursor(ctx)
	if e != nil || actual.Sequence != 0 {
		t.Fatal(actual, e)
	}
}
func TestNewSourceIdentityRetainsHistoryAndResetsImportCursor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replica.db")
	first := store.RandomID()
	s, e := openState(path, first, 16, 2)
	if e != nil {
		t.Fatal(e)
	}
	cursor := store.SourceCursor{Sequence: 77, Key: "old"}
	if e = s.merge(context.Background(), []Component{component(first, 7)}, &cursor, nil); e != nil {
		t.Fatal(e)
	}
	epoch := s.epoch
	s.close()
	second := store.RandomID()
	s, e = openState(path, second, 16, 2)
	if e != nil {
		t.Fatal(e)
	}
	defer s.close()
	current, e := s.sourceCursor(context.Background())
	if e != nil || current.Sequence != 0 || current.Key != "" || s.epoch != epoch {
		t.Fatal(current, e)
	}
	if e = s.merge(context.Background(), []Component{component(second, 2)}, nil, nil); e != nil {
		t.Fatal(e)
	}
	assertTotal(t, s, "9")
}
