package network

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/mattn/go-sqlite3"
	"reflect"
	"testing"
	"time"

	"netmon/internal/observation"
)

func oldSample(node string, window int64, ip string, packets int64) observation.Sample {
	item := sample(node, packets)
	item.Window = window
	item.First = window
	item.Last = window
	item.IP = ip
	return item
}
func drainPrune(t *testing.T, d *disk) {
	t.Helper()
	for i := 0; i < 1000; i++ {
		n, e := d.Prune(context.Background())
		if e != nil {
			t.Fatal(e)
		}
		if n < 128 {
			return
		}
	}
	t.Fatal("cleanup did not finish")
}
func assertStoredCounters(t *testing.T, d *disk) {
	t.Helper()
	ctx := context.Background()
	rows, e := d.r.DB.Query("SELECT " + sampleColumns + " FROM net_observations")
	if e != nil {
		t.Fatal(e)
	}
	expected := map[string]observation.Counters{}
	total := observation.Counters{}
	for rows.Next() {
		s, err := scanSample(rows)
		if err != nil {
			t.Fatal(err)
		}

		expected[s.IP] = expected[s.IP].Plus(s.Counters)
		total = total.Plus(s.Counters)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		t.Fatal(e)
	}
	for ip, counts := range expected {
		row, e := d.Show(ctx, ip)
		if e != nil || row.Counters != counts {
			t.Fatalf("%s counters: %+v want %+v, %v", ip, row.Counters, counts, e)
		}
	}
	_, totals, e := d.View(ctx, "total", 1000)
	if e != nil || totals.Counters != total || totals.IPs != int64(len(expected)) {
		t.Fatalf("totals: %+v want %+v / %d IPs, %v", totals, total, len(expected), e)
	}
	var ips int
	if e = d.r.DB.QueryRow("SELECT count(*) FROM net_ips").Scan(&ips); e != nil || ips != len(expected) {
		t.Fatal(ips, len(expected), e)
	}
}

func TestUnlimitedAgeKeepsOldObservationsAndQueue(t *testing.T) {
	c := configForTest(t)
	if c.Storage.Retention != 0 {
		t.Fatal("default age expiry is enabled")
	}
	d, e := openDisk(c, true)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	old := oldSample(observation.ID(), time.Now().Add(-365*24*time.Hour).Unix()/60*60, "192.0.2.1", 7)
	if e = d.Merge(context.Background(), []observation.Sample{old}, nil); e != nil {
		t.Fatal(e)
	}
	if n, e := d.Prune(context.Background()); e != nil || n != 0 {
		t.Fatal(n, e)
	}
	page, e := d.Page(context.Background(), "", 0)
	if e != nil || len(page.Samples) != 1 || page.Samples[0].ID != old.ID {
		t.Fatal(page, e)
	}
	q := newQueue(1 << 20)
	if !q.put(old, nil) {
		t.Fatal("queue rejected old observation")
	}
	if got := q.peek(1, 0); len(got) != 1 || q.discarded.Load() != 0 {
		t.Fatal(got)
	}
	assertStoredCounters(t, d)
}

func TestDisableAgeExpiryMigratesLegacyDatabaseWithoutReset(t *testing.T) {
	c := configForTest(t)
	c.Storage.Retention = 24 * time.Hour
	d, e := openDisk(c, true)
	if e != nil {
		t.Fatal(e)
	}
	item := sample(observation.ID(), 9)
	if e = d.Merge(context.Background(), []observation.Sample{item}, nil); e != nil {
		t.Fatal(e)
	}
	node, epoch := d.node, d.epoch
	// Model a database created by the previous release, before storage floors.
	if _, e = d.w.DB.Exec("DROP TABLE net_storage"); e != nil {
		t.Fatal(e)
	}
	d.Close()
	c.Storage.Retention = 0
	if e = Check(c); e != nil {
		t.Fatal("read-only upgrade preflight rejected old database", e)
	}
	r, e := openDisk(c, false)
	if e != nil {
		t.Fatal(e)
	}
	var retention int64
	if e = r.r.DB.QueryRow("SELECT retention FROM net_meta").Scan(&retention); e != nil || retention != 86400 {
		t.Fatal("read-only preflight changed metadata", retention, e)
	}
	r.Close()
	d, e = openDisk(c, true)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	if d.node != node || d.epoch != epoch {
		t.Fatal("migration reset replication identity")
	}
	if e = d.r.DB.QueryRow("SELECT retention FROM net_meta").Scan(&retention); e != nil || retention != 0 {
		t.Fatal(retention, e)
	}
	if row, e := d.Show(context.Background(), item.IP); e != nil || row.Packets != 9 {
		t.Fatal(row, e)
	}
	assertStoredCounters(t, d)
}

func TestCapacityEvictsOldestWindowsWithinHardLimitAndCannotResurrect(t *testing.T) {
	ctx := context.Background()
	c := configForTest(t)
	c.MaxDatabaseMB = 1
	d, e := openDisk(c, true)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { d.Close() }()
	bc := configForTest(t)
	b, e := openDisk(bc, true)
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	node := observation.ID()
	base := time.Now().Add(-365*24*time.Hour).Unix() / 60 * 60
	first := oldSample(node, base, "198.51.100.20", 11)
	for _, store := range []*disk{d, b} {
		if e = store.Merge(ctx, []observation.Sample{first}, nil); e != nil {
			t.Fatal(e)
		}
	}
	for start := 0; start < 4096; start += 64 {
		items := []observation.Sample{}
		for i := start; i < start+64; i++ {
			items = append(items, oldSample(node, base+60+int64(i/32)*60, fmt.Sprintf("192.0.2.%d", i%17+1), int64(i%7+1)))
		}
		if e = d.Merge(ctx, items, nil); e != nil {
			t.Fatalf("batch %d: %v", start, e)
		}
	}
	drainPrune(t, d)
	page, e := d.Page(ctx, "", 0)
	if e != nil || page.Floor <= base {
		t.Fatal("no capacity eviction", page, e)
	}
	var pages, size, minimum int64
	d.r.DB.QueryRow("PRAGMA page_count").Scan(&pages)
	d.r.DB.QueryRow("PRAGMA page_size").Scan(&size)
	if pages*size > c.MaxDatabaseMB<<20 {
		t.Fatal("database exceeded cap", pages*size)
	}
	if e = d.r.DB.QueryRow("SELECT min(window) FROM net_observations").Scan(&minimum); e != nil || minimum < page.Floor {
		t.Fatal("oldest windows remain", minimum, page.Floor, e)
	}
	if _, e = d.Show(ctx, first.IP); e != sql.ErrNoRows {
		t.Fatal("oldest IP survived", e)
	}
	assertStoredCounters(t, d)
	// B already has the removed observation; even a page carrying only the floor
	// must clean it up, propagate the boundary and reject stale replica replay.
	tr := transport{store: b}
	previous := Peer{URL: "https://192.0.2.1:9845"}
	reply := message{Node: d.node, Page: Page{Epoch: page.Epoch, Head: page.Head, Cursor: page.Head, Floor: page.Floor}}
	if _, e = tr.applyPage(ctx, previous, reply); e != nil {
		t.Fatal(e)
	}
	drainPrune(t, b)
	for _, store := range []*disk{d, b} {
		if e = store.Merge(ctx, []observation.Sample{first}, nil); e != nil {
			t.Fatal(e)
		}
		if _, e = store.Show(ctx, first.IP); e != sql.ErrNoRows {
			t.Fatal("deleted observation resurrected", e)
		}
	}
	bp, e := b.Page(ctx, "", 0)
	if e != nil || bp.Floor != page.Floor || len(bp.Samples) != 0 {
		t.Fatal(bp, e)
	}
	floor := page.Floor
	d.Close()
	d, e = openDisk(c, true)
	if e != nil {
		t.Fatal(e)
	}
	page, e = d.Page(ctx, "", 0)
	if e != nil || page.Floor != floor {
		t.Fatal("floor not durable", page, e)
	}
	if e = d.Merge(ctx, []observation.Sample{first}, nil); e != nil {
		t.Fatal(e)
	}
	if _, e = d.Show(ctx, first.IP); e != sql.ErrNoRows {
		t.Fatal("restart resurrected old IP", e)
	}
	assertStoredCounters(t, d)
}

func TestCapacityRecoversLargeBatchAndCursorAfterSQLiteFull(t *testing.T) {
	ctx := context.Background()
	c := configForTest(t)
	d, e := openDisk(c, true)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	node := observation.ID()
	base := time.Now().Add(-24*time.Hour).Unix() / 60 * 60
	for start := 0; start < 512; start += 64 {
		var items []observation.Sample
		for i := start; i < start+64; i++ {
			items = append(items, oldSample(node, base+int64(i/16)*60, fmt.Sprintf("198.51.%d.%d", i/256, i%256), 1))
		}
		if e = d.Merge(ctx, items, nil); e != nil {
			t.Fatal(e)
		}
	}
	var limit int64
	if e = d.w.DB.QueryRow("PRAGMA page_count").Scan(&limit); e != nil {
		t.Fatal(e)
	}
	// Leave a small maintenance reserve: WITHOUT ROWID index rebalance can
	// allocate pages during DELETE. The incoming batch must still hit SQLITE_FULL.
	limit += 8
	if _, e = d.w.DB.Exec(fmt.Sprintf("PRAGMA max_page_count=%d", limit)); e != nil {
		t.Fatal(e)
	}
	var incoming []observation.Sample
	for i := 0; i < 128; i++ {
		item := sample(node, 100)
		item.IP = fmt.Sprintf("203.0.113.%d", i)
		item.Name = "a long sensor name to force this new transaction to need more pages than the small deletion reserve can cover"
		for j := 0; j < 64; j++ {
			item.Ports = append(item.Ports, uint16(j+1))
		}
		incoming = append(incoming, item)
	}
	peer := Peer{URL: "https://192.0.2.1:9845", Node: node, Epoch: observation.ID(), Cursor: 42}
	var changed bool
	e = d.mergeOnce(ctx, incoming, &peer, 0, &changed)
	var full sqlite3.Error
	if !errors.As(e, &full) || full.Code != sqlite3.ErrFull || changed {
		t.Fatalf("fixture did not trigger a rolled-back SQLITE_FULL batch: %v", e)
	}
	if e = d.Merge(ctx, incoming, &peer); e != nil {
		t.Fatal("capacity recovery failed", e)
	}
	saved, e := d.Peers(ctx)
	if e != nil || len(saved) != 1 || saved[0].Cursor != 42 {
		t.Fatal(saved, e)
	}
	for _, item := range incoming {
		if row, e := d.Show(ctx, item.IP); e != nil || row.Packets != 100 {
			t.Fatal(row, e)
		}
	}
	// Retry after a lost ACK cannot add the committed batch a second time.
	if e = d.Merge(ctx, incoming, &peer); e != nil {
		t.Fatal(e)
	}
	drainPrune(t, d)
	assertStoredCounters(t, d)
	var count int64
	d.r.DB.QueryRow("PRAGMA page_count").Scan(&count)
	if count > limit {
		t.Fatal("SQLite hard limit exceeded", count, limit)
	}
}

func TestRejectedReplicaPageDoesNotCommitDeletionFloor(t *testing.T) {
	c := configForTest(t)
	d, e := openDisk(c, true)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	item := sample(observation.ID(), 1)
	bad := item
	bad.IP = "192.0.2.2"
	tr := transport{store: d}
	p := Peer{URL: "https://192.0.2.1:9845", Cursor: 2}
	reply := message{Node: observation.ID(), Page: Page{Epoch: observation.ID(), Cursor: 3, Floor: item.Window, Samples: []observation.Sample{item, bad}}}
	next, e := tr.applyPage(context.Background(), p, reply)
	if e == nil || !reflect.DeepEqual(next, p) {
		t.Fatal(next, e)
	}
	page, e := d.Page(context.Background(), "", 0)
	if e != nil || page.Floor != 0 {
		t.Fatal("failed transaction committed floor", page, e)
	}
}
