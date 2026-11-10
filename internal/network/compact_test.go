package network

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"netmon/internal/config"
	"netmon/internal/observation"
)

func legacyFixture(t *testing.T, n int) config.Config {
	t.Helper()
	c := configForTest(t)
	c.MaxDatabaseMB = 64
	d, e := openDisk(c, true)
	if e != nil {
		t.Fatal(e)
	}
	nodes := []string{observation.ID(), observation.ID(), observation.ID()}
	base := time.Now().Add(-24*time.Hour).Unix() / 60 * 60
	for start := 0; start < n; start += 64 {
		var items []observation.Sample
		for i := start; i < min(n, start+64); i++ {
			s := codecSample()
			s.ID = observation.ID()
			s.Node = nodes[i%len(nodes)]
			s.IP = fmt.Sprintf("192.0.2.%d", i%256)
			s.Window = base + int64(i/256)*60
			s.First = s.Window + 1
			s.Last = s.Window + 59
			s.Evidence.At = s.Window + 15
			items = append(items, s)
		}
		if e = d.Merge(context.Background(), items, nil); e != nil {
			t.Fatal(e)
		}
		tx, e := d.w.DB.Begin()
		if e != nil {
			t.Fatal(e)
		}
		for _, s := range items {
			raw, _ := json.Marshal(s)
			if _, e = tx.Exec("UPDATE net_observations SET payload=? WHERE id=?", raw, s.ID); e != nil {
				tx.Rollback()
				t.Fatal(e)
			}
		}
		if e = tx.Commit(); e != nil {
			t.Fatal(e)
		}
	}
	if e = d.SavePeer(context.Background(), Peer{URL: "https://192.0.2.254:9845", Node: nodes[0], Epoch: observation.ID(), Name: "existing-peer", Cursor: 42, Success: base, Error: "historical error"}); e != nil {
		t.Fatal(e)
	}
	if _, e = d.w.DB.Exec("UPDATE net_storage SET floor=?,evicted=23", base-60); e != nil {
		t.Fatal(e)
	}
	// Compare packed legacy and compact files, so the measured reduction does
	// not depend on accidental free pages in the legacy fixture.
	if _, e = d.w.DB.Exec("VACUUM"); e != nil {
		t.Fatal(e)
	}
	d.Close()
	return c
}
func fileDigest(t *testing.T, path string) [32]byte {
	t.Helper()
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	return sha256.Sum256(raw)
}
func TestCompactCopyPreservesHistoryIdentityCursorsAndOriginalFile(t *testing.T) {
	ctx := context.Background()
	c := legacyFixture(t, 5000)
	if e := os.Chmod(DataPath(c.Database), 0640); e != nil {
		t.Fatal(e)
	}
	originalHash := fileDigest(t, DataPath(c.Database))
	before, e := openDisk(c, false)
	if e != nil {
		t.Fatal(e)
	}
	expected, count, e := compactDigest(ctx, before.r.DB)
	if e != nil {
		t.Fatal(e)
	}
	node, epoch := before.node, before.epoch
	rows, totals, e := before.View(ctx, "score", 1000)
	if e != nil {
		t.Fatal(e)
	}
	peers, e := before.Peers(ctx)
	if e != nil {
		t.Fatal(e)
	}
	before.Close()
	target := filepath.Join(filepath.Dir(c.Database), "packed.network.db")
	result, e := Compact(ctx, c, target)
	if e != nil {
		t.Fatal(e)
	}
	if result.Observations != count || result.Converted != count || count != 5000 || result.ResultBytes >= result.SourceBytes {
		t.Fatal(result, count)
	}
	if fileDigest(t, DataPath(c.Database)) != originalHash {
		t.Fatal("source database was modified")
	}
	copyConfig := c
	copyConfig.Database = target
	copy, e := openDisk(copyConfig, true)
	if e != nil {
		t.Fatal(e)
	}
	defer copy.Close()
	actual, n, e := compactDigest(ctx, copy.r.DB)
	if e != nil || n != count || string(actual) != string(expected) {
		t.Fatal("history or versions changed", n, e)
	}
	gotRows, gotTotals, e := copy.View(ctx, "score", 1000)
	if e != nil || !reflect.DeepEqual(rows, gotRows) || gotTotals != totals || copy.node != node || copy.epoch != epoch {
		t.Fatal("counters/rating/identity changed", e)
	}
	gotPeers, e := copy.Peers(ctx)
	if e != nil || !reflect.DeepEqual(peers, gotPeers) {
		t.Fatal("peer cursors changed", gotPeers, e)
	}
	var packed, evicted int64
	if e = copy.r.DB.QueryRow("SELECT count(*) FROM net_observations WHERE substr(payload,1,3)=?", sampleMagic).Scan(&packed); e != nil || packed != count {
		t.Fatal(packed, e)
	}
	if e = copy.r.DB.QueryRow("SELECT evicted FROM net_storage").Scan(&evicted); e != nil || evicted != 23 {
		t.Fatal(evicted, e)
	}
	st, e := os.Stat(target)
	if e != nil || st.Mode().Perm() != 0640 {
		t.Fatal(st, e)
	}
	assertStoredCounters(t, copy)
	// A pre-compaction observation replay must not change totals or its sequence.
	page, e := copy.Page(ctx, "", 0)
	if e != nil {
		t.Fatal(e)
	}
	oldHead := page.Head
	if e = copy.Merge(ctx, page.Samples, nil); e != nil {
		t.Fatal(e)
	}
	page, e = copy.Page(ctx, "", 0)
	if e != nil || page.Head != oldHead {
		t.Fatal("unchanged replay advanced cursor", page.Head, oldHead, e)
	}
	t.Logf("5000 mixed IPv4/node/minute observations: legacy %.2f MiB -> compact %.2f MiB (%.2fx smaller)", float64(result.SourceBytes)/(1<<20), float64(result.ResultBytes)/(1<<20), float64(result.SourceBytes)/float64(result.ResultBytes))
}
func TestCompactRefusesActiveRuntimeAndExistingOutput(t *testing.T) {
	c := legacyFixture(t, 1)
	target := filepath.Join(filepath.Dir(c.Database), "packed.network.db")
	sourceHash := fileDigest(t, DataPath(c.Database))
	lock, e := os.OpenFile(filepath.Join(c.Network.RuntimeDirectory, "monitor.lock"), os.O_CREATE|os.O_RDWR, 0640)
	if e != nil {
		t.Fatal(e)
	}
	defer lock.Close()
	if e = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		t.Fatal(e)
	}
	if _, e = Compact(context.Background(), c, target); e == nil {
		t.Fatal("active runtime accepted")
	}
	unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	if e = os.WriteFile(target, []byte("keep this file"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = Compact(context.Background(), c, target); e == nil {
		t.Fatal("existing output overwritten")
	}
	data, _ := os.ReadFile(target)
	if string(data) != "keep this file" {
		t.Fatal(string(data))
	}
	if fileDigest(t, DataPath(c.Database)) != sourceHash {
		t.Fatal("source changed")
	}
}
func TestCompactCancellationAndMalformedSourcePublishNoCopy(t *testing.T) {
	c := legacyFixture(t, 1)
	target := filepath.Join(filepath.Dir(c.Database), "packed.network.db")
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := Compact(canceled, c, target); e == nil {
		t.Fatal("cancellation ignored")
	}
	d, e := openDisk(c, true)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = d.w.DB.Exec("UPDATE net_observations SET payload=?", []byte("invalid payload")); e != nil {
		t.Fatal(e)
	}
	d.Close()
	sourceHash := fileDigest(t, DataPath(c.Database))
	if _, e = Compact(context.Background(), c, target); e == nil {
		t.Fatal("corruption ignored")
	}
	if _, e = os.Stat(target); !os.IsNotExist(e) {
		t.Fatal("failed compact published output", e)
	}
	files, e := filepath.Glob(filepath.Join(filepath.Dir(c.Database), ".netmon-export-*"))
	if e != nil || len(files) != 0 {
		t.Fatal(files, e)
	}
	if fileDigest(t, DataPath(c.Database)) != sourceHash {
		t.Fatal("failed compact changed original")
	}
}
