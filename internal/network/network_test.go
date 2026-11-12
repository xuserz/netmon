package network

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"netmon/internal/cluster"
	"netmon/internal/config"
	"netmon/internal/observation"
)

func sample(node string, packets int64) observation.Sample {
	now := time.Now().Unix()
	return observation.Sample{ID: observation.ID(), Node: node, Name: "sensor", IP: "192.0.2.1", Window: now / 60 * 60, Counters: observation.Counters{Packets: packets, Bytes: packets * 100, UDP: packets}, First: now, Last: now, PeakPPS: packets}
}
func configForTest(t *testing.T) config.Config {
	t.Helper()
	c := config.Default()
	c.Mode = "network"
	c.Database = filepath.Join(t.TempDir(), "legacy.db")
	c.Network.RuntimeDirectory = t.TempDir()
	c.Network.Capture = false
	c.MaxDatabaseMB = 16
	return c
}
func TestObservationReplayAndUpdatesAreCountedOnce(t *testing.T) {
	c := configForTest(t)
	d, e := openDisk(c, true)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	ctx := context.Background()
	node := observation.ID()
	first := sample(node, 7)
	if e = d.Merge(ctx, []observation.Sample{first}, nil); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 3; i++ {
		if e = d.Merge(ctx, []observation.Sample{first}, nil); e != nil {
			t.Fatal(e)
		}
	}
	newer := first
	newer.Packets = 10
	newer.UDP = 10
	newer.Bytes = 1000
	if e = d.Merge(ctx, []observation.Sample{newer}, nil); e != nil {
		t.Fatal(e)
	}
	if e = d.Merge(ctx, []observation.Sample{first}, nil); e != nil {
		t.Fatal(e)
	}
	rows, total, e := d.View(ctx, "score", 20)
	if e != nil || total.Packets != 10 || len(rows) != 1 || rows[0].Packets != 10 {
		t.Fatal(rows, total, e)
	}
	page, e := d.Page(ctx, "", 0)
	if e != nil || len(page.Samples) != 1 || page.Samples[0].Packets != 10 {
		t.Fatal(page, e)
	}
}

func TestUnchangedObservationReplayStillPersistsPeerCursor(t *testing.T) {
	ctx := context.Background()
	d, err := openDisk(configForTest(t), true)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	item := sample(observation.ID(), 7)
	if err := d.Merge(ctx, []observation.Sample{item}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := d.w.DB.Exec(`CREATE TRIGGER reject_totals BEFORE UPDATE ON net_totals
		BEGIN SELECT RAISE(ABORT,'unchanged totals update'); END;
		CREATE TRIGGER reject_sequence BEFORE UPDATE ON net_meta
		BEGIN SELECT RAISE(ABORT,'unchanged sequence update'); END`); err != nil {
		t.Fatal(err)
	}
	peer := Peer{URL: "https://192.0.2.1:9845", Cursor: 9}
	if err := d.Merge(ctx, []observation.Sample{item}, &peer); err != nil {
		t.Fatal(err)
	}
	peers, err := d.Peers(ctx)
	if err != nil || len(peers) != 1 || peers[0].Cursor != peer.Cursor {
		t.Fatal(peers, err)
	}
	page, err := d.Page(ctx, "", 0)
	if err != nil || page.Head != 1 || len(page.Samples) != 1 || page.Samples[0].Packets != 7 {
		t.Fatal(page, err)
	}
}
func TestQueueCoalescesAndOldACKDoesNotRemoveNewSnapshot(t *testing.T) {
	q := newQueue(800)
	item := sample(observation.ID(), 1)
	ack := &atomic.Int64{}
	if _, ok := q.put(item, ack); !ok {
		t.Fatal("sample did not fit")
	}
	pending := q.peek(1, time.Hour)
	item.Packets = 2
	item.UDP = 2
	item.Bytes = 200
	if _, ok := q.put(item, ack); !ok {
		t.Fatal("replacement rejected")
	}
	q.confirm(pending)
	count, bytes := q.size()
	if count != 1 || bytes > 800 || ack.Load() != 1 {
		t.Fatal(count, bytes, ack.Load())
	}
	other := item
	other.ID = observation.ID()
	if _, ok := q.put(other, nil); ok {
		t.Fatal("RAM budget exceeded")
	}
	q.confirm(q.peek(1, time.Hour))
	count, bytes = q.size()
	if count != 0 || bytes != 0 || ack.Load() != 2 {
		t.Fatal(count, bytes, ack.Load())
	}
}
func TestEvictedIPGetsNewObservationIdentityWithoutLosingCounts(t *testing.T) {
	c := configForTest(t)
	q := newQueue(1 << 20)
	collector := newCollector(observation.ID(), "sensor", 1, Policy(c), q)
	now := time.Now()
	a := observation.Packet{Source: netip.MustParseAddr("192.0.2.1"), Length: 100, Protocol: 17}
	b := a
	b.Source = netip.MustParseAddr("192.0.2.2")
	collector.add(a, now)
	collector.add(b, now)
	collector.add(a, now)
	collector.flush()
	pending := q.peek(128, time.Hour)
	if len(pending) != 3 {
		t.Fatal(len(pending))
	}
	d, e := openDisk(c, true)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	var samples []observation.Sample
	for _, p := range pending {
		samples = append(samples, *p.sample)
	}
	if e = d.Merge(context.Background(), samples, nil); e != nil {
		t.Fatal(e)
	}
	row, e := d.Show(context.Background(), a.Source.String())
	if e != nil || row.Packets != 2 {
		t.Fatal(row, e)
	}
	if len(collector.index) != 1 || collector.evictions.Load() != 2 {
		t.Fatal("collector exceeded capacity")
	}
}
func TestForwardingDoesNotCreateOrOpenAStatisticsDatabase(t *testing.T) {
	c := configForTest(t)
	dir := filepath.Join(t.TempDir(), "must-not-exist")
	c.Database = filepath.Join(dir, "stats.db")
	c.Storage.Mode = "forward"
	c.Cluster.Enabled = true
	c.Cluster.Advertise = ""
	c.Cluster.Peers = []string{"https://127.0.0.1:9845"}
	c.Cluster.KeyFile = filepath.Join(t.TempDir(), "key")
	os.WriteFile(c.Cluster.KeyFile, []byte(cluster.GenerateKey()), 0600)
	r, e := newRuntime(c)
	if e != nil {
		t.Fatal(e)
	}
	defer r.close()
	if r.disk != nil {
		t.Fatal("forwarding opened SQLite")
	}
	r.collector.add(observation.Packet{Source: netip.MustParseAddr("192.0.2.1"), Length: 100, Protocol: 17}, time.Now())
	r.collector.flush()
	if _, e = os.Stat(dir); !os.IsNotExist(e) {
		t.Fatal("statistics directory was created", e)
	}
	if count, _ := r.queue.size(); count != 1 {
		t.Fatal(count)
	}
}

func TestCollectorEvidenceProducesReplicatedScore100(t *testing.T) {
	c := configForTest(t)
	q := newQueue(1 << 20)
	collector := newCollector(observation.ID(), "sensor", 64, Policy(c), q)
	now := time.Now()
	p := observation.Packet{Source: netip.MustParseAddr("192.0.2.3"), Length: 60, Protocol: 6}
	for i := 0; i < 16000; i++ {
		p.SYN = i < 1600
		p.Port = uint16(1000 + i%32)
		collector.add(p, now)
	}
	collector.flush()
	pending := q.peek(128, time.Hour)
	if len(pending) != 1 {
		t.Fatal(len(pending))
	}
	d, e := openDisk(c, true)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	if e = d.Merge(context.Background(), []observation.Sample{*pending[0].sample}, nil); e != nil {
		t.Fatal(e)
	}
	row, e := d.Show(context.Background(), p.Source.String())
	if e != nil || row.Score != 100 || len(row.Reasons) != 3 {
		t.Fatal(row, e)
	}
}
func TestExpiredWindowsAreRemovedAndLateReplaysDoNotResurrectThem(t *testing.T) {
	c := configForTest(t)
	c.Storage.Retention = 24 * time.Hour
	d, e := openDisk(c, true)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	ctx := context.Background()
	old := sample(observation.ID(), 7)
	newer := sample(observation.ID(), 3)
	if e = d.Merge(ctx, []observation.Sample{old, newer}, nil); e != nil {
		t.Fatal(e)
	}
	// Age a complete observation consistently, as if a retention interval elapsed.
	cutoff := time.Now().Add(-c.Storage.Retention-time.Hour).Unix() / 60 * 60
	old.Window = cutoff
	old.First = cutoff
	old.Last = cutoff
	raw, _ := json.Marshal(old)
	if _, e = d.w.DB.Exec("UPDATE net_observations SET window=?,payload=? WHERE id=?", cutoff, raw, old.ID); e != nil {
		t.Fatal(e)
	}
	n, e := d.Prune(ctx)
	if e != nil || n != 1 {
		t.Fatal(n, e)
	}
	row, e := d.Show(ctx, old.IP)
	if e != nil || row.Packets != 3 {
		t.Fatal(row, e)
	}
	if e = d.Merge(ctx, []observation.Sample{old}, nil); e != nil {
		t.Fatal(e)
	}
	row, e = d.Show(ctx, old.IP)
	if e != nil || row.Packets != 3 {
		t.Fatal("expired replay resurrected counters", row, e)
	}
	page, e := d.Page(ctx, "", 0)
	if e != nil || page.Cursor != page.Head || len(page.Samples) != 1 {
		t.Fatal(page, e)
	}
}
func TestNetworkReplicaMergesRemainIdempotentAcrossNodes(t *testing.T) {
	ctx := context.Background()
	a, e := openDisk(configForTest(t), true)
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	b, e := openDisk(configForTest(t), true)
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	s := sample(observation.ID(), 11)
	if e = a.Merge(ctx, []observation.Sample{s}, nil); e != nil {
		t.Fatal(e)
	}
	page, e := a.Page(ctx, "", 0)
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 3; i++ {
		if e = b.Merge(ctx, page.Samples, nil); e != nil {
			t.Fatal(e)
		}
	}
	back, e := b.Page(ctx, "", 0)
	if e != nil {
		t.Fatal(e)
	}
	if e = a.Merge(ctx, back.Samples, nil); e != nil {
		t.Fatal(e)
	}
	_, total, e := a.View(ctx, "score", 20)
	if e != nil || total.Packets != 11 {
		t.Fatal(total, e)
	}
}

func TestMergeIsCommutativeForTiedEvidenceAndPortOrder(t *testing.T) {
	c := configForTest(t)
	a := sample(observation.ID(), 1000)
	a.TCP = 1000
	a.UDP = 0
	a.SYN = 100
	a.Ports = []uint16{80, 22}
	a.Evidence = observation.Evidence{At: a.Last, PPS: 1000, SYN: 100, Ports: 8}
	b := a
	b.Ports = []uint16{443, 22}
	b.Evidence.PPS = 1001 // same score, deterministic evidence tie-break required
	b.Packets = 1001
	b.TCP = 1001
	b.Bytes = 100100
	x, e := mergeSample(a, b, Policy(c))
	if e != nil {
		t.Fatal(e)
	}
	y, e := mergeSample(b, a, Policy(c))
	if e != nil {
		t.Fatal(e)
	}
	xb, _ := json.Marshal(x)
	yb, _ := json.Marshal(y)
	if string(xb) != string(yb) {
		t.Fatalf("noncommutative merge:\n%s\n%s", xb, yb)
	}
}

func TestInvalidBatchRollsBackCountersAndPeerCursor(t *testing.T) {
	c := configForTest(t)
	d, e := openDisk(c, true)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	a := sample(observation.ID(), 1)
	b := a
	b.IP = "192.0.2.2" // both valid individually, but reusing an ID is invalid
	p := Peer{URL: "https://127.0.0.1:9845", Cursor: 10, Epoch: observation.ID()}
	if e = d.Merge(context.Background(), []observation.Sample{a, b}, &p); e == nil {
		t.Fatal("identity reuse accepted")
	}
	_, total, e := d.View(context.Background(), "score", 20)
	if e != nil || total.Packets != 0 {
		t.Fatal(total, e)
	}
	peers, e := d.Peers(context.Background())
	if e != nil || len(peers) != 0 {
		t.Fatal(peers, e)
	}
}

func TestNetworkPolicyMismatchIsExplicit(t *testing.T) {
	c := configForTest(t)
	d, e := openDisk(c, true)
	if e != nil {
		t.Fatal(e)
	}
	d.Close()
	c.Network.Rating.PacketsPerSecond++
	if changed, e := openDisk(c, true); e == nil {
		changed.Close()
		t.Fatal("stored policy silently changed")
	}
	c.Network.Rating.PacketsPerSecond--
	tr := &transport{cfg: c}
	m := message{Version: wireVersion, Mode: "network", PolicyVersion: observation.PolicyVersion, Policy: Policy(c), Retention: int64(c.Storage.Retention / time.Second), Node: observation.ID(), Role: "full"}
	if e := tr.validate(m); e != nil {
		t.Fatal(e)
	}
	m.Policy.SYN++
	if e := tr.validate(m); e == nil {
		t.Fatal("incompatible remote rating policy accepted")
	}
}

func TestRejectedPageDoesNotAdvanceTransportCursor(t *testing.T) {
	c := configForTest(t)
	d, e := openDisk(c, true)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	tr := &transport{store: d, cfg: c}
	previous := Peer{URL: "https://127.0.0.1:9845", Cursor: 10, Epoch: observation.ID(), Success: 1}
	item := sample(observation.ID(), 1)
	bad := item
	bad.IP = "192.0.2.2"
	reply := message{Node: observation.ID(), Page: Page{Epoch: previous.Epoch, Cursor: 20, Samples: []observation.Sample{item, bad}}}
	next, e := tr.applyPage(context.Background(), previous, reply)
	if e == nil || next != previous {
		t.Fatal("rejected batch advanced transport cursor", next, e)
	}
	if e = d.SavePeer(context.Background(), next); e != nil {
		t.Fatal(e)
	}
	peers, e := d.Peers(context.Background())
	if e != nil || len(peers) != 1 || peers[0].Cursor != 10 {
		t.Fatal(peers, e)
	}
	reply.Samples = []observation.Sample{item}
	next, e = tr.applyPage(context.Background(), previous, reply)
	if e != nil || next.Cursor != 20 {
		t.Fatal(next, e)
	}
}

func TestCounterOverflowRejectsWholeTransaction(t *testing.T) {
	c := configForTest(t)
	d, e := openDisk(c, true)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	a := sample(observation.ID(), 1)
	a.Packets = 1 << 62
	a.Bytes = a.Packets
	a.UDP = a.Packets
	b := a
	b.ID = observation.ID()
	if e = d.Merge(context.Background(), []observation.Sample{a, b}, nil); e == nil {
		t.Fatal("overflowing batch accepted")
	}
	_, total, e := d.View(context.Background(), "score", 20)
	if e != nil || total.Packets != 0 {
		t.Fatal(total, e)
	}
}
