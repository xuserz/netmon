package network

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"netmon/internal/observation"
)

func detailedSample(node string, window int64, start uint16) observation.Sample {
	s := observation.Sample{ID: observation.ID(), Node: node, Name: "sensor", IP: "198.51.100.99", Window: window, First: window + 1, Last: window + 10, Counters: observation.Counters{Packets: 8, Bytes: 512, TCP: 8, SYN: 8}, PeakPPS: 1, Evidence: observation.Evidence{At: window + 10, PPS: 1, SYN: 1, Ports: 4}, Details: &observation.Details{Traffic: observation.Traffic{Inbound: 8}}}
	for p := start; p < start+4; p++ {
		s.Ports = append(s.Ports, p)
		s.Details.Targets = append(s.Details.Targets, observation.Target{Protocol: 6, Port: p, Class: observation.Inbound, Counters: observation.Counters{Packets: 2, Bytes: 128, TCP: 2, SYN: 2}})
	}
	return s
}
func TestFlowDirectionWarmupExpiryBoundsAndServerResponses(t *testing.T) {
	now := time.Unix(1000, 0)
	f := newFlowTracker(8, time.Minute)
	out := observation.Packet{Source: netip.MustParseAddr("192.0.2.1"), Destination: netip.MustParseAddr("198.51.100.2"), SourcePort: 40000, Port: 443, Protocol: 6, SYN: true}
	f.Observe(out, true, now)
	reply := out
	reply.Source, reply.Destination = out.Destination, out.Source
	reply.SourcePort, reply.Port = out.Port, out.SourcePort
	reply.SYN = false
	if c := f.Observe(reply, false, now); c != observation.Reply {
		t.Fatal(c)
	}
	if c := f.Observe(reply, false, now.Add(2*time.Minute)); c != observation.Unknown {
		t.Fatal("expired connection classified", c)
	}
	request := reply
	request.SYN = true
	if c := f.Observe(request, false, now); c != observation.Inbound {
		t.Fatal(c)
	}
	request.SYN = false
	if c := f.Observe(request, false, now); c != observation.Inbound {
		t.Fatal("incoming established flow lost", c)
	}
	udp := out
	udp.Protocol = 17
	udp.SYN = false
	udp.Port = 53
	f.Observe(udp, true, now)
	uReply := udp
	uReply.Source, uReply.Destination = udp.Destination, udp.Source
	uReply.SourcePort, uReply.Port = udp.Port, udp.SourcePort
	if c := f.Observe(uReply, false, now); c != observation.Unknown {
		t.Fatal("UDP startup ambiguity hidden", c)
	}
	udp.SourcePort++
	later := now.Add(3 * time.Minute)
	f.Observe(udp, true, later)
	uReply.Port = udp.SourcePort
	if c := f.Observe(uReply, false, later); c != observation.Reply {
		t.Fatal("outbound-first UDP unmatched", c)
	}
	client := uReply
	client.SourcePort = 53001
	client.Port = 53
	if c := f.Observe(client, false, later); c != observation.Unknown {
		t.Fatal(c)
	}
	server := client
	server.Source, server.Destination = client.Destination, client.Source
	server.SourcePort, server.Port = client.Port, client.SourcePort
	f.Observe(server, true, later)
	if c := f.Observe(client, false, later); c != observation.Unknown {
		t.Fatal("server reply turned client into local traffic", c)
	}
	for i := 0; i < 20; i++ {
		p := request
		p.SourcePort = uint16(1000 + i)
		p.SYN = true
		f.Observe(p, false, later)
	}
	if len(f.index) > 8 || f.evictions == 0 {
		t.Fatal(len(f.index), f.evictions)
	}
	echo := observation.Packet{Source: out.Source, Destination: out.Destination, Protocol: 1, EchoRequest: true, EchoID: 12}
	f.Observe(echo, true, later)
	echo.Source, echo.Destination = echo.Destination, echo.Source
	echo.EchoRequest = false
	echo.EchoReply = true
	if c := f.Observe(echo, false, later); c != observation.Reply {
		t.Fatal("echo reply unmatched", c)
	}
}
func TestDetailedCodecQueueSnapshotAndOverflowKeepExactTotals(t *testing.T) {
	s := detailedSample(observation.ID(), time.Now().Unix()/600*600-1200, 1000)
	if e := s.Validate(time.Now(), 0); e != nil {
		t.Fatal(e)
	}
	raw := encodeSample(s)
	if raw[2] != 2 {
		t.Fatal("missing format version")
	}
	decoded, e := decodeSample(s.ID, s.Node, s.IP, s.Window, raw)
	if e != nil || !reflect.DeepEqual(s, decoded) {
		t.Fatal(decoded, e)
	}
	for n := 0; n < len(raw); n++ {
		if _, e := decodeSample(s.ID, s.Node, s.IP, s.Window, raw[:n]); e == nil {
			t.Fatal("accepted truncation", n)
		}
	}
	q := newQueue(1 << 20)
	if !q.put(s, nil) {
		t.Fatal("queue rejection")
	}
	s.Details.Targets[0].Packets++
	if q.peek(1, 0)[0].sample.Details.Targets[0].Packets != 2 {
		t.Fatal("mutable queue snapshot")
	}
	c := newCollector(observation.ID(), "small-budget", 10, Policy(configForTest(t)), newQueue(1<<20))
	c.detailTargets = 2
	for i := 0; i < 10; i++ {
		c.add(observation.Packet{Source: netip.MustParseAddr("192.0.2.9"), Destination: netip.MustParseAddr("192.0.2.1"), Protocol: 6, Port: uint16(1000 + i), SYN: true, Length: 64, Class: observation.Inbound}, time.Now())
	}
	c.flush()
	item := c.queue.peek(1, 0)[0].sample
	if e := item.Validate(time.Now(), 0); e != nil {
		t.Fatal(e)
	}
	if !item.Details.Partial || len(item.Details.Targets) != 2 || item.Packets != 10 || item.Traffic().Inbound != 10 {
		t.Fatal(item)
	}
	profile := c.profile("192.0.2.9")
	if profile == nil || profile.Unattributed != 8 || profile.Packets != 10 {
		t.Fatal(profile)
	}
}

func TestHorizontalScanAndCorruptIncidentEvidence(t *testing.T) {
	policy := Policy(configForTest(t))
	bucket := time.Now().Unix()/600*600 - 1200
	var facts []observation.Fact
	for i := 0; i < 3; i++ {
		s := detailedSample(observation.ID(), bucket, 22)
		s.Ports = []uint16{22}
		facts = append(facts, observation.SampleFact(s))
	}
	v, eligible, e := observation.BuildIncident("198.51.100.99", "distributed_scan", bucket, facts, policy)
	if e != nil || !eligible || v.Nodes != 3 || len(v.Ports) != 1 {
		t.Fatal(v, eligible, e)
	}
	if _, e := normalizeIncident(v, policy); e != nil {
		t.Fatal(e)
	}
	v.ID = observation.ID()
	if _, e := normalizeIncident(v, policy); e == nil {
		t.Fatal("forged incident ID accepted")
	}
}

func TestConflictingTrafficSnapshotsCannotEvictHistoryAtCapacity(t *testing.T) {
	c := configForTest(t)
	d, e := openDisk(c, true)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	ctx := context.Background()
	window := time.Now().Unix()/600*600 - 1200
	original := detailedSample(observation.ID(), window, 1000)
	if e = d.Merge(ctx, []observation.Sample{original}, nil); e != nil {
		t.Fatal(e)
	}
	var pages int
	if e = d.w.DB.QueryRow("PRAGMA page_count").Scan(&pages); e != nil {
		t.Fatal(e)
	}
	if _, e = d.w.DB.Exec(fmt.Sprintf("PRAGMA max_page_count=%d", pages)); e != nil {
		t.Fatal(e)
	}
	x := detailedSample(observation.ID(), window, 2000)
	y := x
	y.Details = x.Details.Clone()
	y.Details.Traffic = observation.Traffic{Unknown: 8}
	for i := range y.Details.Targets {
		y.Details.Targets[i].Class = observation.Unknown
	}
	if e = d.Merge(ctx, []observation.Sample{x, y}, nil); e == nil || !strings.Contains(e.Error(), "traffic classification") {
		t.Fatal("conflicting snapshot was not rejected before writes", e)
	}
	row, e := d.Show(ctx, original.IP)
	if e != nil || row.Packets != 8 {
		t.Fatal("invalid page evicted prior history", row, e)
	}
}

func TestNewJournalStartsAtExistingFrontierAndKeepsLegacyCounters(t *testing.T) {
	c := configForTest(t)
	d, e := openDisk(c, true)
	if e != nil {
		t.Fatal(e)
	}
	ctx := context.Background()
	s := detailedSample(observation.ID(), time.Now().Unix()/600*600-1200, 1000)
	s.Details = nil
	if e = d.Merge(ctx, []observation.Sample{s}, nil); e != nil {
		t.Fatal(e)
	}
	if _, e = d.w.DB.Exec("DROP TABLE net_analysis"); e != nil {
		t.Fatal(e)
	}
	if _, e = d.w.DB.Exec("DROP TABLE net_incidents"); e != nil {
		t.Fatal(e)
	}
	d.Close()
	d, e = openDisk(c, true)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	if n, e := d.Analyze(ctx, 128); e != nil || n != 0 {
		t.Fatal("legacy backlog delayed live analysis", n, e)
	}
	row, e := d.Show(ctx, s.IP)
	if e != nil || row.Packets != 8 || row.Traffic.Unknown != 8 {
		t.Fatal(row, e)
	}
	next := detailedSample(observation.ID(), s.Window, 1004)
	if e = d.Merge(ctx, []observation.Sample{next}, nil); e != nil {
		t.Fatal(e)
	}
	if _, e = d.Analyze(ctx, 128); e != nil {
		t.Fatal(e)
	}
	events, e := d.Incidents(ctx, "", "", 0, 20)
	if e != nil || len(events) != 1 || !events[0].Partial {
		t.Fatal(events, e)
	}
}
func TestDistributedIncidentReplicationReplayProfileAndCompact(t *testing.T) {
	ctx := context.Background()
	ca, cb := configForTest(t), configForTest(t)
	a, e := openDisk(ca, true)
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	b, e := openDisk(cb, true)
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	window := time.Now().Unix()/600*600 - 1200
	x, y := detailedSample(observation.ID(), window, 1000), detailedSample(observation.ID(), window, 1004)
	if e = a.Merge(ctx, []observation.Sample{x}, nil); e != nil {
		t.Fatal(e)
	}
	if e = b.Merge(ctx, []observation.Sample{y}, nil); e != nil {
		t.Fatal(e)
	}
	if _, e = a.Analyze(ctx, 128); e != nil {
		t.Fatal(e)
	}
	events, e := a.Incidents(ctx, "", "", 0, 20)
	if e != nil || len(events) != 0 {
		t.Fatal("single low-rate node reported distributed scan", events, e)
	}
	page, e := a.Page(ctx, "", 0)
	if e != nil {
		t.Fatal(e)
	}
	if e = b.mergePage(ctx, page.Samples, nil, page.Floor, page.Incidents); e != nil {
		t.Fatal(e)
	}
	if _, e = b.Analyze(ctx, 128); e != nil {
		t.Fatal(e)
	}
	events, e = b.Incidents(ctx, "", "", 0, 20)
	if e != nil || len(events) != 1 {
		t.Fatal(events, e)
	}
	event := events[0]
	if event.Kind != "distributed_scan" || event.Nodes != 2 || event.SYN != 16 || len(event.Ports) != 8 || event.Partial {
		t.Fatal(event)
	}
	page, e = b.Page(ctx, "", 0)
	if e != nil {
		t.Fatal(e)
	}
	if len(page.Incidents) != 1 {
		t.Fatal("journal omitted from replication")
	}
	for i := 0; i < 3; i++ {
		if e = a.mergePage(ctx, page.Samples, nil, page.Floor, page.Incidents); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = a.Analyze(ctx, 128); e != nil {
		t.Fatal(e)
	}
	saved, e := a.Incidents(ctx, x.IP, "", 0, 20)
	if e != nil || !reflect.DeepEqual(events, saved) {
		t.Fatal(saved, e)
	}
	profile, e := a.Profile(ctx, x.IP, window, window+599)
	if e != nil || profile.Packets != 16 || profile.SYN != 16 || profile.Traffic.Inbound != 16 || len(profile.Nodes) != 2 || len(profile.Targets) != 8 || profile.Unattributed != 0 {
		t.Fatal(profile, e)
	}
	row, e := a.Show(ctx, x.IP)
	if e != nil || row.Packets != 16 || row.Traffic.Inbound != 16 || row.IntensityScore != 0 || row.Score < 1 || row.Correlation == nil {
		t.Fatal(row, e)
	}
	// Correlation raises suspicion even though individual-node intensity is low.
	copyPath := filepath.Join(t.TempDir(), "packed.network.db")
	if _, e = Compact(ctx, ca, copyPath); e != nil {
		t.Fatal(e)
	}
	packedConfig := ca
	packedConfig.Database = copyPath
	copied, e := ReadIncidents(ctx, packedConfig, "", "", 0, 20)
	if e != nil || !reflect.DeepEqual(copied, events) {
		t.Fatal(copied, e)
	}
	copiedProfile, e := ReadProfile(ctx, packedConfig, x.IP, window, window+599)
	if e != nil || !reflect.DeepEqual(profile, copiedProfile) {
		t.Fatal(copiedProfile, e)
	}
	before, _ := json.Marshal(saved)
	a.Close()
	a, e = openDisk(ca, true)
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	if _, e = a.Analyze(ctx, 128); e != nil {
		t.Fatal(e)
	}
	afterEvents, e := a.Incidents(ctx, "", "", 0, 20)
	after, _ := json.Marshal(afterEvents)
	if e != nil || !bytes.Equal(before, after) {
		t.Fatal("restart changed incident evidence", e)
	}
	floor := window + 600
	if e = a.mergePage(ctx, nil, nil, floor); e != nil {
		t.Fatal(e)
	}
	if e = a.mergePage(ctx, page.Samples, nil, 0, page.Incidents); e != nil {
		t.Fatal(e)
	}
	gone, e := a.Incidents(ctx, "", "", 0, 20)
	if e != nil || len(gone) != 0 {
		t.Fatal("cleanup resurrected incident", gone, e)
	}
}
