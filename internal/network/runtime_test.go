package network

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"netmon/internal/live"
	"netmon/internal/observation"
)

func TestNetworkSnapshotsOnlyReadRequestedRanking(t *testing.T) {
	ctx := context.Background()
	r, err := newRuntime(configForTest(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.close)

	byPackets := sample(r.disk.node, 100)
	byBytes := sample(r.disk.node, 10)
	byBytes.IP = "192.0.2.2"
	byBytes.Bytes = 15000
	if err := r.disk.Merge(ctx, []observation.Sample{byPackets, byBytes}, nil); err != nil {
		t.Fatal(err)
	}
	// The bytes leader cannot be decoded. Health, totals, and the one-row
	// packet ranking should still be available.
	if _, err := r.disk.w.DB.Exec("UPDATE net_ips SET evidence='invalid' WHERE ip=?", byBytes.IP); err != nil {
		t.Fatal(err)
	}
	r.sampleHealth(ctx)
	health := r.Snapshot(ctx, live.Request{Op: "health"})
	if health.Error != "" || health.Health.Updated.IsZero() || len(health.NetworkIPs) != 0 {
		t.Fatalf("health: %+v", health)
	}
	totals := r.Snapshot(ctx, live.Request{Op: "health", Totals: true})
	if totals.Error != "" || totals.NetworkTotals.Packets != 110 || len(totals.NetworkIPs) != 0 {
		t.Fatalf("totals: %+v", totals)
	}
	top := r.Snapshot(ctx, live.Request{Op: "top", Sort: "total", Limit: 1})
	if top.Error != "" || top.NetworkTotals.Packets != 110 || len(top.NetworkIPs) != 1 || top.NetworkIPs[0].IP != byPackets.IP {
		t.Fatalf("packet ranking: %+v", top)
	}
	if top := r.Snapshot(ctx, live.Request{Op: "top", Sort: "bytes", Limit: 1}); top.Error == "" {
		t.Fatal("expected an error when the requested row cannot be decoded")
	}
}

func TestLocalNetworkSnapshotsReadCurrentRAMCounters(t *testing.T) {
	ctx := context.Background()
	r, err := newRuntime(configForTest(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.close)
	now := time.Now()
	a := netip.MustParseAddr("192.0.2.1")
	b := netip.MustParseAddr("192.0.2.2")
	for _, ip := range []netip.Addr{a, b, b} {
		r.collector.add(observation.Packet{Source: ip, Protocol: 17, Length: 100}, now)
	}
	r.collector.flush()
	r.sampleHealth(ctx)
	totals := r.Snapshot(ctx, live.Request{Op: "health", Totals: true, Local: true})
	if totals.Error != "" || !totals.Partial || totals.NetworkTotals.IPs != 2 || totals.NetworkTotals.Packets != 3 || totals.Health.Counted != 3 || len(totals.NetworkIPs) != 0 {
		t.Fatalf("local totals: %+v", totals)
	}
	top := r.Snapshot(ctx, live.Request{Op: "top", Sort: "total", Limit: 1, Local: true})
	if top.Error != "" || !top.Partial || len(top.NetworkIPs) != 1 || top.NetworkIPs[0].IP != b.String() {
		t.Fatalf("local ranking: %+v", top)
	}
	show := r.Snapshot(ctx, live.Request{Op: "show", IP: a.String(), Local: true})
	if show.Error != "" || len(show.NetworkIPs) != 1 || show.NetworkIPs[0].IP != a.String() || show.Profile == nil {
		t.Fatalf("local IP details: %+v", show)
	}
}
