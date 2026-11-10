package network

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestPresenceCombinesAuthenticatedDirectionsAndExpiresWithoutLosingIdentity(t *testing.T) {
	p := newPresence()
	now := time.Now()
	ttl := 15 * time.Second
	id := strings.Repeat("a", 32)
	url := "https://192.0.2.1:9845"
	m := message{Node: id, Name: "storage-eu", Role: "full", ContactTTLSeconds: 15}
	peers := []Peer{{URL: url}}
	p.recordOutgoing(url, m, now, time.Millisecond, nil, ttl)
	p.recordIncoming(m, "192.0.2.1:43210", now.Add(time.Second), ttl)
	p.syncResult(url, Peer{Cursor: 5, Success: now.Unix()}, 8, nil)
	nodes, drops := p.snapshot(peers, now.Add(2*time.Second), ttl, true)
	if drops != 0 || len(nodes) != 1 || !nodes[0].Online || nodes[0].Direction != "BOTH" || nodes[0].Node != id || nodes[0].RTTMillis != 1 || nodes[0].Head-nodes[0].Cursor != 3 {
		t.Fatal(nodes, drops)
	}
	p.syncResult(url, Peer{}, 0, errors.New("database is full"))
	p.recordOutgoing(url, m, now.Add(3*time.Second), time.Millisecond, nil, ttl)
	nodes, _ = p.snapshot(peers, now.Add(4*time.Second), ttl, true)
	if nodes[0].State != "DEGRADED" || !nodes[0].Online || nodes[0].SyncError != "database is full" {
		t.Fatal(nodes)
	}
	p.syncResult(url, Peer{Cursor: 8, Success: now.Unix()}, 8, nil)
	nodes, _ = p.snapshot(peers, now.Add(4*time.Second), ttl, true)
	if nodes[0].State != "ONLINE" || nodes[0].Head != nodes[0].Cursor {
		t.Fatal(nodes)
	}
	nodes, _ = p.snapshot(peers, now.Add(time.Minute), ttl, true)
	if nodes[0].Online || nodes[0].State != "OFFLINE" || nodes[0].Name != "storage-eu" {
		t.Fatal(nodes)
	}
}
func TestStoredSuccessCannotProveOnlineAfterLocalRestart(t *testing.T) {
	now := time.Now()
	peers := []Peer{{URL: "https://192.0.2.1:9845", Node: strings.Repeat("a", 32), Name: "saved", Success: now.Unix()}}
	p := newPresence()
	nodes, _ := p.snapshot(peers, now, time.Minute, true)
	if len(nodes) != 1 || nodes[0].State != "UNKNOWN" || nodes[0].Online {
		t.Fatal(nodes)
	}
	p.recordOutgoing(peers[0].URL, message{}, now, 0, errors.New("connection refused"), time.Minute)
	nodes, _ = p.snapshot(peers, now, time.Minute, true)
	if nodes[0].State != "OFFLINE" || nodes[0].Online || nodes[0].Name != "saved" || nodes[0].Node != peers[0].Node || nodes[0].Error == "" {
		t.Fatal(nodes)
	}
	nodes, _ = p.snapshot(peers, now, time.Minute, false)
	if nodes[0].State != "STALE" || nodes[0].Online {
		t.Fatal(nodes)
	}
}
func TestIncomingNodeCacheIsBoundedAndDeliveryIsSeparateFromHeartbeat(t *testing.T) {
	p := newPresence()
	now := time.Now()
	for i := 0; i < maxIncomingNodes+5; i++ {
		m := message{Node: fmt.Sprintf("%032x", i+1), Name: "sensor", Role: "forward"}
		p.recordIncoming(m, "[2001:db8::1]:55000", now.Add(time.Duration(i)*time.Millisecond), time.Minute)
	}
	nodes, drops := p.snapshot(nil, now.Add(time.Second), time.Minute, true)
	if len(nodes) != maxIncomingNodes || drops != 5 {
		t.Fatal(len(nodes), drops)
	}
	for _, node := range nodes {
		if node.Address != "2001:db8::1" || !node.LastDelivery.IsZero() || node.Role != "forward" || !node.Online {
			t.Fatal(node)
		}
	}
	id := nodes[0].Node
	p.delivery(id, now, nil)
	nodes, _ = p.snapshot(nil, now.Add(time.Second), time.Minute, true)
	found := false
	for _, n := range nodes {
		if n.Node == id {
			found = !n.LastDelivery.IsZero()
		}
	}
	if !found {
		t.Fatal("durable delivery not recorded")
	}
}
func TestOfflineNodeReadKeepsConfiguredPeersAndNeverReportsOnline(t *testing.T) {
	c := configForTest(t)
	d, e := openDisk(c, true)
	if e != nil {
		t.Fatal(e)
	}
	peer := Peer{URL: "https://192.0.2.1:9845", Node: strings.Repeat("b", 32), Name: "stored", Success: time.Now().Unix()}
	if e = d.SavePeer(context.Background(), peer); e != nil {
		t.Fatal(e)
	}
	d.Close()
	c.Cluster.Peers = []string{peer.URL, "https://192.0.2.2:9845"}
	nodes, e := StoredNodes(context.Background(), c)
	if e != nil || len(nodes) != 2 {
		t.Fatal(nodes, e)
	}
	for _, n := range nodes {
		if n.State != "STALE" || n.Online {
			t.Fatal(n)
		}
	}
}

func TestHeartbeatsDoNotClearDeliveryFailures(t *testing.T) {
	p := newPresence()
	now := time.Now()
	m := message{Node: strings.Repeat("c", 32), Name: "edge", Role: "forward"}
	p.recordIncoming(m, "192.0.2.1:55443", now, time.Minute)
	p.delivery(m.Node, now, errors.New("database is full"))
	p.recordIncoming(m, "192.0.2.1:55443", now.Add(time.Second), time.Minute)
	nodes, _ := p.snapshot(nil, now.Add(2*time.Second), time.Minute, true)
	if len(nodes) != 1 || nodes[0].State != "DEGRADED" || !nodes[0].LastDelivery.IsZero() || nodes[0].SyncError == "" {
		t.Fatal(nodes)
	}
	p.delivery(m.Node, now.Add(3*time.Second), nil)
	nodes, _ = p.snapshot(nil, now.Add(4*time.Second), time.Minute, true)
	if nodes[0].State != "ONLINE" || nodes[0].LastDelivery.IsZero() || nodes[0].SyncError != "" {
		t.Fatal(nodes)
	}
}
