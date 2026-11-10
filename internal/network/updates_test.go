package network

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netmon/internal/cluster"
	"netmon/internal/observation"
	"netmon/internal/release"
)

func TestCoordinatorLeaseSerializesAndSurvivesRestartByCooldown(t *testing.T) {
	now := time.Now()
	u := &updateControl{started: now}
	a := UpdateLease{Action: "acquire", Token: strings.Repeat("a", 32), Target: "build-2-1-aaaaaaaa"}
	b := a
	b.Token = strings.Repeat("b", 32)
	if u.lease("A", a, now).Granted {
		t.Fatal("startup forgot possible previous grant")
	}
	now = now.Add(UpdateLeaseTTL)
	if !u.lease("A", a, now).Granted || u.lease("B", b, now).Granted {
		t.Fatal("concurrent installation allowed")
	}
	// Retries are idempotent and cannot extend a grant beyond its original TTL.
	if !u.lease("A", a, now.Add(time.Minute)).Granted {
		t.Fatal("retry refused")
	}
	releaseB := b
	releaseB.Action = "release"
	u.lease("B", releaseB, now)
	if u.lease("B", b, now.Add(time.Minute)).Granted {
		t.Fatal("foreign release broke lease")
	}
	releaseA := a
	releaseA.Action = "release"
	u.lease("A", releaseA, now)
	if !u.lease("B", b, now).Granted {
		t.Fatal("released grant still held")
	}
	if !u.lease("A", a, now.Add(UpdateLeaseTTL)).Granted {
		t.Fatal("dead holder blocked forever")
	}
	restarted := &updateControl{started: now.Add(UpdateLeaseTTL)}
	if restarted.lease("B", b, now.Add(UpdateLeaseTTL+time.Second)).Granted {
		t.Fatal("restart allowed overlapping grants")
	}
}
func TestAuthenticatedOfferGossipAndUpdateLeaseOverRealTLS(t *testing.T) {
	c := configForTest(t)
	c.BuildVersion = "build-1-1-aaaaaaaa"
	c.Cluster.Enabled = true
	c.Cluster.KeyFile = filepath.Join(t.TempDir(), "cluster.key")
	if e := os.WriteFile(c.Cluster.KeyFile, []byte(cluster.GenerateKey()), 0600); e != nil {
		t.Fatal(e)
	}
	pub, private, _ := ed25519.GenerateKey(nil)
	c.Updates.PublicKey = filepath.Join(t.TempDir(), "publisher.pub")
	os.WriteFile(c.Updates.PublicKey, []byte(hex.EncodeToString(pub)), 0600)
	node := observation.ID()
	key, _ := cluster.ReadKey(c.Cluster.KeyFile)
	serverTLS, _, e := cluster.TransportTLS(key, node)
	if e != nil {
		t.Fatal(e)
	}
	coordinator := &transport{cfg: c, node: node, name: "coordinator", peers: map[string]Peer{}, presence: newPresence(), updates: newUpdateControl(c), slots: make(chan struct{}, 4)}
	server := httptest.NewUnstartedServer(http.HandlerFunc(coordinator.handle))
	server.TLS = serverTLS
	url := "https://" + server.Listener.Addr().String()
	coordinator.cfg.Cluster.Advertise = url
	coordinator.cfg.Updates.Coordinator = url
	coordinator.updates.started = time.Now().Add(-UpdateLeaseTTL)
	server.StartTLS()
	defer server.Close()
	c.Updates.Coordinator = url
	c.Storage.Mode = "forward"
	clientNode := observation.ID()
	unlock, e := AcquireUpdateLease(context.Background(), c, clientNode, "build-2-1-bbbbbbbb")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = AcquireUpdateLease(context.Background(), c, observation.ID(), "build-2-1-bbbbbbbb"); e == nil {
		t.Fatal("parallel grant accepted")
	}
	unlock()
	selfUnlock, se := AcquireUpdateLease(context.Background(), c, node, "build-2-1-bbbbbbbb")
	if se != nil {
		t.Fatal("coordinator cannot update itself", se)
	}
	selfUnlock()
	next, e := AcquireUpdateLease(context.Background(), c, observation.ID(), "build-2-1-bbbbbbbb")
	if e != nil {
		t.Fatal(e)
	}
	next()
	_, clientTLS, e := cluster.TransportTLS(key, clientNode)
	if e != nil {
		t.Fatal(e)
	}
	clientHTTP := &http.Transport{TLSClientConfig: clientTLS}
	defer clientHTTP.CloseIdleConnections()
	client := &transport{cfg: c, node: clientNode, peers: map[string]Peer{}, presence: newPresence(), updates: newUpdateControl(c), client: &http.Client{Transport: clientHTTP}}
	manifest := release.Manifest{Format: 1, Repository: release.Repository, Version: "build-2-1-bbbbbbbb", Compatibility: release.Compatibility, Automatic: true, Assets: map[string]release.Asset{"netmon_linux_amd64.tar.gz": {SHA256: strings.Repeat("a", 64), Size: 1}, "netmon_linux_arm64.tar.gz": {SHA256: strings.Repeat("b", 64), Size: 1}}}
	raw, _ := json.Marshal(manifest)
	offer, _ := release.Sign(raw, private)
	heartbeat := client.envelope()
	heartbeat.Heartbeat = true
	heartbeat.Update = &offer
	reply, e := client.request(context.Background(), Peer{URL: url}, "/v3/network/ingest", heartbeat)
	if e != nil || reply.Update == nil {
		t.Fatal(reply, e)
	}
	if _, e := release.Verify(*reply.Update, pub); e != nil {
		t.Fatal(e)
	}
	// Invalid publisher signatures are ignored without disrupting valid v3 traffic.
	forged := offer
	forged.Signature = strings.Repeat("0", 128)
	heartbeat.Update = &forged
	if _, e := client.request(context.Background(), Peer{URL: url}, "/v3/network/ingest", heartbeat); e != nil {
		t.Fatal(e)
	}
	if coordinator.updates.version != manifest.Version {
		t.Fatal("valid candidate lost")
	}
	nodes, _ := coordinator.presence.snapshot(nil, time.Now(), time.Minute, true)
	found := false
	for _, n := range nodes {
		if n.Node == clientNode && n.Version == c.BuildVersion {
			found = true
		}
	}
	if !found {
		t.Fatal("build version missing", nodes)
	}
	badKey := c
	badKey.Cluster.KeyFile = filepath.Join(t.TempDir(), "wrong.key")
	os.WriteFile(badKey.Cluster.KeyFile, []byte(cluster.GenerateKey()), 0600)
	if _, e := AcquireUpdateLease(context.Background(), badKey, observation.ID(), manifest.Version); e == nil {
		t.Fatal("wrong cluster gained update permission")
	}
}
func TestMalformedUpdateMetadataCannotDisruptOrAllocateUnboundedPresence(t *testing.T) {
	c := configForTest(t)
	tr := &transport{cfg: c}
	m := tr.envelope()
	for _, mutate := range []func(*message){func(m *message) { m.Build = strings.Repeat("x", 129) }, func(m *message) { m.UpdateStatus.Error = strings.Repeat("x", 257) }, func(m *message) { m.Update = &release.Offer{Manifest: make([]byte, release.MaxManifest+1)} }, func(m *message) { m.UpdateLease = &UpdateLease{Action: "run-command"} }} {
		bad := m
		mutate(&bad)
		if e := tr.validate(bad); e == nil {
			t.Fatal("invalid metadata accepted")
		}
	}
}
