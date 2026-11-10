package cluster

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"netmon/internal/config"
	"netmon/internal/store"
)

func reserve(t *testing.T) string {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Skip("network unavailable", e)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}
func testManager(t *testing.T, key string, peers []string) (*Manager, *store.Store, config.Config) {
	t.Helper()
	c := config.Default()
	c.Database = filepath.Join(t.TempDir(), "stats.db")
	c.MaxDatabaseMB = 16
	address := reserve(t)
	c.Cluster = config.Cluster{Enabled: true, Listen: address, Advertise: "https://" + address, Peers: peers, KeyFile: filepath.Join(t.TempDir(), "cluster.key"), Name: "test node", SyncInterval: time.Second}
	os.WriteFile(c.Cluster.KeyFile, []byte(key), 0600)
	db, e := store.Open(c.Database, true, 16, 2)
	if e != nil {
		t.Fatal(e)
	}
	m, e := New(context.Background(), c, db)
	if e != nil {
		db.Close()
		t.Fatal(e)
	}
	t.Cleanup(func() { m.Close(); db.Close() })
	return m, db, c
}
func waitCluster(t *testing.T, predicate func() bool) {
	t.Helper()
	deadline := time.Now().Add(12 * time.Second)
	for !predicate() {
		if time.Now().After(deadline) {
			t.Fatal("cluster did not converge")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
func TestThreePeersDiscoverConvergeAndResumeWithoutDoubleCounting(t *testing.T) {
	key := GenerateKey()
	a, sa, ca := testManager(t, key, nil)
	b, sb, _ := testManager(t, key, []string{ca.Cluster.Advertise})
	c, sc, cc := testManager(t, key, []string{ca.Cluster.Advertise})
	ip := netip.MustParseAddr("192.0.2.1")
	for i, db := range []*store.Store{sa, sb, sc} {
		if e := db.Flush(map[netip.Addr]store.Delta{ip: {Requests: int64(i + 1), First: 10, Last: 20}}); e != nil {
			t.Fatal(e)
		}
	}
	waitCluster(t, func() bool {
		return a.View().Totals.Requests == "6" && b.View().Totals.Requests == "6" && c.View().Totals.Requests == "6"
	})
	// C is offline; A and B continue and retain cumulative origin components.
	c.Close()
	if e := sa.Flush(map[netip.Addr]store.Delta{ip: {Requests: 4, First: 5, Last: 30}}); e != nil {
		t.Fatal(e)
	}
	waitCluster(t, func() bool { return b.View().Totals.Requests == "10" })
	// Resume C with its original durable identities and receive cursors.
	restarted, e := New(context.Background(), cc, sc)
	if e != nil {
		t.Fatal(e)
	}
	defer restarted.Close()
	waitCluster(t, func() bool { return restarted.View().Totals.Requests == "10" })
	// Another complete exchange of already known components cannot add again.
	time.Sleep(1100 * time.Millisecond)
	if a.View().Totals.Requests != "10" || b.View().Totals.Requests != "10" || restarted.View().Totals.Requests != "10" {
		t.Fatal(a.View(), b.View(), restarted.View())
	}
}
func TestWrongClusterKeyAndMissingClientCertificateAreRejected(t *testing.T) {
	m, _, cfg := testManager(t, GenerateKey(), nil)
	_, wrong, e := transportTLS([]byte("01234567890123456789012345678901"), store.RandomID())
	if e != nil {
		t.Fatal(e)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: wrong}, Timeout: time.Second}
	if response, e := client.Get(cfg.Cluster.Advertise + "/v1/sync"); e == nil {
		response.Body.Close()
		t.Fatal("foreign cluster authenticated")
	}
	correct := m.transport.TLSClientConfig.Clone()
	correct.Certificates = nil
	client = &http.Client{Transport: &http.Transport{TLSClientConfig: correct}, Timeout: time.Second}
	if response, e := client.Get(cfg.Cluster.Advertise + "/v1/sync"); e == nil {
		response.Body.Close()
		t.Fatal("unauthenticated peer accepted")
	}
	if m.server.TLSConfig.MinVersion != tls.VersionTLS13 {
		t.Fatal("TLS minimum changed")
	}
}
