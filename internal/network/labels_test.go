package network

import (
	"context"
	"encoding/csv"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"netmon/internal/identity"
	"netmon/internal/observation"
)

func TestLabelsAreIndependentAndNeverEraseRiskOrCounts(t *testing.T) {
	c := configForTest(t)
	c.Interface = "nonexistent"
	c.LabelsFile = filepath.Join(t.TempDir(), "labels.yaml")
	if e := identity.Edit(c.LabelsFile, nil, func(b *identity.Book) error {
		b.Servers = []identity.Entry{{IP: "192.0.2.0/24", Description: "Own server subnet"}}
		b.Whitelist = []identity.Entry{{IP: "192.0.2.1", Description: "Uptime Kuma"}}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	row := observation.IP{IP: "192.0.2.1", Score: 85, Counters: observation.Counters{Packets: 100, Bytes: 2000, SYN: 50}}
	labeler := NewLabeler(c)
	rows := []observation.IP{row}
	if e := labeler.Annotate(rows); e != nil {
		t.Fatal(e)
	}
	got := rows[0]
	if got.ServerName != "Own server subnet" || !got.Whitelisted || got.WhitelistDescription != "Uptime Kuma" || got.Score != 85 || got.Counters != row.Counters || got.Tag() != "SERVER+WL" {
		t.Fatal(got)
	}
	frozen, e := labeler.Snapshot()
	if e != nil {
		t.Fatal(e)
	}
	if e := identity.Edit(c.LabelsFile, nil, func(b *identity.Book) error { b.Whitelist = nil; return nil }); e != nil {
		t.Fatal(e)
	}
	if e := labeler.Annotate(rows); e != nil || rows[0].Whitelisted {
		t.Fatal(rows, e)
	}
	frozen(&row)
	if !row.Whitelisted {
		t.Fatal("bulk annotation snapshot changed mid-export")
	}
}
func TestConfiguredServerNodesAreRecognizedWithoutDNS(t *testing.T) {
	c := configForTest(t)
	c.Interface = "nonexistent"
	c.LabelsFile = ""
	c.Storage.Mode = "forward"
	c.Cluster.Enabled = true
	c.Cluster.Name = "local-node"
	c.Cluster.Advertise = "https://192.0.2.10:9845"
	c.Cluster.Peers = []string{"https://192.0.2.20:9845", "https://hostname.invalid:9845"}
	rows := []observation.IP{{IP: "192.0.2.10"}, {IP: "192.0.2.20"}, {IP: "192.0.2.30"}}
	if e := NewLabeler(c).Annotate(rows); e != nil {
		t.Fatal(e)
	}
	if rows[0].ServerName != "local-node" || rows[1].ServerSource != "cluster-peer" || rows[2].ServerName != "" || rows[1].Whitelisted {
		t.Fatal(rows)
	}
}
func TestStoredViewsListAndCSVIncludeCurrentLabels(t *testing.T) {
	c := configForTest(t)
	c.ProvidersFile, _ = filepath.Abs("../../data/providers/catalog.json.gz")
	c.Interface = "nonexistent"
	c.LabelsFile = filepath.Join(t.TempDir(), "labels.yaml")
	d, e := openDisk(c, true)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	item := sample(observation.ID(), 7)
	item.IP = "104.16.1.2"
	if e = d.Merge(context.Background(), []observation.Sample{item}, nil); e != nil {
		t.Fatal(e)
	}
	if e = identity.Edit(c.LabelsFile, nil, func(b *identity.Book) error {
		b.Whitelist = []identity.Entry{{IP: item.IP, Description: "Known monitor"}}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	row, e := ReadIP(context.Background(), c, item.IP)
	if e != nil || !row.Whitelisted || row.Packets != 7 {
		t.Fatal(row, e)
	}
	if len(row.Providers) == 0 || row.DisplayTag() != "TRUSTED" || !strings.Contains(row.Label(), "Cloudflare (CDN)") || row.ProviderDate != "2026-11-10" {
		t.Fatal(row)
	}
	seen := false
	_, e = List(context.Background(), c, t.TempDir(), "score", func(ip observation.IP) error { seen = ip.WhitelistDescription == "Known monitor"; return nil })
	if e != nil || !seen {
		t.Fatal(seen, e)
	}
	target := filepath.Join(t.TempDir(), "export.csv")
	if e = Export(context.Background(), c, target); e != nil {
		t.Fatal(e)
	}
	f, e := os.Open(target)
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	records, e := csv.NewReader(f).ReadAll()
	if e != nil || len(records) != 2 {
		t.Fatal(records, e)
	}
	if records[0][14] != "whitelisted" || records[1][14] != "true" || records[1][15] != "Known monitor" {
		t.Fatal(records)
	}
	if len(records[0]) != 19 || records[0][16] != "providers" || !strings.Contains(records[1][16], `"id":"cloudflare"`) || records[1][17] != row.ProviderRevision || records[1][18] != row.ProviderDate {
		t.Fatal(records)
	}
	if e = Export(context.Background(), c, c.LabelsFile); e == nil {
		t.Fatal("CSV overwrote labels file")
	}
	if e = Export(context.Background(), c, c.ProvidersFile); e == nil {
		t.Fatal("CSV overwrote provider catalog")
	}
}

func TestProviderAttributionNeverGrantsTrustOrChangesCounters(t *testing.T) {
	c := configForTest(t)
	c.Interface = "nonexistent"
	c.LabelsFile = ""
	c.ProvidersFile, _ = filepath.Abs("../../data/providers/catalog.json.gz")
	row := observation.IP{IP: "104.16.1.2", Score: 85, Counters: observation.Counters{Packets: 120, Bytes: 5000, SYN: 100}}
	rows := []observation.IP{row}
	if e := NewLabeler(c).Annotate(rows); e != nil {
		t.Fatal(e)
	}
	got := rows[0]
	if got.Whitelisted || got.ServerName != "" || got.DisplayTag() != "CDN" || got.Score != row.Score || got.Counters != row.Counters {
		t.Fatal(got)
	}
}
