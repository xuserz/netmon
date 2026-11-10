package providers

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixture() Metadata {
	return Metadata{Format: 1, Repository: "https://example.com/ranges", Revision: strings.Repeat("a", 40), Generated: "2026-11-10", License: "CC0-1.0", Providers: []Provider{
		{ID: "host", Name: "Hosting", Category: "cloud", Generated: "2026-11-10", Prefixes: []string{"104.16.0.0/12", "104.16.0.0/16", "2606:4700::/32"}},
		{ID: "bot", Name: "Searchbot", Category: "bot", Generated: "2026-11-10", Prefixes: []string{"104.16.1.0/24"}},
		{ID: "tor", Name: "Tor exits", Category: "tor", Generated: "2026-11-10", Prefixes: []string{"104.16.1.2/32"}},
	}}
}
func writeCatalog(t testing.TB, path string, m Metadata) {
	t.Helper()
	f, e := os.Create(path)
	if e != nil {
		t.Fatal(e)
	}
	g := gzip.NewWriter(f)
	if e = json.NewEncoder(g).Encode(m); e != nil {
		t.Fatal(e)
	}
	if e = g.Close(); e != nil {
		t.Fatal(e)
	}
	if e = f.Close(); e != nil {
		t.Fatal(e)
	}
}
func TestOverlappingProvidersUseMostSpecificRangePerProvider(t *testing.T) {
	path := filepath.Join(t.TempDir(), "catalog.gz")
	writeCatalog(t, path, fixture())
	c, e := Load(path)
	if e != nil {
		t.Fatal(e)
	}
	got := c.Lookup(netip.MustParseAddr("::ffff:104.16.1.2"))
	if len(got) != 3 || got[0].ID != "tor" || got[1].ID != "bot" || got[2].ID != "host" || got[2].CIDR != "104.16.0.0/16" {
		t.Fatal(got)
	}
	if got := c.Lookup(netip.MustParseAddr("2606:4700::1111")); len(got) != 1 || got[0].ID != "host" {
		t.Fatal(got)
	}
	for _, raw := range []string{"10.0.0.1", "127.0.0.1", "fc00::1", "fe80::1", "224.0.0.1", "192.0.2.1"} {
		if got := c.Lookup(netip.MustParseAddr(raw)); len(got) != 0 {
			t.Fatal(raw, got)
		}
	}
	if c.Entries != 5 || c.Metadata.Providers[0].Prefixes != nil {
		t.Fatal(c)
	}
}

func TestAll128OverlappingProvidersRemainVisible(t *testing.T) {
	m := fixture()
	m.Providers = nil
	for i := 0; i < MaxProviders; i++ {
		m.Providers = append(m.Providers, Provider{ID: fmt.Sprintf("provider%d", i), Name: "Host", Category: "cloud", Generated: m.Generated, Prefixes: []string{"104.16.0.0/16"}})
	}
	path := filepath.Join(t.TempDir(), "catalog.gz")
	writeCatalog(t, path, m)
	c, e := Load(path)
	if e != nil {
		t.Fatal(e)
	}
	got := c.Lookup(netip.MustParseAddr("104.16.1.2"))
	if len(got) != MaxProviders || got[63].ID != "provider63" || got[64].ID != "provider64" || got[127].ID != "provider127" {
		t.Fatal(got)
	}
}
func TestCatalogValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "catalog.gz")
	for _, bad := range []func(*Metadata){
		func(m *Metadata) { m.Format = 2 },
		func(m *Metadata) { m.Providers[0].Name = "bad\x1b[2J" },
		func(m *Metadata) { m.Providers[0].Category = "trusted" },
		func(m *Metadata) { m.Providers[1].ID = m.Providers[0].ID },
		func(m *Metadata) { m.Providers = make([]Provider, 129) },
		func(m *Metadata) { m.Providers[0].Prefixes = []string{"104.16.1.2/24"} },
		func(m *Metadata) { m.Providers[0].Prefixes = []string{"0.0.0.0/0"} },
		func(m *Metadata) { m.Providers[0].Prefixes = []string{"::ffff:104.16.0.0/112"} },
		func(m *Metadata) { m.Providers[0].Prefixes = []string{"104.16.0.0/16", "104.16.0.0/16"} },
	} {
		m := fixture()
		bad(&m)
		writeCatalog(t, path, m)
		if _, e := Load(path); e == nil {
			t.Fatal("accepted invalid catalog", m)
		}
	}
	if e := os.WriteFile(path, []byte("not gzip"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := Load(path); e == nil {
		t.Fatal("accepted corrupt gzip")
	}
	for _, p := range []string{"", path + ".missing"} {
		if c, e := Load(p); e != nil || c.Entries != 0 {
			t.Fatal(c, e)
		}
	}
	f, e := os.Create(path)
	if e != nil {
		t.Fatal(e)
	}
	if e = f.Truncate(maxCompressed + 1); e != nil {
		t.Fatal(e)
	}
	f.Close()
	if _, e := Load(path); e == nil {
		t.Fatal("accepted oversized file")
	}
	gfile, e := os.Create(path)
	if e != nil {
		t.Fatal(e)
	}
	g := gzip.NewWriter(gfile)
	for i := 0; i <= 32; i++ {
		if _, e := g.Write(make([]byte, 1<<20)); e != nil {
			t.Fatal(e)
		}
	}
	g.Close()
	gfile.Close()
	if _, e := Load(path); e == nil {
		t.Fatal("accepted oversized expanded file")
	}
}
func TestLoaderAtomicReplacementAndFrozenSnapshot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "catalog.gz")
	writeCatalog(t, path, fixture())
	l := Loader{Path: path}
	first, e := l.Snapshot()
	if e != nil {
		t.Fatal(e)
	}
	if again, e := l.Snapshot(); e != nil || again != first {
		t.Fatal("not cached", e)
	}
	m := fixture()
	m.Providers[0].Name = "New host"
	replacement := filepath.Join(dir, "replacement")
	writeCatalog(t, replacement, m)
	if e := os.Rename(replacement, path); e != nil {
		t.Fatal(e)
	}
	second, e := l.Snapshot()
	if e != nil {
		t.Fatal(e)
	}
	ip := netip.MustParseAddr("104.16.2.2")
	if second.Lookup(ip)[0].Name != "New host" || first.Lookup(ip)[0].Name != "Hosting" {
		t.Fatal("snapshot mutated")
	}
	if e := os.WriteFile(path, []byte("bad"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := l.Snapshot(); e == nil {
		t.Fatal("corruption hidden")
	}
	if first.Lookup(ip)[0].Name != "Hosting" {
		t.Fatal("old snapshot changed")
	}
}
func TestBundledCatalogProvenanceAndKnownRanges(t *testing.T) {
	path := "../../data/providers/catalog.json.gz"
	c, e := Load(path)
	if e != nil {
		t.Fatal(e)
	}
	if len(c.Metadata.Providers) != 67 || c.Entries != 45643 || c.Metadata.Revision != "98befa4548b486fee5332e92b0a6e1b0ab55f31e" {
		t.Fatal(c.Metadata, c.Entries)
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(raw)
	manifest, e := os.ReadFile("../../data/providers/manifest.json")
	if e != nil {
		t.Fatal(e)
	}
	var m struct {
		CatalogSHA256 string `json:"catalog_sha256"`
		PrefixCount   int    `json:"prefix_count"`
		Revision      string `json:"revision"`
	}
	if e := json.Unmarshal(manifest, &m); e != nil {
		t.Fatal(e)
	}
	if hex.EncodeToString(sum[:]) != m.CatalogSHA256 || m.PrefixCount != c.Entries || m.Revision != c.Metadata.Revision {
		t.Fatal("manifest mismatch")
	}
	for _, ip := range []string{"104.16.1.2", "2606:4700::1111"} {
		found := false
		for _, p := range c.Lookup(netip.MustParseAddr(ip)) {
			if p.ID == "cloudflare" && p.Category == "cdn" {
				found = true
			}
		}
		if !found {
			t.Fatal("missing Cloudflare", ip)
		}
	}
}
func BenchmarkBundledLookup(b *testing.B) {
	c, e := Load("../../data/providers/catalog.json.gz")
	if e != nil {
		b.Fatal(e)
	}
	ip := netip.MustParseAddr("104.16.1.2")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Lookup(ip)
	}
}
