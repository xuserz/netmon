package identity

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestLongestPrefixAndMappedIPv4(t *testing.T) {
	b := Book{Whitelist: []Entry{{"192.0.2.10", "Exact service"}, {"192.0.2.123/24", "Monitoring subnet"}, {"2001:db8::/32", "IPv6 service"}}}
	if e := Validate(&b); e != nil {
		t.Fatal(e)
	}
	index := Compile(b.Whitelist)
	for ip, want := range map[string]string{"192.0.2.10": "Exact service", "::ffff:192.0.2.10": "Exact service", "192.0.2.20": "Monitoring subnet", "2001:db8::1": "IPv6 service", "198.51.100.1": ""} {
		if got := index.Lookup(netip.MustParseAddr(ip)); got != want {
			t.Fatal(ip, got, want)
		}
	}
	if normalized, e := Normalize("::ffff:192.0.2.123/120"); e != nil || normalized != "192.0.2.0/24" {
		t.Fatal(normalized, e)
	}
}
func TestInvalidCatalogDoesNotBecomeTrusted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "labels.yaml")
	for _, text := range []string{
		"whitelist:\n  - ip: invalid\n    description: test\n",
		"whitelist:\n  - ip: 192.0.2.1\n    description: ''\n",
		"whitelist:\n  - ip: 192.0.2.1\n    description: x\n  - ip: ::ffff:192.0.2.1\n    description: y\n",
		"whitelist:\n  - ip: 192.0.2.1\n    description: \"bad\\nlabel\"\n",
		"unknown: true\n",
		"servers: []\n---\nwhitelist: []\n",
	} {
		os.WriteFile(path, []byte(text), 0600)
		if _, e := Load(path); e == nil {
			t.Fatal("accepted invalid catalog", text)
		}
	}
}
func TestAtomicEditReloadAndPreservedFileMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "labels.yaml")
	os.WriteFile(path, []byte("servers: []\nwhitelist: []\n"), 0640)
	loader := Loader{Path: path}
	_, index, e := loader.Indexes()
	if e != nil || index.Lookup(netip.MustParseAddr("192.0.2.1")) != "" {
		t.Fatal(e)
	}
	if e = Edit(path, nil, func(b *Book) error {
		b.Whitelist = append(b.Whitelist, Entry{"192.0.2.1", "Сервис мониторинга"})
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	_, index, e = loader.Indexes()
	if e != nil || index.Lookup(netip.MustParseAddr("192.0.2.1")) != "Сервис мониторинга" {
		t.Fatal(index, e)
	}
	info, e := os.Stat(path)
	if e != nil || info.Mode().Perm() != 0640 {
		t.Fatal(info, e)
	}
	before, _ := os.ReadFile(path)
	if e = Edit(path, nil, func(b *Book) error { b.Whitelist[0].Description = ""; return nil }); e == nil {
		t.Fatal("invalid replacement accepted")
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("failed edit damaged existing catalog")
	}
	if e = Edit(path, nil, func(b *Book) error { return errors.New("abort") }); e == nil {
		t.Fatal("failed edit accepted")
	}
}
func TestProtectedPathsAndSymlinksAreNotOverwritten(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	os.WriteFile(path, []byte("important configuration"), 0600)
	add := func(b *Book) error { b.Whitelist = append(b.Whitelist, Entry{"192.0.2.1", "test"}); return nil }
	if e := Edit(path, []string{path}, add); e == nil {
		t.Fatal("config overwritten")
	}
	link := filepath.Join(dir, "alias")
	os.Symlink(path, link)
	if e := Edit(link, nil, add); e == nil {
		t.Fatal("symlink overwritten")
	}
	hard := filepath.Join(dir, "hard")
	os.Link(path, hard)
	if e := Edit(hard, []string{path}, add); e == nil {
		t.Fatal("protected hardlink overwritten")
	}
	aliasDir := filepath.Join(dir, "alias-dir")
	os.Symlink(dir, aliasDir)
	if e := Edit(filepath.Join(aliasDir, "new.db"), []string{filepath.Join(dir, "new.db")}, add); e == nil {
		t.Fatal("future protected database overwritten through parent symlink")
	}
	got, _ := os.ReadFile(path)
	if string(got) != "important configuration" {
		t.Fatal(string(got))
	}
}
func TestConcurrentWritersDoNotLoseEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "labels.yaml")
	var wg sync.WaitGroup
	for i := 1; i <= 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			e := Edit(path, nil, func(b *Book) error {
				b.Servers = append(b.Servers, Entry{fmt.Sprintf("192.0.2.%d", i), fmt.Sprintf("node-%d", i)})
				return nil
			})
			if e != nil {
				t.Error(e)
			}
		}(i)
	}
	wg.Wait()
	b, e := Load(path)
	if e != nil || len(b.Servers) != 16 {
		t.Fatal(b, e)
	}
}
