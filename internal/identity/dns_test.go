package identity

import (
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestPublicDNSSnapshotAndFreshInstallAgree(t *testing.T) {
	preset, entries, e := PublicDNS()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = time.Parse("2006-01-02", preset.Verified); e != nil {
		t.Fatal(e)
	}
	if len(preset.Providers) != 14 || len(entries) != 185 {
		t.Fatalf("unexpected snapshot: %d providers / %d IPs", len(preset.Providers), len(entries))
	}
	names := map[string]bool{}
	for _, provider := range preset.Providers {
		if provider.Name == "" || names[provider.Name] || len(provider.Sources) == 0 || len(provider.Profiles) == 0 {
			t.Fatalf("invalid provider: %+v", provider)
		}
		names[provider.Name] = true
		for _, source := range provider.Sources {
			u, e := url.Parse(source)
			if e != nil || u.Scheme != "https" || u.Host == "" {
				t.Fatalf("invalid source: %q", source)
			}
		}
		for _, profile := range provider.Profiles {
			if profile.Name == "" || len(profile.Addresses) == 0 {
				t.Fatalf("invalid profile: %+v", profile)
			}
			for _, raw := range profile.Addresses {
				ip, e := netip.ParseAddr(raw)
				if e != nil || raw != ip.Unmap().String() {
					t.Fatalf("non-canonical endpoint: %q", raw)
				}
			}
		}
	}
	book, e := Load("../../ip-labels.yaml")
	if e != nil {
		t.Fatal(e)
	}
	if len(book.Servers) != 0 || !reflect.DeepEqual(book.Whitelist, entries) {
		t.Fatal("fresh-install catalog differs from embedded preset")
	}
	index := Compile(entries)
	for ip, label := range map[string]string{
		"8.8.8.8":              "Google Public DNS (standard)",
		"2606:4700:4700::1113": "Cloudflare DNS (family)",
		"2606:1a40::32":        "Control D (OISD Full)",
		"2a07:a8c0::":          "NextDNS (anycast bootstrap)",
	} {
		if got := index.Lookup(netip.MustParseAddr(ip)); got != label {
			t.Fatalf("%s: %q, want %q", ip, got, label)
		}
	}
}

func TestPublicDNSImportPreservesUserDescriptionsAndCoverage(t *testing.T) {
	book := Book{
		Servers:   []Entry{{IP: "8.8.8.8", Description: "My explicitly configured server"}},
		Whitelist: []Entry{{IP: "8.8.8.8", Description: "My Google label"}, {IP: "2606:4700:4700::/48", Description: "My Cloudflare IPv6 label"}, {IP: "192.0.2.1", Description: "My probe"}},
	}
	original := append([]Entry(nil), book.Whitelist...)
	servers := append([]Entry(nil), book.Servers...)
	added, e := AddPublicDNS(&book)
	if e != nil {
		t.Fatal(e)
	}
	// One Google endpoint and all six Cloudflare IPv6 endpoints are covered.
	if added != 178 {
		t.Fatalf("added %d", added)
	}
	if !reflect.DeepEqual(book.Servers, servers) || !reflect.DeepEqual(book.Whitelist[:len(original)], original) {
		t.Fatal("user entries overwritten")
	}
	index := Compile(book.Whitelist)
	if got := index.Lookup(netip.MustParseAddr("2606:4700:4700::1111")); got != "My Cloudflare IPv6 label" {
		t.Fatal(got)
	}
	before := append([]Entry(nil), book.Whitelist...)
	added, e = AddPublicDNS(&book)
	if e != nil || added != 0 || !reflect.DeepEqual(book.Whitelist, before) {
		t.Fatalf("import not idempotent: added=%d, err=%v", added, e)
	}
}

func TestPublicDNSImportRejectsFullCatalogWithoutChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "labels.yaml")
	book := Book{}
	for i := 0; i < MaxEntries; i++ {
		book.Whitelist = append(book.Whitelist, Entry{IP: fmt.Sprintf("198.18.%d.%d", i/256, i%256), Description: "Private test label"})
	}
	if e := Edit(path, nil, func(b *Book) error { *b = book; return nil }); e != nil {
		t.Fatal(e)
	}
	before, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	e = Edit(path, nil, func(b *Book) error { _, e := AddPublicDNS(b); return e })
	if e == nil || !strings.Contains(e.Error(), "limited") {
		t.Fatalf("expected limit failure: %v", e)
	}
	after, e := os.ReadFile(path)
	if e != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("failed import changed catalog", e)
	}
	original := append([]Entry(nil), book.Whitelist...)
	if _, e = AddPublicDNS(&book); e == nil || !reflect.DeepEqual(original, book.Whitelist) {
		t.Fatal("failed import mutated caller's book", e)
	}
}
