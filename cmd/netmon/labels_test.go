package main

import (
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"netmon/internal/identity"
)

func TestLabelCommandsDoNotOpenStatisticsAndKeepIndependentLists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	catalog := filepath.Join(dir, "labels.yaml")
	db := filepath.Join(dir, "must-not-exist", "stats.db")
	os.WriteFile(path, []byte(fmt.Sprintf("mode: network\ninterface: lo\nlabels_file: %s\ndatabase: %s\n", catalog, db)), 0600)
	call := func(args ...string) string {
		t.Helper()
		var out, errs bytes.Buffer
		args = append(args, "--config", path)
		if e := run(args, &out, &errs); e != nil {
			t.Fatal(e, errs.String())
		}
		return out.String()
	}
	call("whitelist", "add", "::ffff:192.0.2.10", "Uptime Kuma")
	call("whitelist", "add", "192.0.2.10", "Updated monitor")
	call("servers", "add", "192.0.2.10", "DNS node EU")
	if out := call("whitelist", "list"); !strings.Contains(out, "Updated monitor") || !strings.Contains(out, "Entries: 1") {
		t.Fatal(out)
	}
	if out := call("servers"); !strings.Contains(out, "DNS node EU") {
		t.Fatal(out)
	}
	b, e := identity.Load(catalog)
	if e != nil || len(b.Servers) != 1 || len(b.Whitelist) != 1 {
		t.Fatal(b, e)
	}
	call("whitelist", "remove", "192.0.2.10")
	b, e = identity.Load(catalog)
	if e != nil || len(b.Servers) != 1 || len(b.Whitelist) != 0 {
		t.Fatal(b, e)
	}
	if _, e := os.Stat(filepath.Dir(db)); !os.IsNotExist(e) {
		t.Fatal("label commands opened statistics", e)
	}
}
func TestLabelCommandsRefuseToOverwriteMainConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	text := "mode: network\nlabels_file: " + path + "\n"
	os.WriteFile(path, []byte(text), 0600)
	var out, errs bytes.Buffer
	if e := run([]string{"--config", path, "whitelist", "add", "192.0.2.1", "monitor"}, &out, &errs); e == nil {
		t.Fatal("config overwritten")
	}
	after, _ := os.ReadFile(path)
	if string(after) != text {
		t.Fatal(string(after))
	}
}

func TestWhitelistImportDNSOnForwardNodeWithoutStatistics(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	catalog := filepath.Join(dir, "labels.yaml")
	db := filepath.Join(dir, "must-not-exist", "stats.db")
	if e := os.WriteFile(path, []byte(fmt.Sprintf("mode: network\ninterface: lo\nlabels_file: %s\ndatabase: %s\nstorage:\n  mode: forward\ncluster:\n  enabled: true\n  key_file: /not-created/cluster.key\n  peers: [https://192.0.2.1:9845]\n", catalog, db)), 0600); e != nil {
		t.Fatal(e)
	}
	call := func(args ...string) (string, error) {
		t.Helper()
		var out, errs bytes.Buffer
		e := run(append(args, "--config", path), &out, &errs)
		return out.String(), e
	}
	if out, e := call("whitelist", "import-dns"); e != nil || !strings.Contains(out, "Added: 185;") {
		t.Fatal(out, e)
	}
	if out, e := call("whitelist", "add", "8.8.8.8", "My DNS label"); e != nil {
		t.Fatal(out, e)
	}
	if out, e := call("servers", "add", "192.0.2.1", "My server"); e != nil {
		t.Fatal(out, e)
	}
	if out, e := call("whitelist", "import-dns"); e != nil || !strings.Contains(out, "Added: 0;") {
		t.Fatal(out, e)
	}
	book, e := identity.Load(catalog)
	if e != nil || len(book.Whitelist) != 185 || len(book.Servers) != 1 {
		t.Fatal(book, e)
	}
	if got := identity.Compile(book.Whitelist).Lookup(netip.MustParseAddr("8.8.8.8")); got != "My DNS label" {
		t.Fatal(got)
	}
	before, e := os.ReadFile(catalog)
	if e != nil {
		t.Fatal(e)
	}
	for _, args := range [][]string{{"servers", "import-dns"}, {"whitelist", "import-dns", "extra"}} {
		if _, e := call(args...); e == nil {
			t.Fatalf("accepted %v", args)
		}
	}
	after, e := os.ReadFile(catalog)
	if e != nil || !bytes.Equal(before, after) {
		t.Fatal("rejected command changed catalog", e)
	}
	if _, e := os.Stat(filepath.Dir(db)); !os.IsNotExist(e) {
		t.Fatal("import opened statistics directory", e)
	}
}
