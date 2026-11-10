package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProviderCommandsUseLocalDataWithoutOpeningForwardStatistics(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	catalog, e := filepath.Abs("../../data/providers/catalog.json.gz")
	if e != nil {
		t.Fatal(e)
	}
	db := filepath.Join(dir, "must-not-exist", "stats.db")
	text := fmt.Sprintf("mode: network\ninterface: lo\nproviders_file: %s\ndatabase: %s\nstorage:\n  mode: forward\ncluster:\n  enabled: true\n  key_file: /not-created/cluster.key\n  peers: [https://192.0.2.1:9845]\n", catalog, db)
	if e := os.WriteFile(path, []byte(text), 0600); e != nil {
		t.Fatal(e)
	}
	for _, args := range [][]string{{"providers"}, {"providers", "lookup", "104.16.1.2"}, {"providers", "lookup", "2606:4700::1111"}} {
		var out, errs bytes.Buffer
		if e := run(append(args, "--config", path), &out, &errs); e != nil {
			t.Fatal(e, errs.String())
		}
		if !strings.Contains(out.String(), "Providers: 67; prefixes: 45643") {
			t.Fatal(out.String())
		}
		if len(args) > 1 && (!strings.Contains(out.String(), "Cloudflare") || !strings.Contains(out.String(), "CDN")) {
			t.Fatal(out.String())
		}
	}
	if _, e := os.Stat(filepath.Dir(db)); !os.IsNotExist(e) {
		t.Fatal("opened statistics", e)
	}
	for _, args := range [][]string{{"providers", "lookup", "bad"}, {"providers", "lookup", "fe80::1%lo"}, {"providers", "lookup"}, {"providers", "update"}, {"providers", "--db", db}} {
		var out, errs bytes.Buffer
		if e := run(append(args, "--config", path), &out, &errs); e == nil {
			t.Fatal("accepted", args)
		}
	}
}
