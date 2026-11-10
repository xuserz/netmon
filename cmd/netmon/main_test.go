package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"netmon/internal/store"
)

func TestReadCommandsAndExport(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stats.db")
	s, e := store.Open(path, true, 2, 1)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	batch := map[netip.Addr]store.Delta{netip.MustParseAddr("192.0.2.1"): {Requests: 125430, First: 100, Last: 200}, netip.MustParseAddr("2001:db8::1"): {Requests: math.MaxInt64, First: 100, Last: 300}, netip.MustParseAddr("192.0.2.2"): {Requests: math.MaxInt64, First: 100, Last: 300}}
	if e = s.Flush(batch); e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		args []string
		want string
	}{{[]string{"top", "-n", "1"}, "9,223,372,036,854,775,807"}, {[]string{"list"}, "192.0.2.1"}, {[]string{"show", "::ffff:192.0.2.1"}, "125,430"}, {[]string{"stats"}, "18,446,744,073,709,677,044"}} {
		var out, errs bytes.Buffer
		if e = run(append([]string{"--db", path}, tc.args...), &out, &errs); e != nil {
			t.Fatal(e, errs.String())
		}
		if !strings.Contains(out.String(), tc.want) {
			t.Fatalf("%v: %s", tc.args, out.String())
		}
	}
	dest := filepath.Join(dir, "stats.csv")
	var out bytes.Buffer
	if e = run([]string{"export", "--db", path, "--csv", dest}, &out, &out); e != nil {
		t.Fatal(e)
	}
	f, e := os.Open(dest)
	if e != nil {
		t.Fatal(e)
	}
	rows, e := csv.NewReader(f).ReadAll()
	f.Close()
	if e != nil || len(rows) != 4 {
		t.Fatal(rows, e)
	}
	if len(rows[0]) != 4 || rows[1][2] != "1970-01-01T00:01:40Z" {
		t.Fatal(rows)
	}
	for _, target := range []string{path, path + ".sock"} {
		if e = run([]string{"--db", path, "export", "--csv", target}, &out, &out); e == nil {
			t.Fatal("export allowed overwriting service state", target)
		}
	}
	for _, args := range [][]string{{"top", "-n", "0"}, {"top", "--sort", "rate", "--once"}, {"top", "--sort", "invalid"}, {"export", "--csv", dest, "--timeout", "0s"}, {"show", "invalid"}, {"show", "192.0.2.99"}, {"list", "unexpected"}, {"export"}, {"unknown"}, {"top", "--once", "--watch"}, {"top", "--interval", "100ms"}, {"top", "--watch"}} {
		if e = run(append([]string{"--db", path}, args...), &out, &out); e == nil {
			t.Fatal("expected error", args)
		}
	}
}
func TestReadNeverCreatesDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.db")
	var out bytes.Buffer
	if e := run([]string{"stats", "--db", path}, &out, &out); e == nil {
		t.Fatal("expected missing DB error")
	}
	if _, e := os.Stat(path); !os.IsNotExist(e) {
		t.Fatal(e)
	}
}

func TestCanceledExportRetainsExistingCSVAndCleansSnapshot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "stats.db")
	s, e := store.Open(path, true, 8, 2)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	target := filepath.Join(dir, "stats.csv")
	if e = os.WriteFile(target, []byte("original export\n"), 0600); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e = export(ctx, s, path, target, &bytes.Buffer{}); e == nil {
		t.Fatal("cancellation ignored")
	}
	data, e := os.ReadFile(target)
	if e != nil || string(data) != "original export\n" {
		t.Fatal(string(data), e)
	}
	matches, _ := filepath.Glob(filepath.Join(dir, ".netmon-*"))
	if len(matches) != 0 {
		t.Fatal("temporary exports leaked", matches)
	}
}

func TestClusterKeygenNeverOverwritesExistingKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	var out bytes.Buffer
	if e := run([]string{"cluster", "keygen", "--out", path}, &out, &out); e != nil {
		t.Fatal(e)
	}
	before, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if st, e := os.Stat(path); e != nil || st.Mode().Perm() != 0600 {
		t.Fatal(st, e)
	}
	if e = run([]string{"cluster", "keygen", "--out", path}, &out, &out); e == nil {
		t.Fatal("existing key overwritten")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("existing key changed")
	}
}

func TestClusterReadScopesAndExportProtectBothDatabases(t *testing.T) {
	dir := t.TempDir()
	local := filepath.Join(dir, "stats.db")
	replica := local + ".cluster.db"
	for _, item := range []struct {
		path  string
		count int64
	}{{local, 7}, {replica, 13}} {
		s, e := store.Open(item.path, true, 8, 2)
		if e != nil {
			t.Fatal(e)
		}
		if e = s.Flush(map[netip.Addr]store.Delta{netip.MustParseAddr("::1"): {Requests: item.count, First: 1, Last: 2}}); e != nil {
			t.Fatal(e)
		}
		s.Close()
	}
	config := filepath.Join(dir, "config.yaml")
	data := "database: " + local + "\ncluster:\n  enabled: true\n  advertise: https://127.0.0.1:9845\n  key_file: " + filepath.Join(dir, "key") + "\n"
	if e := os.WriteFile(config, []byte(data), 0600); e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		args []string
		want string
	}{{[]string{"stats"}, "Total requests: 13"}, {[]string{"stats", "--local"}, "Total requests: 7"}, {[]string{"stats", "--db", local}, "Total requests: 7"}} {
		var out bytes.Buffer
		args := append([]string{"--config", config}, tc.args...)
		if e := run(args, &out, &out); e != nil || !strings.Contains(out.String(), tc.want) {
			t.Fatal(tc, out.String(), e)
		}
	}
	for _, args := range [][]string{{"export", "--csv", local}, {"export", "--local", "--csv", replica}} {
		var out bytes.Buffer
		if e := run(append([]string{"--config", config}, args...), &out, &out); e == nil {
			t.Fatal("export overwrote another cluster database", args)
		}
	}
	for _, item := range []struct {
		path string
		want string
	}{{local, "7"}, {replica, "13"}} {
		s, e := store.Open(item.path, false, 0, 0)
		if e != nil {
			t.Fatal(e)
		}
		total, e := s.Totals(context.Background())
		s.Close()
		if e != nil || total.Requests != item.want {
			t.Fatal(total, e)
		}
	}
}
