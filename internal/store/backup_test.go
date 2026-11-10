package store

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mattn/go-sqlite3"
)

func TestSQLiteIncludesWALResetFix(t *testing.T) {
	version, number, _ := sqlite3.Version()
	if number < 3051003 {
		t.Fatal("SQLite must include the WAL-reset fix", version, number)
	}
	t.Log("SQLite", version)
}
func TestExportSnapshotReleasesSourceAndPreservesFourFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "source.db")
	s, e := Open(path, true, 16, 1)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	batch := map[netip.Addr]Delta{}
	for i := 0; i < 20000; i++ {
		batch[netip.MustParseAddr(fmt.Sprintf("2001:db8::%x", i))] = Delta{1, 10, 20}
	}
	if e = s.Flush(batch); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	copy, cleanup, e := s.Snapshot(ctx, dir)
	if e != nil {
		t.Fatal(e)
	}
	snapshotDir := filepath.Dir(copy.path)
	defer cleanup()
	defer copy.Close()
	// Simulate a slow CSV reader that leaves the snapshot transaction open.
	tx, e := copy.DB.Begin()
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	var before int
	if e = tx.QueryRow("SELECT sum(requests) FROM clients").Scan(&before); e != nil {
		t.Fatal(e)
	}
	ip := netip.MustParseAddr("2001:db8::1")
	for i := 0; i < 20; i++ {
		if e = s.Flush(map[netip.Addr]Delta{ip: {1, 30, 30}}); e != nil {
			t.Fatal(e)
		}
		var busy, log, done int
		if e = s.DB.QueryRow("PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &log, &done); e != nil || busy != 0 {
			t.Fatal("copy reader pinned source WAL", busy, e)
		}
	}
	var after int
	tx.QueryRow("SELECT sum(requests) FROM clients").Scan(&after)
	if before != 20000 || after != before {
		t.Fatal(before, after)
	}
	var fields int
	tx.QueryRow("SELECT count(*) FROM pragma_table_info('clients')").Scan(&fields)
	if fields != 4 {
		t.Fatal(fields)
	}
	tx.Rollback()
	copy.Close()
	cleanup()
	if _, e = os.Stat(snapshotDir); !os.IsNotExist(e) {
		t.Fatal("private copy retained", e)
	}
}
func TestSnapshotCancellationCleansTemporaryDirectory(t *testing.T) {
	dir := t.TempDir()
	s := openTest(t, filepath.Join(dir, "source.db"))
	exportDir := filepath.Join(dir, "exports ? #")
	os.Mkdir(exportDir, 0700)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, e := s.Snapshot(ctx, exportDir); e == nil {
		t.Fatal("cancellation ignored")
	}
	entries, _ := os.ReadDir(exportDir)
	if len(entries) != 0 {
		t.Fatal("temporary files leaked", entries)
	}
	copy, cleanup, e := s.Snapshot(context.Background(), exportDir)
	if e != nil {
		t.Fatal(e)
	}
	copy.Close()
	cleanup()
}
