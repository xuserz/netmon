package store

import (
	"context"
	"database/sql"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mattn/go-sqlite3"
)

func TestPreparedReplayAndConfirmedCache(t *testing.T) {
	s := openTest(t, filepath.Join(t.TempDir(), "stats.db"))
	s.ConfigureCache(2)
	ip := netip.MustParseAddr("192.0.2.1")
	ctx := context.Background()
	p, e := s.PrepareBatch(ctx, map[netip.Addr]Delta{ip: {7, 10, 20}})
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 3; i++ {
		if e = s.ApplyPrepared(ctx, p); e != nil {
			t.Fatal(e)
		}
	}
	s.Acknowledge(p)
	if _, e = s.FlushBatch(map[netip.Addr]Delta{ip: {3, 5, 25}}); e != nil {
		t.Fatal(e)
	}
	c, e := Scan(s.DB.QueryRow("SELECT ip,requests,first_seen,last_seen FROM clients"))
	if e != nil || c.Requests != 10 || c.First != 5 || c.Last != 25 {
		t.Fatal(c, e)
	}
	if st := s.CacheStats(); st.Hits != 1 || st.Entries != 1 {
		t.Fatal(st)
	}
	for i := 2; i < 6; i++ {
		if e = s.Flush(map[netip.Addr]Delta{netip.MustParseAddr(fmt.Sprint("192.0.2.", i)): {1, 1, 1}}); e != nil {
			t.Fatal(e)
		}
	}
	if st := s.CacheStats(); st.Entries != 2 {
		t.Fatal(st)
	}
}
func legacyDB(t *testing.T, path string, rows int) *sql.DB {
	t.Helper()
	db, e := sql.Open("sqlite3", path)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = db.Exec(`CREATE TABLE clients (` + columns + `);` + rankIndex); e != nil {
		t.Fatal(e)
	}
	tx, e := db.Begin()
	if e != nil {
		t.Fatal(e)
	}
	stmt, e := tx.Prepare("INSERT INTO clients VALUES(?,?,?,?)")
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < rows; i++ {
		if _, e = stmt.Exec(fmt.Sprintf("2001:db8::%x", i), i+1, 10, 20); e != nil {
			t.Fatal(e)
		}
	}
	stmt.Close()
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
	return db
}
func TestMigrationPreservesRowsAndOnlyFourColumns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stats.db")
	db := legacyDB(t, path, 2000)
	db.Close()
	s, e := Open(path, true, 8, 2)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	var definition string
	var count, total, first, last int
	s.DB.QueryRow("SELECT sql FROM sqlite_master WHERE name='clients'").Scan(&definition)
	if !strings.Contains(definition, "WITHOUT ROWID") {
		t.Fatal(definition)
	}
	if e = s.DB.QueryRow("SELECT count(*),sum(requests),min(first_seen),max(last_seen) FROM clients").Scan(&count, &total, &first, &last); e != nil {
		t.Fatal(e)
	}
	if count != 2000 || total != 2001000 || first != 10 || last != 20 {
		t.Fatal(count, total, first, last)
	}
	s.DB.QueryRow("SELECT count(*) FROM pragma_table_info('clients')").Scan(&count)
	if count != 4 {
		t.Fatal(count)
	}
	s.DB.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table'").Scan(&count)
	if count != 1 {
		t.Fatal(count)
	}
}
func TestMigrationFullRollsBackOriginalSchemaAndRows(t *testing.T) {
	db := legacyDB(t, filepath.Join(t.TempDir(), "stats.db"), 5000)
	defer db.Close()
	var pages int
	db.QueryRow("PRAGMA page_count").Scan(&pages)
	if _, e := db.Exec(fmt.Sprint("PRAGMA max_page_count=", pages+1)); e != nil {
		t.Fatal(e)
	}
	if e := migrate(db); e == nil {
		t.Fatal("expected SQLITE_FULL migration failure")
	}
	var definition string
	db.QueryRow("SELECT sql FROM sqlite_master WHERE name='clients'").Scan(&definition)
	if strings.Contains(definition, "WITHOUT ROWID") {
		t.Fatal("schema changed despite rollback")
	}
	var count, total int
	if e := db.QueryRow("SELECT count(*),sum(requests) FROM clients").Scan(&count, &total); e != nil {
		t.Fatal(e)
	}
	if count != 5000 || total != 12502500 {
		t.Fatal(count, total)
	}
	db.QueryRow("SELECT count(*) FROM sqlite_master WHERE name='clients_migration'").Scan(&count)
	if count != 0 {
		t.Fatal("partial migration table retained")
	}
}
func TestRetryClassification(t *testing.T) {
	for _, code := range []sqlite3.ErrNo{sqlite3.ErrBusy, sqlite3.ErrLocked, sqlite3.ErrIoErr, sqlite3.ErrProtocol} {
		if !Retryable(fmt.Errorf("wrapped: %w", sqlite3.Error{Code: code})) {
			t.Fatal(code)
		}
	}
	for _, code := range []sqlite3.ErrNo{sqlite3.ErrFull, sqlite3.ErrCorrupt, sqlite3.ErrReadonly, sqlite3.ErrConstraint} {
		if Retryable(sqlite3.Error{Code: code}) {
			t.Fatal(code)
		}
	}
}
