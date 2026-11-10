package store

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
)

// Identical sorted IPv6/text keys and indexes in both fresh layouts. This
// measures this fixture's footprint, not an arbitrary production database.
func TestLayoutFootprint(t *testing.T) {
	const clients = 100000
	pages := make([]int, 2)
	for layout := 0; layout < 2; layout++ {
		db, e := sql.Open("sqlite3", filepath.Join(t.TempDir(), "layout.db"))
		if e != nil {
			t.Fatal(e)
		}
		definition := "CREATE TABLE clients (" + columns + ")"
		if layout == 1 {
			definition += " WITHOUT ROWID"
		}
		if _, e = db.Exec(definition + ";" + rankIndex); e != nil {
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
		for i := 0; i < clients; i++ {
			if _, e = stmt.Exec(fmt.Sprintf("2001:db8:1234:5678::%08x", i), i%1000+1, 1700000000, 1700000100); e != nil {
				t.Fatal(e)
			}
		}
		stmt.Close()
		if e = tx.Commit(); e != nil {
			t.Fatal(e)
		}
		var pageSize int
		db.QueryRow("PRAGMA page_size").Scan(&pageSize)
		db.QueryRow("PRAGMA page_count").Scan(&pages[layout])
		t.Logf("without_rowid=%t clients=%d bytes=%d pages=%d", layout == 1, clients, pages[layout]*pageSize, pages[layout])
		db.Close()
	}
	if pages[1] >= pages[0] {
		t.Fatal("WITHOUT ROWID fixture regressed", pages)
	}
	t.Logf("fixture space reduction %.1f%%", 100*(1-float64(pages[1])/float64(pages[0])))
}
