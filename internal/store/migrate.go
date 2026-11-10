package store

import (
	"database/sql"
	"fmt"
	"strings"
)

const columns = `ip TEXT PRIMARY KEY, requests INTEGER NOT NULL DEFAULT 0 CHECK(requests >= 0), first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL`
const schema = `CREATE TABLE IF NOT EXISTS clients (` + columns + `) WITHOUT ROWID`
const rankIndex = `CREATE INDEX IF NOT EXISTS clients_rank ON clients(requests DESC,ip ASC)`

// SQLite transactional DDL keeps old rows/schema intact if any migration step
// fails (including SQLITE_FULL). Only clients remains after a successful commit.
func migrate(db *sql.DB) error {
	var definition string
	if e := db.QueryRow("SELECT sql FROM sqlite_master WHERE type='table' AND name='clients'").Scan(&definition); e != nil {
		if e == sql.ErrNoRows {
			_, e = db.Exec(schema)
			if e != nil {
				return e
			}
			_, e = db.Exec(rankIndex)
			return e
		}
		return e
	}
	if strings.Contains(strings.ToUpper(definition), "WITHOUT ROWID") {
		_, e := db.Exec(rankIndex)
		return e
	}
	tx, e := db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	for _, statement := range []string{
		`CREATE TABLE clients_migration (` + columns + `) WITHOUT ROWID`,
		`INSERT INTO clients_migration(ip,requests,first_seen,last_seen) SELECT ip,requests,first_seen,last_seen FROM clients ORDER BY ip`,
		`DROP TABLE clients`,
		`ALTER TABLE clients_migration RENAME TO clients`,
		rankIndex,
	} {
		if _, e = tx.Exec(statement); e != nil {
			return fmt.Errorf("WITHOUT ROWID migration rolled back; ensure free disk space and room within max_database_mb: %w", e)
		}
	}
	if e = tx.Commit(); e != nil {
		return fmt.Errorf("migration commit: %w", e)
	}
	return nil
}
