package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// SourceCursor addresses a bounded, coalesced change feed. Every IP in a batch
// shares a sequence; the IP key makes pagination lossless across that batch.
type SourceCursor struct {
	Sequence int64  `json:"sequence"`
	Key      string `json:"key"`
}
type SourcePage struct {
	Cursor  SourceCursor
	Clients []Client
}

func RandomID() string {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b[:])
}

// EnableReplication installs metadata only when the optional cluster is enabled.
// Existing client rows become the initial feed, without changing their schema.
func (s *Store) EnableReplication() (string, error) {
	tx, e := s.DB.Begin()
	if e != nil {
		return "", e
	}
	defer tx.Rollback()
	for _, q := range []string{
		`CREATE TABLE IF NOT EXISTS replica_source(id INTEGER PRIMARY KEY CHECK(id=1),node TEXT NOT NULL,sequence INTEGER NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS replica_changes(ip TEXT PRIMARY KEY,sequence INTEGER NOT NULL) WITHOUT ROWID`,
		`CREATE INDEX IF NOT EXISTS replica_changes_order ON replica_changes(sequence,ip)`,
	} {
		if _, e = tx.Exec(q); e != nil {
			return "", e
		}
	}
	var exists int
	if e = tx.QueryRow("SELECT count(*) FROM replica_source").Scan(&exists); e != nil {
		return "", e
	}
	if exists == 0 {
		if _, e = tx.Exec("INSERT INTO replica_source VALUES(1,?,0)", RandomID()); e != nil {
			return "", e
		}
		if _, e = tx.Exec("INSERT INTO replica_changes SELECT ip,0 FROM clients"); e != nil {
			return "", fmt.Errorf("initialize cluster change feed (allow room within max_database_mb): %w", e)
		}
	}
	var node string
	if e = tx.QueryRow("SELECT node FROM replica_source WHERE id=1").Scan(&node); e != nil {
		return "", e
	}
	if e = tx.Commit(); e != nil {
		return "", e
	}
	s.replicate = true
	return node, nil
}
func (s *Store) SourceChanges(ctx context.Context, after SourceCursor, limit int) (SourcePage, error) {
	page := SourcePage{Cursor: after}
	if limit < 1 || limit > 512 || after.Sequence < 0 {
		return page, fmt.Errorf("invalid source change page")
	}
	rows, e := s.DB.QueryContext(ctx, `SELECT c.ip,c.requests,c.first_seen,c.last_seen,r.sequence
 FROM replica_changes r JOIN clients c ON c.ip=r.ip
 WHERE (r.sequence,r.ip)>(?,?) ORDER BY r.sequence,r.ip LIMIT ?`, after.Sequence, after.Key, limit)
	if e != nil {
		return page, e
	}
	defer rows.Close()
	for rows.Next() {
		var c Client
		var seq int64
		if e = rows.Scan(&c.IP, &c.Requests, &c.First, &c.Last, &seq); e != nil {
			return page, e
		}
		page.Clients = append(page.Clients, c)
		page.Cursor = SourceCursor{seq, c.IP}
	}
	return page, rows.Err()
}
