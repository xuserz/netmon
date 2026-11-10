package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"

	_ "github.com/mattn/go-sqlite3"
)

const schema = `CREATE TABLE IF NOT EXISTS clients (
 ip TEXT PRIMARY KEY,
 requests INTEGER NOT NULL DEFAULT 0 CHECK(requests >= 0),
 first_seen INTEGER NOT NULL,
 last_seen INTEGER NOT NULL
);`

type Delta struct {
	Requests    int64
	First, Last int64
}
type Client struct {
	IP       string `json:"ip"`
	Requests int64  `json:"requests"`
	First    int64  `json:"first_seen"`
	Last     int64  `json:"last_seen"`
}
type Store struct {
	DB       *sql.DB
	path     string
	walLimit int64
}

func Open(path string, write bool, maxMB, walMB int64) (*Store, error) {
	mode := "ro"
	if write {
		mode = "rwc"
		if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
			return nil, err
		}
	}
	u := url.URL{Scheme: "file", Path: path}
	q := u.Query()
	q.Set("mode", mode)
	q.Set("_busy_timeout", "5000")
	q.Set("_cache_size", "-1024")
	if write {
		q.Set("_journal_mode", "WAL")
		q.Set("_synchronous", "FULL")
	} else {
		q.Set("_query_only", "true")
	}
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite3", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{DB: db, path: path, walLimit: walMB << 20}
	ok := false
	defer func() {
		if !ok {
			db.Close()
		}
	}()
	if err = db.Ping(); err != nil {
		return nil, err
	}
	if _, err = db.Exec("PRAGMA temp_store=FILE"); err != nil {
		return nil, err
	}
	if write {
		var pageSize, pageCount, actual int64
		if err = db.QueryRow("PRAGMA page_size").Scan(&pageSize); err != nil {
			return nil, err
		}
		if err = db.QueryRow("PRAGMA page_count").Scan(&pageCount); err != nil {
			return nil, err
		}
		maxPages := (maxMB << 20) / pageSize
		if pageCount > maxPages {
			return nil, errors.New("existing database exceeds max_database_mb; increase the limit")
		}
		if err = db.QueryRow(fmt.Sprintf("PRAGMA max_page_count=%d", maxPages)).Scan(&actual); err != nil {
			return nil, err
		}
		if actual != maxPages {
			return nil, errors.New("could not apply SQLite page limit")
		}
		for _, statement := range []string{"PRAGMA wal_autocheckpoint=256", fmt.Sprintf("PRAGMA journal_size_limit=%d", s.walLimit), schema, "CREATE INDEX IF NOT EXISTS clients_rank ON clients(requests DESC, ip ASC)"} {
			if _, err = db.Exec(statement); err != nil {
				return nil, err
			}
		}
	}
	ok = true
	return s, nil
}

func (s *Store) Close() error { return s.DB.Close() }

func (s *Store) Flush(batch map[netip.Addr]Delta) error { _, e := s.FlushBatch(batch); return e }

func (s *Store) FlushBatch(batch map[netip.Addr]Delta) (Change, error) {
	if len(batch) == 0 {
		return Change{}, nil
	}
	if st, e := os.Stat(s.path + "-wal"); e == nil && st.Size() > s.walLimit {
		// A long reader can pin WAL pages. Never keep appending without a bound.
		var busy, log, done int
		if e = s.DB.QueryRow("PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &log, &done); e != nil {
			return Change{}, e
		}
		if busy != 0 {
			return Change{}, errors.New("WAL limit reached and a reader prevents checkpoint; monitoring stopped; close long readers and restart")
		}
	}
	tx, e := s.DB.Begin()
	if e != nil {
		return Change{}, e
	}
	defer tx.Rollback()
	existing, e := lookup(context.Background(), tx, batch)
	if e != nil {
		return Change{}, e
	}
	stmt, e := tx.Prepare(`INSERT INTO clients(ip,requests,first_seen,last_seen) VALUES(?,?,?,?)
 ON CONFLICT(ip) DO UPDATE SET
 requests=CASE WHEN clients.requests > 9223372036854775807-excluded.requests THEN 9223372036854775807 ELSE clients.requests+excluded.requests END,
 first_seen=min(clients.first_seen,excluded.first_seen), last_seen=max(clients.last_seen,excluded.last_seen)`)
	if e != nil {
		return Change{}, e
	}
	defer stmt.Close()
	for ip, d := range batch {
		if d.Requests < 0 {
			return Change{}, errors.New("negative counter delta")
		}
		if _, e = stmt.Exec(ip.String(), d.Requests, d.First, d.Last); e != nil {
			return Change{}, fmt.Errorf("flush failed (disk or configured DB limit?): %w", e)
		}
	}
	if e = tx.Commit(); e != nil {
		return Change{}, e
	}
	return changes(existing, batch), nil
}

func Add(batch map[netip.Addr]Delta, ip netip.Addr, n int64, ts int64) {
	d, exists := batch[ip]
	if n > math.MaxInt64-d.Requests {
		d.Requests = math.MaxInt64
	} else {
		d.Requests += n
	}
	if !exists || ts < d.First {
		d.First = ts
	}
	if ts > d.Last {
		d.Last = ts
	}
	batch[ip] = d
}

func Scan(row interface{ Scan(...any) error }) (Client, error) {
	var c Client
	e := row.Scan(&c.IP, &c.Requests, &c.First, &c.Last)
	return c, e
}
