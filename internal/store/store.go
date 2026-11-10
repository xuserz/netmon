package store

import (
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
	cache    *clientCache
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
	q.Set("_busy_timeout", "500")
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
	s := &Store{DB: db, path: path, walLimit: walMB << 20, cache: newCache(8192)}
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
		for _, statement := range []string{"PRAGMA wal_autocheckpoint=256", fmt.Sprintf("PRAGMA journal_size_limit=%d", s.walLimit)} {
			if _, err = db.Exec(statement); err != nil {
				return nil, err
			}
		}
	}
	if write {
		if err = migrate(db); err != nil {
			return nil, err
		}
	}
	ok = true
	return s, nil
}

func (s *Store) Close() error { return s.DB.Close() }

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
