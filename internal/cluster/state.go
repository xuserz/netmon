package cluster

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"sync"
	"time"

	"netmon/internal/store"
)

const pageSize = 512

var ErrSourceRewind = errors.New("local counters moved backwards; restore requires a fresh source identity, not an older database under an active identity")

func Path(local string) string { return local + ".cluster.db" }

type Component struct {
	Origin string `json:"origin"`
	Name   string `json:"name"`
	store.Client
}
type Peer struct {
	Head       int64
	URL        string
	Node, Name string
	Epoch      string
	Cursor     int64
	Success    time.Time
	Error      string
}
type state struct {
	w, r        *store.Store
	mu          sync.Mutex
	totals      store.Totals
	validTotals bool
	epoch       string
	node        string
}

func validID(id string) bool {
	b, e := hex.DecodeString(id)
	return e == nil && len(b) == 16 && id == fmt.Sprintf("%x", b)
}
func openState(path, node string, maxMB, walMB int64) (*state, error) {
	w, e := store.Open(path, true, maxMB, walMB)
	if e != nil {
		return nil, e
	}
	ok := false
	defer func() {
		if !ok {
			w.Close()
		}
	}()
	for _, q := range []string{
		`CREATE TABLE IF NOT EXISTS cluster_meta(id INTEGER PRIMARY KEY CHECK(id=1),epoch TEXT NOT NULL,sequence INTEGER NOT NULL,source_seq INTEGER NOT NULL,source_key TEXT NOT NULL,source_node TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS cluster_components(origin TEXT NOT NULL,ip TEXT NOT NULL,requests INTEGER NOT NULL CHECK(requests>=0),first_seen INTEGER NOT NULL,last_seen INTEGER NOT NULL,version INTEGER NOT NULL,PRIMARY KEY(origin,ip)) WITHOUT ROWID`,
		`CREATE INDEX IF NOT EXISTS cluster_changes ON cluster_components(version)`,
		`CREATE TABLE IF NOT EXISTS cluster_origins(origin TEXT PRIMARY KEY,name TEXT NOT NULL) WITHOUT ROWID`,
		`CREATE TABLE IF NOT EXISTS cluster_peers(url TEXT PRIMARY KEY,node TEXT NOT NULL DEFAULT '',name TEXT NOT NULL DEFAULT '',epoch TEXT NOT NULL DEFAULT '',cursor INTEGER NOT NULL DEFAULT 0,success INTEGER NOT NULL DEFAULT 0,error TEXT NOT NULL DEFAULT '',head INTEGER NOT NULL DEFAULT 0) WITHOUT ROWID`,
	} {
		if _, e = w.DB.Exec(q); e != nil {
			return nil, e
		}
	}
	if _, e = w.DB.Exec("INSERT OR IGNORE INTO cluster_meta VALUES(1,?,0,0,'',?)", store.RandomID(), node); e != nil {
		return nil, e
	}
	if _, e = w.DB.Exec("UPDATE cluster_meta SET source_seq=0,source_key='',source_node=? WHERE source_node!=?", node, node); e != nil {
		return nil, e
	}
	s := &state{w: w, node: node}
	if e = w.DB.QueryRow("SELECT epoch FROM cluster_meta WHERE id=1").Scan(&s.epoch); e != nil {
		return nil, e
	}
	s.totals, e = w.Totals(context.Background())
	if e != nil {
		return nil, e
	}
	s.validTotals = true
	s.r, e = store.Open(path, false, 0, 0)
	if e != nil {
		return nil, e
	}
	ok = true
	return s, nil
}
func (s *state) close() { s.r.Close(); s.w.Close() }
func (s *state) sourceCursor(ctx context.Context) (store.SourceCursor, error) {
	var c store.SourceCursor
	e := s.r.DB.QueryRowContext(ctx, "SELECT source_seq,source_key FROM cluster_meta WHERE id=1").Scan(&c.Sequence, &c.Key)
	return c, e
}
func validateComponent(c Component) error {
	ip, e := netip.ParseAddr(c.IP)
	if !validID(c.Origin) || e != nil || ip.Zone() != "" || ip.Unmap().String() != c.IP || c.Requests < 0 || c.First < 0 || c.Last < c.First || len(c.Name) > 128 {
		return errors.New("invalid cluster counter component")
	}
	return nil
}

// merge joins per-origin counters with max, and timestamps with min/max.
// Updating the materialized total and advancing a durable receive cursor happen
// in the same SQLite transaction, so replay and transitive delivery are safe.
func (s *state) merge(ctx context.Context, items []Component, local *store.SourceCursor, peer *Peer) error {
	if len(items) > pageSize {
		return errors.New("cluster page too large")
	}
	for _, c := range items {
		if e := validateComponent(c); e != nil {
			return e
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validTotals {
		var e error
		s.totals, e = s.w.Totals(ctx)
		if e != nil {
			return e
		}
		s.validTotals = true
	}
	if e := s.w.EnsureWAL(ctx); e != nil {
		return e
	}
	tx, e := s.w.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var seq int64
	if e = tx.QueryRowContext(ctx, "SELECT sequence FROM cluster_meta WHERE id=1").Scan(&seq); e != nil {
		return e
	}
	queries := []string{
		"SELECT ip,requests,first_seen,last_seen FROM cluster_components WHERE origin=? AND ip=?",
		"SELECT ip,requests,first_seen,last_seen FROM clients WHERE ip=?",
		`INSERT INTO cluster_components VALUES(?,?,?,?,?,?) ON CONFLICT(origin,ip) DO UPDATE SET requests=excluded.requests,first_seen=excluded.first_seen,last_seen=excluded.last_seen,version=excluded.version`,
		`INSERT INTO clients VALUES(?,?,?,?) ON CONFLICT(ip) DO UPDATE SET requests=excluded.requests,first_seen=excluded.first_seen,last_seen=excluded.last_seen`,
		`INSERT INTO cluster_origins VALUES(?,?) ON CONFLICT(origin) DO UPDATE SET name=excluded.name`,
	}
	statements := make([]*sql.Stmt, len(queries))
	for i, q := range queries {
		stmt, err := tx.PrepareContext(ctx, q)
		if err != nil {
			return err
		}
		statements[i] = stmt
		defer stmt.Close()
	}
	names := map[string]string{}
	change := store.Change{Added: "0"}
	added := new(big.Int)
	for _, c := range items {
		old, e := store.Scan(statements[0].QueryRowContext(ctx, c.Origin, c.IP))
		exists := e == nil
		if e != nil && !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		next := c.Client
		if local != nil && exists && c.Origin == s.node && c.Requests < old.Requests {
			return ErrSourceRewind
		}
		if exists {
			next.Requests = max(old.Requests, c.Requests)
			next.First = min(old.First, c.First)
			next.Last = max(old.Last, c.Last)
		}
		if exists && next == old {
			continue
		}
		aggregate, e := store.Scan(statements[1].QueryRowContext(ctx, c.IP))
		newIP := errors.Is(e, sql.ErrNoRows)
		if e != nil && !newIP {
			return e
		}
		total := store.Apply(aggregate, c.IP, store.Delta{Requests: next.Requests - old.Requests, First: next.First, Last: next.Last})
		seq++
		if _, e = statements[2].ExecContext(ctx, c.Origin, c.IP, next.Requests, next.First, next.Last, seq); e != nil {
			return e
		}
		if _, e = statements[3].ExecContext(ctx, total.IP, total.Requests, total.First, total.Last); e != nil {
			return e
		}
		names[c.Origin] = c.Name
		if newIP {
			change.NewClients++
		}
		added.Add(added, big.NewInt(total.Requests-aggregate.Requests))
		if change.First == 0 || total.First < change.First {
			change.First = total.First
		}
		change.Last = max(change.Last, total.Last)
	}
	for origin, name := range names {
		if _, e = statements[4].ExecContext(ctx, origin, name); e != nil {
			return e
		}
	}
	if _, e = tx.ExecContext(ctx, "UPDATE cluster_meta SET sequence=? WHERE id=1", seq); e != nil {
		return e
	}
	if local != nil {
		if _, e = tx.ExecContext(ctx, "UPDATE cluster_meta SET source_seq=?,source_key=? WHERE id=1", local.Sequence, local.Key); e != nil {
			return e
		}
	}
	if peer != nil {
		if _, e = tx.ExecContext(ctx, "UPDATE cluster_peers SET node=?,name=?,epoch=?,cursor=?,head=?,success=?,error='' WHERE url=?", peer.Node, peer.Name, peer.Epoch, peer.Cursor, peer.Head, time.Now().Unix(), peer.URL); e != nil {
			return e
		}
	}
	if e = tx.Commit(); e != nil {
		// A failed acknowledgement can be ambiguous. Reload totals before the next
		// snapshot rather than applying this page's cached delta a second time.
		var reloadError error
		s.totals, reloadError = s.w.Totals(ctx)
		s.validTotals = reloadError == nil
		return e
	}
	change.Added = added.String()
	s.totals = s.totals.With(change)
	return nil
}
func (s *state) changes(ctx context.Context, after int64) ([]Component, int64, error) {
	if after < 0 {
		return nil, after, errors.New("negative cluster cursor")
	}
	rows, e := s.r.DB.QueryContext(ctx, `SELECT c.origin,coalesce(o.name,''),c.ip,c.requests,c.first_seen,c.last_seen,c.version FROM cluster_components c LEFT JOIN cluster_origins o ON o.origin=c.origin WHERE c.version>? ORDER BY c.version LIMIT ?`, after, pageSize)
	if e != nil {
		return nil, after, e
	}
	defer rows.Close()
	result := make([]Component, 0, pageSize)
	for rows.Next() {
		var c Component
		var seq int64
		if e = rows.Scan(&c.Origin, &c.Name, &c.IP, &c.Requests, &c.First, &c.Last, &seq); e != nil {
			return nil, after, e
		}
		result = append(result, c)
		after = seq
	}
	return result, after, rows.Err()
}
func (s *state) addPeer(ctx context.Context, url string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.w.EnsureWAL(ctx); e != nil {
		return e
	}
	_, e := s.w.DB.ExecContext(ctx, `INSERT OR IGNORE INTO cluster_peers(url) SELECT ? WHERE (SELECT count(*) FROM cluster_peers)<32`, url)
	return e
}
func (s *state) peers(ctx context.Context) ([]Peer, error) {
	rows, e := s.r.DB.QueryContext(ctx, "SELECT url,node,name,epoch,cursor,success,error,head FROM cluster_peers ORDER BY url")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var result []Peer
	for rows.Next() {
		var p Peer
		var sec int64
		if e = rows.Scan(&p.URL, &p.Node, &p.Name, &p.Epoch, &p.Cursor, &sec, &p.Error, &p.Head); e != nil {
			return nil, e
		}
		if sec > 0 {
			p.Success = time.Unix(sec, 0)
		}
		result = append(result, p)
	}
	return result, rows.Err()
}
func (s *state) peerError(ctx context.Context, url string, e error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.w.EnsureWAL(ctx); err != nil {
		return
	}
	message := e.Error()
	if len(message) > 256 {
		message = message[:256]
	}
	s.w.DB.ExecContext(ctx, "UPDATE cluster_peers SET error=? WHERE url=?", message, url)
}
func (s *state) view(ctx context.Context) ([]store.Client, store.Totals, error) {
	// Only this background publisher waits for a merge. Capture and RPC handlers
	// use a separate database and immutable cached responses.
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.validTotals {
		var e error
		s.totals, e = s.w.Totals(ctx)
		if e != nil {
			return nil, store.Totals{}, e
		}
		s.validTotals = true
	}
	return s.r.View(ctx, 1000, nil, s.totals)
}
