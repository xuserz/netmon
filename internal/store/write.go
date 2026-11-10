package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sort"

	"github.com/mattn/go-sqlite3"
)

// PreparedBatch contains absolute, monotonic targets computed exactly once.
// Applying this same object again never adds its deltas a second time, even if
// an earlier COMMIT reached disk but its acknowledgement was lost.
type PreparedBatch struct {
	targets []Client
	Change  Change
}

var sqlTxReadOnly = sql.TxOptions{ReadOnly: true}
var ErrCheckpointBusy = errors.New("WAL threshold reached; a reader prevents checkpoint")

func Retryable(e error) bool {
	if errors.Is(e, ErrCheckpointBusy) {
		return true
	}
	var se sqlite3.Error
	if !errors.As(e, &se) {
		return false
	}
	switch se.Code {
	case sqlite3.ErrBusy, sqlite3.ErrLocked, sqlite3.ErrIoErr, sqlite3.ErrProtocol:
		return true
	}
	return false
}
func (s *Store) PrepareBatch(ctx context.Context, batch map[netip.Addr]Delta) (*PreparedBatch, error) {
	existing := make(map[string]Client, len(batch))
	missing := make(map[netip.Addr]Delta)
	for ip, d := range batch {
		if d.Requests < 0 {
			return nil, errors.New("negative counter delta")
		}
		if row, ok := s.cache.get(ip); ok {
			existing[ip.String()] = row
		} else {
			missing[ip] = d
		}
	}
	if len(missing) > 0 {
		tx, e := s.DB.BeginTx(ctx, &sqlTxReadOnly)
		if e != nil {
			return nil, e
		}
		found, e := lookup(ctx, tx, missing)
		tx.Rollback()
		if e != nil {
			return nil, e
		}
		for ip, row := range found {
			existing[ip] = row
		}
	}
	p := &PreparedBatch{Change: changes(existing, batch), targets: make([]Client, 0, len(batch))}
	for ip, d := range batch {
		p.targets = append(p.targets, Apply(existing[ip.String()], ip.String(), d))
	}
	sort.Slice(p.targets, func(i, j int) bool { return p.targets[i].IP < p.targets[j].IP })
	return p, nil
}
func (s *Store) ApplyPrepared(ctx context.Context, p *PreparedBatch) error {
	if len(p.targets) == 0 {
		return nil
	}
	if st, e := os.Stat(s.path + "-wal"); e == nil && st.Size() > s.walLimit {
		var busy, log, done int
		if e = s.DB.QueryRowContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &log, &done); e != nil {
			return e
		}
		if busy != 0 {
			return ErrCheckpointBusy
		}
	}
	tx, e := s.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	stmt, e := tx.PrepareContext(ctx, `INSERT INTO clients(ip,requests,first_seen,last_seen) VALUES(?,?,?,?)
 ON CONFLICT(ip) DO UPDATE SET requests=max(clients.requests,excluded.requests),
 first_seen=min(clients.first_seen,excluded.first_seen),last_seen=max(clients.last_seen,excluded.last_seen)
 WHERE clients.requests<excluded.requests OR clients.first_seen>excluded.first_seen OR clients.last_seen<excluded.last_seen`)
	if e != nil {
		return e
	}
	defer stmt.Close()
	for _, row := range p.targets {
		if _, e = stmt.ExecContext(ctx, row.IP, row.Requests, row.First, row.Last); e != nil {
			return fmt.Errorf("write targets (disk or DB limit?): %w", e)
		}
	}
	return tx.Commit()
}

// Acknowledge is called once, after a successful ApplyPrepared. All subsequent
// batches are prepared after this point; only one writer may own a Store.
func (s *Store) Acknowledge(p *PreparedBatch) {
	for _, row := range p.targets {
		ip, e := netip.ParseAddr(row.IP)
		if e == nil {
			s.cache.put(ip, row)
		}
	}
}
func (s *Store) Flush(batch map[netip.Addr]Delta) error { _, e := s.FlushBatch(batch); return e }
func (s *Store) FlushBatch(batch map[netip.Addr]Delta) (Change, error) {
	p, e := s.PrepareBatch(context.Background(), batch)
	if e != nil {
		return Change{}, e
	}
	if e = s.ApplyPrepared(context.Background(), p); e != nil {
		return Change{}, e
	}
	s.Acknowledge(p)
	return p.Change, nil
}
