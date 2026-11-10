package main

import (
	"context"
	"database/sql"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"netmon/internal/store"
)

func show(tx *sql.Tx, ip string, w io.Writer) error {
	a, e := netip.ParseAddr(ip)
	if e != nil || a.Zone() != "" {
		return errors.New("invalid IPv4/IPv6 address")
	}
	c, e := store.Scan(tx.QueryRow("SELECT ip,requests,first_seen,last_seen FROM clients WHERE ip=?", a.Unmap().String()))
	if errors.Is(e, sql.ErrNoRows) {
		return fmt.Errorf("no statistics for %s", a)
	}
	if e != nil {
		return e
	}
	printHeader(w)
	printClient(w, c)
	return nil
}
func export(ctx context.Context, source *store.Store, dbPath, path string, w io.Writer, protected ...string) error {
	abs, e := filepath.Abs(path)
	if e != nil {
		return e
	}
	dbPaths := append([]string{dbPath}, protected...)
	for _, base := range dbPaths {
		if real, err := filepath.EvalSymlinks(base); err == nil {
			dbPaths = append(dbPaths, real)
		}
	}
	for _, base := range dbPaths {
		for _, suffix := range []string{"", "-wal", "-shm", ".lock", ".sock"} {
			target := base + suffix
			resolved, _ := filepath.EvalSymlinks(abs)
			same := abs == target || resolved == target
			if a, err := os.Stat(abs); err == nil {
				if b, err := os.Stat(target); err == nil && os.SameFile(a, b) {
					same = true
				}
			}
			if same {
				return errors.New("CSV destination must not overwrite the database or its sidecar files")
			}
		}
	}
	copy, cleanup, e := source.Snapshot(ctx, filepath.Dir(abs))
	if e != nil {
		return fmt.Errorf("prepare export snapshot: %w", e)
	}
	defer cleanup()
	defer copy.Close()
	tx, e := copy.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return e
	}
	defer tx.Rollback()
	f, e := os.CreateTemp(filepath.Dir(abs), ".netmon-csv-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	defer f.Close()
	rows, e := tx.QueryContext(ctx, "SELECT ip,requests,first_seen,last_seen FROM clients ORDER BY requests DESC,ip ASC")
	if e != nil {
		return e
	}
	defer rows.Close()
	cw := csv.NewWriter(f)
	if e = cw.Write([]string{"ip", "requests", "first_seen", "last_seen"}); e != nil {
		return e
	}
	for rows.Next() {
		c, err := store.Scan(rows)
		if err != nil {
			return err
		}
		if err = cw.Write([]string{c.IP, strconv.FormatInt(c.Requests, 10), time.Unix(c.First, 0).UTC().Format(time.RFC3339), time.Unix(c.Last, 0).UTC().Format(time.RFC3339)}); err != nil {
			return err
		}
	}
	if e = rows.Err(); e != nil {
		return e
	}
	cw.Flush()
	if e = cw.Error(); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = os.Rename(f.Name(), abs); e != nil {
		return e
	}
	fmt.Fprintln(w, "Exported:", abs)
	return nil
}
