package main

import (
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

	"dnsmon/internal/store"
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
func export(tx *sql.Tx, dbPath, path string, w io.Writer) error {
	abs, e := filepath.Abs(path)
	if e != nil {
		return e
	}
	dbPaths := []string{dbPath}
	if real, err := filepath.EvalSymlinks(dbPath); err == nil {
		dbPaths = append(dbPaths, real)
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
	f, e := os.CreateTemp(filepath.Dir(abs), ".dnsmon-csv-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	defer f.Close()
	rows, e := tx.Query("SELECT ip,requests,first_seen,last_seen FROM clients ORDER BY requests DESC,ip ASC")
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
