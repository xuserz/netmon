package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/mattn/go-sqlite3"
	"golang.org/x/sys/unix"
)

// Snapshot copies an online database incrementally, without a long-lived source
// transaction. cleanup must be called after the returned database is closed.
// The private temporary directory is created on the chosen export filesystem.
func (s *Store) Snapshot(ctx context.Context, directory string) (*Store, func(), error) {
	dir, e := os.MkdirTemp(directory, ".netmon-export-*")
	if e != nil {
		return nil, nil, e
	}
	remove := func() { os.RemoveAll(dir) }
	cleanup := remove
	success := false
	defer func() {
		if !success {
			remove()
		}
	}()
	path := filepath.Join(dir, "snapshot.db")
	u := url.URL{Scheme: "file", Path: path}
	q := u.Query()
	q.Set("_journal_mode", "DELETE")
	q.Set("_cache_size", "-1024")
	q.Set("_busy_timeout", "100")
	u.RawQuery = q.Encode()
	dest, e := sql.Open("sqlite3", u.String())
	if e != nil {
		return nil, nil, e
	}
	defer dest.Close()
	srcConn, e := s.DB.Conn(ctx)
	if e != nil {
		return nil, nil, e
	}
	defer srcConn.Close()
	dstConn, e := dest.Conn(ctx)
	if e != nil {
		return nil, nil, e
	}
	defer dstConn.Close()
	var pages, pageSize int64
	if e = srcConn.QueryRowContext(ctx, "PRAGMA page_count").Scan(&pages); e != nil {
		return nil, nil, e
	}
	if e = srcConn.QueryRowContext(ctx, "PRAGMA page_size").Scan(&pageSize); e != nil {
		return nil, nil, e
	}
	if e = backupSpace(dir, pages*pageSize); e != nil {
		return nil, nil, e
	}
	e = srcConn.Raw(func(src any) error {
		return dstConn.Raw(func(dst any) (stepErr error) {
			backup, e := dst.(*sqlite3.SQLiteConn).Backup("main", src.(*sqlite3.SQLiteConn), "main")
			if e != nil {
				return e
			}
			defer func() { stepErr = errors.Join(stepErr, backup.Finish()) }()
			nextSpace := time.Now()
			for {
				if e = ctx.Err(); e != nil {
					return e
				}
				// At most 128 pages are held under SQLite's source read lock per step.
				done, e := backup.Step(128)
				if e != nil {
					return e
				}
				if done {
					return nil
				}
				if !time.Now().Before(nextSpace) {
					if e = backupSpace(dir, int64(backup.Remaining())*pageSize); e != nil {
						return e
					}
					nextSpace = time.Now().Add(time.Second)
				}
				// Step releases the source read transaction before yielding to the writer.
				timer := time.NewTimer(time.Millisecond)
				select {
				case <-ctx.Done():
					timer.Stop()
					return ctx.Err()
				case <-timer.C:
				}
			}
		})
	})
	if e != nil {
		return nil, nil, e
	}
	// Close destination before opening it read-only and before exporting CSV.
	dstConn.Close()
	if e = dest.Close(); e != nil {
		return nil, nil, e
	}
	copy, e := Open(path, false, 0, 0)
	if e != nil {
		return nil, nil, e
	}
	success = true
	return copy, cleanup, nil
}
func backupSpace(directory string, remaining int64) error {
	var st unix.Statfs_t
	if e := unix.Statfs(directory, &st); e != nil {
		return e
	}
	free := uint64(st.Bavail) * uint64(st.Bsize)
	if remaining < 0 || free < uint64(remaining)+(16<<20) {
		return fmt.Errorf("not enough free space for export snapshot: need %d bytes plus 16 MiB reserve, available %d", remaining, free)
	}
	return nil
}

func SQLiteVersion() string { version, _, _ := sqlite3.Version(); return version }
