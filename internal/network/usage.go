package network

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
	"netmon/internal/config"
	"netmon/internal/live"
	"netmon/internal/store"
)

// StorageUsage samples the database filesystem without creating a directory or
// database. Forward nodes never open SQLite, including for these diagnostics.
func StorageUsage(ctx context.Context, c config.Config) live.StorageUsage {
	if c.Storage.Mode == "forward" {
		return sampleStorageUsage(ctx, c, nil)
	}
	s, e := store.OpenBare(DataPath(c.Database), false, 0, 0)
	if e != nil {
		u := sampleStorageUsage(ctx, c, nil)
		u.Error = limitedError(e)
		return u
	}
	defer s.Close()
	return sampleStorageUsage(ctx, c, s.DB)
}
func sampleStorageUsage(ctx context.Context, c config.Config, db *sql.DB) live.StorageUsage {
	u := live.StorageUsage{Enabled: c.Storage.Mode == "full"}
	path := DataPath(c.Database)
	dir := filepath.Dir(path)
	var fs unix.Statfs_t
	for {
		e := unix.Statfs(dir, &fs)
		if e == nil {
			u.DiskKnown = true
			u.DiskAvailableBytes = int64(fs.Bavail) * int64(fs.Bsize)
			break
		}
		if !errors.Is(e, os.ErrNotExist) || filepath.Dir(dir) == dir {
			u.Error = limitedError(e)
			break
		}
		dir = filepath.Dir(dir)
	}
	if !u.Enabled {
		return u
	}
	u.LimitBytes = c.MaxDatabaseMB << 20
	if db == nil {
		return u
	}
	var pages, free, size int64
	// PRAGMA table-valued functions read one SQLite snapshot, including WAL pages.
	e := db.QueryRowContext(ctx, `SELECT page_count,freelist_count,page_size FROM pragma_page_count(),pragma_freelist_count(),pragma_page_size()`).Scan(&pages, &free, &size)
	if e != nil {
		u.Error = limitedError(e)
		return u
	}
	u.DatabaseKnown = true
	u.DatabaseBytes = pages * size
	u.ReusableBytes = free * size
	u.UsedBytes = max(int64(0), pages-free) * size
	for _, suffix := range []string{"", "-wal", "-shm"} {
		st, e := os.Stat(path + suffix)
		if e != nil {
			if !errors.Is(e, os.ErrNotExist) {
				u.Error = limitedError(e)
			}
			continue
		}
		u.FilesBytes += st.Size()
		if suffix == "-wal" {
			u.WALBytes = st.Size()
		}
	}
	if u.DiskKnown {
		// Estimate incremental live SQLite page space before eviction. Each page,
		// including a reused page, still needs WAL space on this filesystem.
		u.HeadroomBytes = min(max(int64(0), u.LimitBytes-u.UsedBytes), u.DiskAvailableBytes)
	}
	return u
}
