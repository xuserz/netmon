package network

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"netmon/internal/config"
	"netmon/internal/observation"
	"netmon/internal/store"
)

type CompactResult struct {
	SourceBytes  int64
	ResultBytes  int64
	Observations int64
	Converted    int64
	Output       string
}
type compactRow struct {
	sample   observation.Sample
	version  int64
	priority float64
	raw      []byte
}

func compactRows(ctx context.Context, db *sql.DB, after string) ([]compactRow, error) {
	rows, e := db.QueryContext(ctx, "SELECT "+sampleColumns+",version,priority FROM net_observations WHERE id>? ORDER BY id LIMIT 128", after)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	result := make([]compactRow, 0, 128)
	for rows.Next() {
		var id, node, ip string
		var window int64
		var r compactRow
		if e = rows.Scan(&id, &node, &ip, &window, &r.raw, &r.version, &r.priority); e != nil {
			return nil, e
		}
		r.sample, e = decodeSample(id, node, ip, window, r.raw)
		if e != nil {
			return nil, e
		}
		// Validate structure independently of optional age expiry and wall-clock skew.
		now := time.Unix(max(time.Now().Unix(), r.sample.Last), 0)
		if e = r.sample.Validate(now, 0); e != nil {
			return nil, e
		}
		result = append(result, r)
	}
	return result, rows.Err()
}
func digestCompactRow(h hash.Hash, r compactRow) {
	raw, _ := json.Marshal(r.sample)
	var header [24]byte
	binary.LittleEndian.PutUint64(header[:8], uint64(len(raw)))
	binary.LittleEndian.PutUint64(header[8:16], uint64(r.version))
	binary.LittleEndian.PutUint64(header[16:], math.Float64bits(r.priority))
	h.Write(header[:])
	h.Write(raw)
}
func compactDigest(ctx context.Context, db *sql.DB) ([]byte, int64, error) {
	h := sha256.New()
	after := ""
	var count int64
	for {
		rows, e := compactRows(ctx, db, after)
		if e != nil {
			return nil, 0, e
		}
		for _, r := range rows {
			digestCompactRow(h, r)
			after = r.sample.ID
			count++
		}
		if len(rows) < 128 {
			return h.Sum(nil), count, nil
		}
	}
}

// Compact creates a verified copy; it never replaces the source or changes its
// counters/cursors. The normal runtime lock prevents copying a moving history
// that would lose the final observations when an operator switches DB paths.
func Compact(ctx context.Context, c config.Config, output string) (result CompactResult, err error) {
	if c.Mode != "network" || c.Storage.Mode != "full" {
		return result, errors.New("compact requires network mode with full storage")
	}
	target, e := filepath.Abs(output)
	if e != nil {
		return result, e
	}
	if output == "" {
		return result, errors.New("compact requires --output FILE")
	}
	if !strings.HasSuffix(target, ".network.db") {
		return result, errors.New("compact --output must end in .network.db; use the exact output path as database")
	}

	if _, e = os.Lstat(target); !os.IsNotExist(e) {
		return result, errors.New("compact output must not already exist")
	}
	source := DataPath(c.Database)
	info, e := os.Lstat(source)
	if e != nil {
		return result, e
	}
	if !info.Mode().IsRegular() {
		return result, errors.New("compact source must be a regular database file, not a symlink")
	}
	if e = os.MkdirAll(c.Network.RuntimeDirectory, 0750); e != nil {
		return result, e
	}
	lockPath := filepath.Join(c.Network.RuntimeDirectory, "monitor.lock")
	fd, e := unix.Open(lockPath, unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0640)
	if e != nil {
		return result, e
	}
	lock := os.NewFile(uintptr(fd), lockPath)
	defer lock.Close()
	if st, e := lock.Stat(); e != nil || !st.Mode().IsRegular() {
		return result, errors.New("invalid runtime lock file")
	}
	if e = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); e != nil {
		return result, errors.New("stop the network monitor before compacting its database")
	}
	defer unix.Flock(fd, unix.LOCK_UN)
	src, e := openDisk(c, false)
	if e != nil {
		return result, e
	}
	defer src.Close()
	var pages, pageSize int64
	if e = src.r.DB.QueryRowContext(ctx, "SELECT page_count,page_size FROM pragma_page_count(),pragma_page_size()").Scan(&pages, &pageSize); e != nil {
		return result, e
	}
	result.SourceBytes = pages * pageSize
	dir := filepath.Dir(target)
	var space unix.Statfs_t
	if e = unix.Statfs(dir, &space); e != nil {
		return result, e
	}
	if uint64(space.Bavail)*uint64(space.Bsize) < uint64(3*result.SourceBytes+(16<<20)) {
		return result, errors.New("compact needs free space for three source-sized temporary files plus 16 MiB reserve on the output filesystem")
	}
	snapshot, cleanup, e := src.r.Snapshot(ctx, dir)
	if e != nil {
		return result, e
	}
	defer cleanup()
	var tempPath string
	e = snapshot.DB.QueryRowContext(ctx, "SELECT file FROM pragma_database_list WHERE name='main'").Scan(&tempPath)
	snapshot.Close()
	if e != nil {
		return result, e
	}
	// Private maintenance copy may temporarily need pages for B-tree rebalance.
	w, e := store.OpenBare(tempPath, true, c.MaxDatabaseMB+max(int64(16), c.MaxDatabaseMB/10), c.MaxWALMB)
	if e != nil {
		return result, e
	}
	defer w.Close()
	expected := sha256.New()
	after := ""
	for {
		batch, e := compactRows(ctx, w.DB, after)
		if e != nil {
			return result, e
		}
		if len(batch) == 0 {
			break
		}
		if e = w.EnsureWAL(ctx); e != nil {
			return result, e
		}
		tx, e := w.DB.BeginTx(ctx, nil)
		if e != nil {
			return result, e
		}
		for _, r := range batch {
			raw := encodeSample(r.sample)
			roundTrip, e := decodeSample(r.sample.ID, r.sample.Node, r.sample.IP, r.sample.Window, raw)
			if e != nil {
				tx.Rollback()
				return result, e
			}
			oldJSON, _ := json.Marshal(r.sample)
			newJSON, _ := json.Marshal(roundTrip)
			if string(oldJSON) != string(newJSON) {
				tx.Rollback()
				return result, errors.New("compact round-trip changed an observation")
			}
			digestCompactRow(expected, r)
			if len(r.raw) > 0 && r.raw[0] == '{' {
				if _, e = tx.ExecContext(ctx, "UPDATE net_observations SET payload=? WHERE id=?", raw, r.sample.ID); e != nil {
					tx.Rollback()
					return result, e
				}
				result.Converted++
			}
			after = r.sample.ID
			result.Observations++
		}
		if e = tx.Commit(); e != nil {
			return result, e
		}
	}
	var journal string
	if e = w.DB.QueryRowContext(ctx, "PRAGMA journal_mode=DELETE").Scan(&journal); e != nil {
		return result, e
	}
	if strings.ToLower(journal) != "delete" {
		return result, errors.New("could not checkpoint compact database")
	}
	if _, e = w.DB.ExecContext(ctx, "VACUUM"); e != nil {
		return result, e
	}
	actual, count, e := compactDigest(ctx, w.DB)
	if e != nil {
		return result, e
	}
	if string(actual) != string(expected.Sum(nil)) || count != result.Observations {
		return result, errors.New("compact database verification failed")
	}
	var integrity string
	if e = w.DB.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&integrity); e != nil {
		return result, e
	}
	if integrity != "ok" {
		return result, fmt.Errorf("compact database integrity: %s", integrity)
	}
	if e = w.Close(); e != nil {
		return result, e
	}
	st, e := os.Stat(tempPath)
	if e != nil {
		return result, e
	}
	result.ResultBytes = st.Size()
	if result.ResultBytes > c.MaxDatabaseMB<<20 {
		return result, errors.New("compacted database still exceeds max_database_mb; increase the limit before switching paths")
	}
	var owner unix.Stat_t
	if e = unix.Stat(source, &owner); e != nil {
		return result, e
	}
	if e = os.Chown(tempPath, int(owner.Uid), int(owner.Gid)); e != nil {
		return result, e
	}

	if e = os.Chmod(tempPath, info.Mode().Perm()); e != nil {
		return result, e
	}
	f, e := os.OpenFile(tempPath, os.O_RDWR, 0)
	if e != nil {
		return result, e
	}
	e = f.Sync()
	closeErr := f.Close()
	if e != nil {
		return result, e
	}
	if closeErr != nil {
		return result, closeErr
	}
	// Same-filesystem link publishes a complete file atomically and never replaces
	// another file or follows a target symlink, even if one appears during work.
	if e = os.Link(tempPath, target); e != nil {
		return result, e
	}
	published := false
	defer func() {
		if !published {
			os.Remove(target)
		}
	}()
	parent, e := os.Open(dir)
	if e != nil {
		return result, e
	}
	e = parent.Sync()
	parent.Close()
	if e != nil {
		return result, e
	}
	result.Output = target
	published = true
	return result, nil
}
