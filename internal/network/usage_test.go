package network

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"netmon/internal/observation"
)

func TestStorageMetricsIncludeWALAndCorrectHeadroom(t *testing.T) {
	c := configForTest(t)
	d, e := openDisk(c, true)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	if e = d.Merge(context.Background(), []observation.Sample{sample(observation.ID(), 7)}, nil); e != nil {
		t.Fatal(e)
	}
	u := StorageUsage(context.Background(), c)
	if u.Error != "" || !u.DatabaseKnown || !u.DiskKnown || !u.Enabled {
		t.Fatal(u)
	}
	if u.DatabaseBytes <= 0 || u.UsedBytes <= 0 || u.DatabaseBytes != u.UsedBytes+u.ReusableBytes || u.LimitBytes != c.MaxDatabaseMB<<20 {
		t.Fatal(u)
	}
	if u.WALBytes <= 0 || u.FilesBytes < u.WALBytes || u.DiskAvailableBytes <= 0 {
		t.Fatal(u)
	}
	expected := min(u.LimitBytes-u.UsedBytes, u.DiskAvailableBytes)
	if u.HeadroomBytes != expected || u.HeadroomBytes < 0 {
		t.Fatal(u, expected)
	}
	var actual int64
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if st, e := os.Stat(DataPath(c.Database) + suffix); e == nil {
			actual += st.Size()
		}
	}
	if u.FilesBytes != actual {
		t.Fatal("file sizes do not match filesystem", u.FilesBytes, actual)
	}
}
func TestStorageMetricsNeverCreateForwardOrMissingDatabase(t *testing.T) {
	c := configForTest(t)
	c.Database = filepath.Join(t.TempDir(), "must-not-exist", "stats.db")
	for _, role := range []string{"forward", "full"} {
		c.Storage.Mode = role
		u := StorageUsage(context.Background(), c)
		if !u.DiskKnown || u.DiskAvailableBytes <= 0 || u.DatabaseKnown || u.HeadroomBytes != 0 {
			t.Fatal(role, u)
		}
		if role == "forward" && (u.Enabled || u.Error != "") {
			t.Fatal("forward tried to open SQLite", u)
		}
		if role == "full" && u.Error == "" {
			t.Fatal("missing database metrics silently look valid", u)
		}
		if _, e := os.Stat(filepath.Dir(c.Database)); !os.IsNotExist(e) {
			t.Fatal("metrics created database directory", e)
		}
	}
}
