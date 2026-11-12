package network

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"netmon/internal/cluster"
	"netmon/internal/config"
	"netmon/internal/observation"
	"netmon/internal/release"
)

func Read(ctx context.Context, c config.Config, sort string, n int) ([]observation.IP, observation.Totals, error) {
	s, e := openDisk(c, false)
	if e != nil {
		return nil, observation.Totals{}, e
	}
	defer s.Close()
	rows, total, e := s.View(ctx, sort, n)
	if e != nil {
		return nil, total, e
	}
	e = NewLabeler(c).Annotate(rows)
	return rows, total, e
}
func ReadTotals(ctx context.Context, c config.Config) (observation.Totals, error) {
	s, e := openDisk(c, false)
	if e != nil {
		return observation.Totals{}, e
	}
	defer s.Close()
	return readTotals(ctx, s.r.DB)
}
func ReadIP(ctx context.Context, c config.Config, ip string) (observation.IP, error) {
	s, e := openDisk(c, false)
	if e != nil {
		return observation.IP{}, e
	}
	defer s.Close()
	row, e := s.Show(ctx, ip)
	if e != nil {
		return row, e
	}
	rows := []observation.IP{row}
	e = NewLabeler(c).Annotate(rows)
	return rows[0], e
}
func ReadPeers(ctx context.Context, c config.Config) ([]Peer, error) {
	s, e := openDisk(c, false)
	if e != nil {
		return nil, e
	}
	defer s.Close()
	return s.Peers(ctx)
}
func csvFields(row observation.IP) []string {
	reasons, _ := json.Marshal(row.Reasons)
	return []string{row.IP, strconv.FormatInt(row.Packets, 10), strconv.FormatInt(row.Bytes, 10), strconv.FormatInt(row.TCP, 10), strconv.FormatInt(row.SYN, 10), strconv.FormatInt(row.UDP, 10), strconv.FormatInt(row.ICMP, 10), time.Unix(row.First, 0).UTC().Format(time.RFC3339), time.Unix(row.Last, 0).UTC().Format(time.RFC3339), strconv.Itoa(row.Score), string(reasons), strconv.FormatBool(row.Partial), row.ServerName, row.ServerSource, strconv.FormatBool(row.Whitelisted), row.WhitelistDescription, providerCSV(row), row.ProviderRevision, row.ProviderDate, strconv.FormatInt(row.Traffic.Inbound, 10), strconv.FormatInt(row.Traffic.Reply, 10), strconv.FormatInt(row.Traffic.Unknown, 10)}
}
func Export(ctx context.Context, c config.Config, path string) error {
	target, e := filepath.Abs(path)
	if e != nil {
		return e
	}
	for _, base := range []string{c.Database, DataPath(c.Database), cluster.Path(c.Database), c.Cluster.KeyFile, c.LabelsFile, c.ProvidersFile, c.Updates.PublicKey, InstalledOfferPath, InstalledOfferPath + ".sig", UpdateStatePath, RuntimeBase(c)} {
		if base == "" {
			continue
		}
		for _, suffix := range []string{"", "-wal", "-shm", ".sock", ".lock"} {
			protected := base + suffix
			resolved, _ := filepath.EvalSymlinks(target)
			real, _ := filepath.EvalSymlinks(protected)
			same := target == protected || resolved != "" && (resolved == protected || resolved == real)
			if a, err := os.Stat(target); err == nil {
				if b, err := os.Stat(protected); err == nil && os.SameFile(a, b) {
					same = true
				}
			}
			if same {
				return errors.New("network CSV must not overwrite a database, key, or runtime file")
			}
		}
	}
	s, e := openDisk(c, false)
	if e != nil {
		return e
	}
	defer s.Close()
	copy, cleanup, e := s.r.Snapshot(ctx, filepath.Dir(target))
	if e != nil {
		return e
	}
	defer cleanup()
	defer copy.Close()
	f, e := os.CreateTemp(filepath.Dir(target), ".netmon-network-csv-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	defer f.Close()
	writer := csv.NewWriter(f)
	if e = writer.Write([]string{"ip", "packets", "bytes", "tcp_packets", "tcp_syn", "udp_packets", "icmp_packets", "first_seen", "last_seen", "suspicion", "reasons", "partial", "server_name", "server_source", "whitelisted", "whitelist_description", "providers", "provider_revision", "provider_date", "inbound_packets", "reply_packets", "unknown_packets"}); e != nil {
		return e
	}
	rows, e := copy.DB.QueryContext(ctx, "SELECT "+ipColumns+" FROM net_ips ORDER BY priority DESC,ip")
	if e != nil {
		return e
	}
	defer rows.Close()
	now := time.Now()
	annotate, e := NewLabeler(c).Snapshot()
	if e != nil {
		return e
	}
	for rows.Next() {
		row, err := scanIP(rows, s.policy, now)
		if err != nil {
			return err
		}
		annotate(&row)
		if e = writer.Write(csvFields(row)); e != nil {
			return e
		}
	}
	if e = rows.Err(); e != nil {
		return e
	}
	writer.Flush()
	if e = writer.Error(); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	return os.Rename(f.Name(), target)
}
func Check(c config.Config) error {
	if e := c.Validate(); e != nil {
		return e
	}
	if c.Updates.Automatic {
		if _, e := release.PublicKey(c.Updates.PublicKey); e != nil {
			return fmt.Errorf("update verification key: %w", e)
		}
	}
	if c.Cluster.Enabled {
		if _, e := cluster.ReadKey(c.Cluster.KeyFile); e != nil {
			return fmt.Errorf("network cluster key: %w", e)
		}
	}
	return nil
}

// List uses a private copy so a slow output pipe cannot pin the capture WAL.
func List(ctx context.Context, c config.Config, directory, kind string, visit func(observation.IP) error) (observation.Totals, error) {
	column, e := rank(kind)
	if e != nil {
		return observation.Totals{}, e
	}
	s, e := openDisk(c, false)
	if e != nil {
		return observation.Totals{}, e
	}
	defer s.Close()
	copy, cleanup, e := s.r.Snapshot(ctx, directory)
	if e != nil {
		return observation.Totals{}, e
	}
	defer cleanup()
	defer copy.Close()
	tx, e := copy.DB.BeginTx(ctx, nil)
	if e != nil {
		return observation.Totals{}, e
	}
	defer tx.Rollback()
	totals, e := readTotals(ctx, tx)
	if e != nil {
		return totals, e
	}
	rows, e := tx.QueryContext(ctx, "SELECT "+ipColumns+" FROM net_ips ORDER BY "+column+" DESC,ip")
	if e != nil {
		return totals, e
	}
	defer rows.Close()
	now := time.Now()
	annotate, e := NewLabeler(c).Snapshot()
	if e != nil {
		return totals, e
	}
	for rows.Next() {
		row, err := scanIP(rows, s.policy, now)
		if err != nil {
			return totals, err
		}
		annotate(&row)
		if e = visit(row); e != nil {
			return totals, e
		}
	}
	return totals, rows.Err()
}

func providerCSV(row observation.IP) string {
	if len(row.Providers) == 0 {
		return ""
	}
	raw, _ := json.Marshal(row.Providers)
	return string(raw)
}
