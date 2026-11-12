package network

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/mattn/go-sqlite3"
	"netmon/internal/config"
	"netmon/internal/observation"
	"netmon/internal/store"
)

var ErrExpired = errors.New("observation expired")

func DataPath(path string) string {
	if strings.HasSuffix(path, ".network.db") {
		return path
	}
	return path + ".network.db"
}
func Policy(c config.Config) observation.Policy {
	r := c.Network.Rating
	return observation.Policy{PPS: r.PacketsPerSecond, SYN: r.SYNPerSecond, Ports: r.ScanPorts, HalfLifeSeconds: int64(r.HalfLife / time.Second)}
}

type disk struct {
	journal     bool
	w, r        *store.Store
	mu          sync.Mutex // Serializes writes, including use of the incident encoder.
	encoder     incidentEncoder
	node, epoch string
	retention   time.Duration
	policy      observation.Policy
}
type Peer struct {
	URL     string `json:"url"`
	Name    string `json:"name"`
	Node    string `json:"node"`
	Epoch   string `json:"epoch"`
	Cursor  int64  `json:"cursor"`
	Success int64  `json:"success"`
	Error   string `json:"error"`
}
type Page struct {
	Incidents []observation.Incident `json:"incidents,omitempty"`
	Epoch     string                 `json:"epoch"`
	Cursor    int64                  `json:"cursor"`
	Head      int64                  `json:"head"`
	Floor     int64                  `json:"storage_floor"`
	Samples   []observation.Sample   `json:"samples"`
}

func openDisk(c config.Config, write bool) (*disk, error) {
	path := DataPath(c.Database)
	w, e := store.OpenBare(path, write, c.MaxDatabaseMB, c.MaxWALMB)
	if e != nil {
		return nil, e
	}
	s := &disk{w: w, retention: c.Storage.Retention, policy: Policy(c)}
	ok := false
	defer func() {
		if !ok {
			w.Close()
		}
	}()
	if write {
		tx, e := w.DB.Begin()
		if e != nil {
			return nil, e
		}
		defer tx.Rollback()
		for _, q := range []string{
			`CREATE TABLE IF NOT EXISTS net_meta(id INTEGER PRIMARY KEY CHECK(id=1),node TEXT NOT NULL,epoch TEXT NOT NULL,sequence INTEGER NOT NULL,policy TEXT NOT NULL,retention INTEGER NOT NULL)`,
			`CREATE TABLE IF NOT EXISTS net_observations(id TEXT PRIMARY KEY,node TEXT NOT NULL,ip TEXT NOT NULL,window INTEGER NOT NULL,version INTEGER NOT NULL,priority REAL NOT NULL,payload BLOB NOT NULL) WITHOUT ROWID`,
			`CREATE INDEX IF NOT EXISTS net_changes ON net_observations(version)`,
			`CREATE INDEX IF NOT EXISTS net_ip_observations ON net_observations(ip,priority DESC)`,
			`CREATE INDEX IF NOT EXISTS net_expiry ON net_observations(window)`,
			`CREATE INDEX IF NOT EXISTS net_ip_windows ON net_observations(ip,window)`,
			`CREATE TABLE IF NOT EXISTS net_storage(id INTEGER PRIMARY KEY CHECK(id=1),floor INTEGER NOT NULL,evicted INTEGER NOT NULL)`,
			`INSERT OR IGNORE INTO net_storage VALUES(1,0,0)`,
			`CREATE TABLE IF NOT EXISTS net_totals(id INTEGER PRIMARY KEY CHECK(id=1),ips INTEGER NOT NULL,packets INTEGER NOT NULL,bytes INTEGER NOT NULL,tcp INTEGER NOT NULL,syn INTEGER NOT NULL,udp INTEGER NOT NULL,icmp INTEGER NOT NULL)`,
			`INSERT OR IGNORE INTO net_totals VALUES(1,0,0,0,0,0,0,0)`,
			`CREATE TABLE IF NOT EXISTS net_ips(ip TEXT PRIMARY KEY,packets INTEGER NOT NULL,bytes INTEGER NOT NULL,tcp INTEGER NOT NULL,syn INTEGER NOT NULL,udp INTEGER NOT NULL,icmp INTEGER NOT NULL,first INTEGER NOT NULL,last INTEGER NOT NULL,peak INTEGER NOT NULL,evidence BLOB NOT NULL,priority REAL NOT NULL,partial INTEGER NOT NULL) WITHOUT ROWID`,
			`CREATE INDEX IF NOT EXISTS net_rank_score ON net_ips(priority DESC,ip)`,
			`CREATE INDEX IF NOT EXISTS net_rank_packets ON net_ips(packets DESC,ip)`,
			`CREATE INDEX IF NOT EXISTS net_rank_bytes ON net_ips(bytes DESC,ip)`,
			`CREATE INDEX IF NOT EXISTS net_rank_syn ON net_ips(syn DESC,ip)`,
			`CREATE TABLE IF NOT EXISTS net_analysis(id INTEGER PRIMARY KEY CHECK(id=1),sequence INTEGER NOT NULL)`,
			`CREATE TABLE IF NOT EXISTS net_incidents(id TEXT PRIMARY KEY,ip TEXT NOT NULL,kind TEXT NOT NULL,bucket INTEGER NOT NULL,last INTEGER NOT NULL,version INTEGER NOT NULL,priority REAL NOT NULL,payload BLOB NOT NULL) WITHOUT ROWID`,
			`CREATE INDEX IF NOT EXISTS net_incident_changes ON net_incidents(version)`,
			`CREATE INDEX IF NOT EXISTS net_incident_recent ON net_incidents(last DESC,id)`,
			`CREATE INDEX IF NOT EXISTS net_incident_ip ON net_incidents(ip,priority DESC)`,
			`CREATE TABLE IF NOT EXISTS net_peers(url TEXT PRIMARY KEY,node TEXT NOT NULL DEFAULT '',name TEXT NOT NULL DEFAULT '',epoch TEXT NOT NULL DEFAULT '',cursor INTEGER NOT NULL DEFAULT 0,success INTEGER NOT NULL DEFAULT 0,error TEXT NOT NULL DEFAULT '') WITHOUT ROWID`,
		} {
			if _, e = tx.Exec(q); e != nil {
				return nil, e
			}
		}
		policy, _ := json.Marshal(s.policy)
		if _, e = tx.Exec("INSERT OR IGNORE INTO net_meta VALUES(1,?,?,0,?,?)", observation.ID(), observation.ID(), string(policy), int64(c.Storage.Retention/time.Second)); e != nil {
			return nil, e
		}
		// A newly introduced journal starts at the existing frontier. Do not
		// delay live detection by re-analyzing years of pre-feature history.
		if _, e = tx.Exec("INSERT OR IGNORE INTO net_analysis SELECT 1,sequence FROM net_meta WHERE id=1"); e != nil {
			return nil, e
		}
		if e = tx.Commit(); e != nil {
			return nil, e
		}
	}
	var policy string
	var retention int64
	if e = w.DB.QueryRow("SELECT node,epoch,policy,retention FROM net_meta WHERE id=1").Scan(&s.node, &s.epoch, &policy, &retention); e != nil {
		return nil, e
	}
	expected, _ := json.Marshal(s.policy)
	if policy != string(expected) {
		return nil, errors.New("network rating policy differs from this database; use a new database for another policy")
	}
	if retention != int64(s.retention/time.Second) && s.retention == 0 && retention > 0 {
		// Disabling age expiry preserves all surviving observations and node identity.
		if write {
			if _, e = w.DB.Exec("UPDATE net_meta SET retention=0 WHERE id=1"); e != nil {
				return nil, e
			}
		}
		retention = 0
	}
	if retention != int64(s.retention/time.Second) {
		return nil, errors.New("network rating policy/retention differ from this database; use a new database for another policy")
	}
	if write {
		s.r, e = store.OpenBare(path, false, 0, 0)
		if e != nil {
			return nil, e
		}
	} else {
		s.r = w
	}
	var tables int
	if e = w.DB.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='net_incidents'").Scan(&tables); e != nil {
		return nil, e
	}
	s.journal = tables > 0
	ok = true
	return s, nil
}
func (s *disk) Close() {
	if s.r != s.w {
		s.r.Close()
	}
	s.w.Close()
}
func unionPorts(a, b []uint16) []uint16 {
	out := append(append(make([]uint16, 0, len(a)+len(b)), a...), b...)
	slices.Sort(out)
	out = slices.Compact(out)
	return out[:min(len(out), observation.MaxPorts)]
}
func mergeSample(old, next observation.Sample, p observation.Policy) (observation.Sample, error) {
	if old.ID != "" {
		if old.Node != next.Node || old.IP != next.IP || old.Window != next.Window {
			return old, errors.New("observation identity reused for a different source/window")
		}
		details, e := observation.MergeDetails(old.Details, next.Details)
		if e != nil {
			return old, e
		}
		next.Details = details
		next.Name = min(old.Name, next.Name)
		next.Counters = next.Counters.Max(old.Counters)
		next.First = min(old.First, next.First)
		next.Last = max(old.Last, next.Last)
		next.PeakPPS = max(old.PeakPPS, next.PeakPPS)
		next.Ports = unionPorts(old.Ports, next.Ports)
		next.Partial = old.Partial || next.Partial
		if p.Better(old.Evidence, next.Evidence) {
			next.Evidence = old.Evidence
		}
	}
	next.Ports = unionPorts(nil, next.Ports)
	return next, nil
}
func (s *disk) Merge(ctx context.Context, items []observation.Sample, peer *Peer) error {
	return s.mergeBatch(ctx, items, peer, 0, nil, 0)
}
func (s *disk) mergePage(ctx context.Context, items []observation.Sample, peer *Peer, floor int64, incidents []observation.Incident) error {
	return s.mergeBatch(ctx, items, peer, floor, incidents, 0)
}
func (s *disk) mergeBatch(ctx context.Context, items []observation.Sample, peer *Peer, floor int64, incidents []observation.Incident, analysisCursor int64) error {
	if len(items)+len(incidents) > 128 {
		return errors.New("network page exceeds 128 records")
	}
	for _, v := range incidents {
		if _, e := normalizeIncident(v, s.policy); e != nil {
			return e
		}
	}
	if floor < 0 || floor%60 != 0 || floor > time.Now().Unix()+300 {
		return errors.New("invalid storage floor")
	}
	if len(items) > 128 {
		return errors.New("network page exceeds 128 observations")
	}
	// Validate before any capacity deletion: malformed input cannot evict history.
	now := time.Now()
	identities := map[string]observation.Sample{}
	for _, item := range items {
		if s.retention > 0 && item.Window+60 <= now.Add(-s.retention).Unix() {
			continue
		}
		if e := item.Validate(now, s.retention); e != nil {
			return e
		}
		merged, e := mergeSample(identities[item.ID], item, s.policy)
		if e != nil {
			return e
		}
		if e = merged.Validate(now, s.retention); e != nil {
			return e
		}
		identities[item.ID] = merged
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.w.EnsureWAL(ctx); e != nil {
		return e
	}

	for {
		var changed bool
		e := s.mergeOnce(ctx, items, peer, floor, &changed, incidents, analysisCursor)
		if e == nil {
			// Reserve space after a committed change; stale/no-op replay must never
			// trigger new eviction simply because this replica is near capacity.
			if !changed {
				return nil
			}
			if floor > 0 {
				if _, err := s.pruneLocked(ctx, false); err != nil {
					return err
				}
			}
			for {
				pressure, err := s.capacityPressure(ctx)
				if err != nil {
					return err
				}
				if !pressure {
					return nil
				}
				n, err := s.pruneLocked(ctx, true)
				if err != nil {
					return err
				}
				if n == 0 {
					return nil
				}
				if ctx.Err() != nil {
					return ctx.Err()
				}
			}
		}
		var sqliteErr sqlite3.Error
		if !errors.As(e, &sqliteErr) || sqliteErr.Code != sqlite3.ErrFull {
			return e
		}
		// SQLITE_FULL rolls back the batch. Free old committed windows in a separate
		// transaction, then replay the same absolute counters and cursor safely.
		n, pruneErr := s.pruneLocked(ctx, true)
		if pruneErr != nil {
			return pruneErr
		}
		if n == 0 {
			return e
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
}
func (s *disk) mergeOnce(ctx context.Context, items []observation.Sample, peer *Peer, floor int64, changed *bool, incidents []observation.Incident, analysisCursor int64) error {
	if len(items) > 128 {
		return errors.New("network page exceeds 128 observations")
	}
	now := time.Now()
	filtered := make([]observation.Sample, 0, len(items))
	for _, item := range items {
		if s.retention == 0 || item.Window+60 > now.Add(-s.retention).Unix() {
			filtered = append(filtered, item)
		}
	}
	items = filtered
	for _, item := range items {
		if e := item.Validate(now, s.retention); e != nil {
			return e
		}
	}
	tx, e := s.w.DB.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var seq int64
	if e = tx.QueryRowContext(ctx, "SELECT sequence FROM net_meta WHERE id=1").Scan(&seq); e != nil {
		return e
	}
	originalSequence := seq
	var storedFloor int64
	if e = tx.QueryRowContext(ctx, "SELECT floor FROM net_storage WHERE id=1").Scan(&storedFloor); e != nil {
		return e
	}
	if floor > storedFloor {
		if _, e = tx.ExecContext(ctx, "UPDATE net_storage SET floor=? WHERE id=1", floor); e != nil {
			return e
		}
		seq++
	} else {
		floor = storedFloor
	}
	var totals, originalTotals observation.Totals
	var stmts [4]*sql.Stmt
	if len(items) != 0 {
		totals, e = readTotals(ctx, tx)
		if e != nil {
			return e
		}
		originalTotals = totals
		queries := [...]string{
			"SELECT " + sampleColumns + " FROM net_observations WHERE id=?",
			`INSERT INTO net_observations VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET version=excluded.version,priority=excluded.priority,payload=excluded.payload`,
			"SELECT " + ipColumns + " FROM net_ips WHERE ip=?",
			`INSERT INTO net_ips VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(ip) DO UPDATE SET packets=excluded.packets,bytes=excluded.bytes,tcp=excluded.tcp,syn=excluded.syn,udp=excluded.udp,icmp=excluded.icmp,first=excluded.first,last=excluded.last,peak=excluded.peak,evidence=excluded.evidence,priority=excluded.priority,partial=excluded.partial`,
		}
		for i, q := range queries {
			stmt, err := tx.PrepareContext(ctx, q)
			if err != nil {
				return err
			}
			stmts[i] = stmt
			defer stmt.Close()
		}
	}
	for _, item := range items {
		if item.Window < floor {
			continue
		}
		old, e := scanSample(stmts[0].QueryRowContext(ctx, item.ID))
		if e != nil && !errors.Is(e, sql.ErrNoRows) {
			return e
		}

		next, err := mergeSample(old, item, s.policy)
		if err != nil {
			return err
		}
		if e := next.Validate(now, s.retention); e != nil {
			return e
		}
		encoded := encodeSample(next)
		if old.ID != "" && bytes.Equal(encodeSample(old), encoded) {
			continue
		}
		row, evidence, e := scanIPState(stmts[2].QueryRowContext(ctx, item.IP))
		absent := errors.Is(e, sql.ErrNoRows)
		if e != nil && !absent {
			return e
		}
		row.IP = item.IP
		delta := next.Counters.Minus(old.Counters)
		if !row.Counters.CanAdd(delta) || !totals.Counters.CanAdd(delta) {
			return errors.New("network counter overflow; transaction was not applied")
		}
		oldCounters := row.Counters
		trafficDelta := next.Traffic().Minus(old.Traffic())
		if trafficDelta.Unknown < 0 || trafficDelta.Inbound < 0 || trafficDelta.Reply < 0 {
			return errors.New("inconsistent traffic classification snapshot")
		}
		row.Traffic = row.Traffic.Plus(trafficDelta)
		row.Counters = row.Counters.Plus(delta)
		totals.Counters = totals.Counters.Plus(row.Counters.Minus(oldCounters))
		if absent {
			totals.IPs++
		}
		if absent {
			row.First = next.First
		}
		row.First = min(row.First, next.First)
		row.Last = max(row.Last, next.Last)
		row.PeakPPS = max(row.PeakPPS, next.PeakPPS)
		row.Partial = row.Partial || next.Partial
		if s.policy.Better(next.Evidence, evidence) {
			evidence = next.Evidence
		}
		if absent {
			row.Correlation, e = loadCorrelation(ctx, tx, row.IP)
			if e != nil {
				return e
			}
		}
		ev := marshalIPState(evidence, row.Traffic, row.Correlation)
		seq++
		if _, e = stmts[1].ExecContext(ctx, next.ID, next.Node, next.IP, next.Window, seq, s.policy.Priority(next.Evidence), encoded); e != nil {
			return e
		}
		if _, e = stmts[3].ExecContext(ctx, row.IP, row.Packets, row.Bytes, row.TCP, row.SYN, row.UDP, row.ICMP, row.First, row.Last, row.PeakPPS, ev, max(s.policy.Priority(evidence), row.Correlation.Priority(s.policy)), row.Partial); e != nil {
			return e
		}
	}
	if len(incidents) != 0 {
		updatedIPs := make(map[string]struct{}, len(incidents))
		for _, v := range incidents {
			previous := seq
			if e := s.writeIncident(ctx, tx, v, &seq, incidentFloor(s.retention, floor)); e != nil {
				return e
			}
			if seq != previous {
				updatedIPs[v.IP] = struct{}{}
			}
		}
		for ip := range updatedIPs {
			if e := refreshCorrelation(ctx, tx, ip, s.policy); e != nil {
				return e
			}
		}
	}
	if totals != originalTotals {
		if e = writeTotals(ctx, tx, totals); e != nil {
			return e
		}
	}
	if seq != originalSequence {
		if _, e = tx.ExecContext(ctx, "UPDATE net_meta SET sequence=? WHERE id=1", seq); e != nil {
			return e
		}
	}
	if analysisCursor > 0 {
		if _, e = tx.ExecContext(ctx, advanceAnalysisSQL, analysisCursor); e != nil {
			return e
		}
	}
	if peer != nil {
		if _, e = tx.ExecContext(ctx, `INSERT INTO net_peers(url,node,name,epoch,cursor,success,error) VALUES(?,?,?,?,?,?, '') ON CONFLICT(url) DO UPDATE SET node=excluded.node,name=excluded.name,epoch=excluded.epoch,cursor=excluded.cursor,success=excluded.success,error=''`, peer.URL, peer.Node, peer.Name, peer.Epoch, peer.Cursor, now.Unix()); e != nil {
			return e
		}
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	*changed = seq != originalSequence
	return nil
}

const ipColumns = "ip,packets,bytes,tcp,syn,udp,icmp,first,last,peak,evidence,partial"

func scanIPState(row interface{ Scan(...any) error }) (observation.IP, observation.Evidence, error) {
	var ip observation.IP
	var raw []byte
	e := row.Scan(&ip.IP, &ip.Packets, &ip.Bytes, &ip.TCP, &ip.SYN, &ip.UDP, &ip.ICMP, &ip.First, &ip.Last, &ip.PeakPPS, &raw, &ip.Partial)
	if e != nil {
		return ip, observation.Evidence{}, e
	}
	var state ipState
	if e := json.Unmarshal(raw, &state); e != nil {
		return ip, observation.Evidence{}, e
	}
	if state.Traffic != nil {
		ip.Traffic = *state.Traffic
	} else {
		ip.Traffic = observation.Traffic{Unknown: ip.Packets}
	}
	ip.Correlation = state.Correlation
	return ip, state.Evidence, nil
}

func scanIP(row interface{ Scan(...any) error }, policy observation.Policy, now time.Time) (observation.IP, error) {
	ip, evidence, e := scanIPState(row)
	if e != nil {
		return ip, e
	}
	ip.Score, ip.Reasons = policy.Score(evidence, now)
	ip.IntensityScore = ip.Score
	ip.EvidenceAt = evidence.At
	if correlated := ip.Correlation.Decay(policy, now); correlated > ip.Score {
		ip.Score = correlated
		ip.EvidenceAt = ip.Correlation.At
		ip.Reasons = append(ip.Reasons, ip.Correlation.Reason+"; incident "+ip.Correlation.ID)
	}
	return ip, nil
}
func rank(sort string) (string, error) {
	switch sort {
	case "score":
		return "priority", nil
	case "total", "packets":
		return "packets", nil
	case "bytes":
		return "bytes", nil
	case "syn":
		return "syn", nil
	}
	return "", errors.New("network sort must be score, total, bytes, or syn")
}
func (s *disk) View(ctx context.Context, sort string, limit int) ([]observation.IP, observation.Totals, error) {
	col, e := rank(sort)
	if e != nil {
		return nil, observation.Totals{}, e
	}
	if limit < 1 || limit > 1000 {
		return nil, observation.Totals{}, errors.New("network top limit must be 1..1000")
	}
	tx, e := s.r.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return nil, observation.Totals{}, e
	}
	defer tx.Rollback()
	totals, e := readTotals(ctx, tx)
	if e != nil {
		return nil, totals, e
	}
	rows, e := tx.QueryContext(ctx, "SELECT "+ipColumns+" FROM net_ips ORDER BY "+col+" DESC,ip LIMIT ?", limit)
	if e != nil {
		return nil, totals, e
	}
	defer rows.Close()
	var result []observation.IP
	for rows.Next() {
		row, err := scanIP(rows, s.policy, time.Now())
		if err != nil {
			return nil, totals, err
		}
		result = append(result, row)
	}
	return result, totals, rows.Err()
}
func (s *disk) Show(ctx context.Context, ip string) (observation.IP, error) {
	addr, e := netip.ParseAddr(ip)
	if e != nil {
		return observation.IP{}, e
	}
	return scanIP(s.r.DB.QueryRowContext(ctx, "SELECT "+ipColumns+" FROM net_ips WHERE ip=?", addr.Unmap().String()), s.policy, time.Now())
}
func (s *disk) Page(ctx context.Context, epoch string, after int64) (Page, error) {
	page := Page{Epoch: s.epoch}
	if after < 0 {
		return page, errors.New("negative cursor")
	}
	tx, e := s.r.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return page, e
	}
	defer tx.Rollback()
	if e = tx.QueryRowContext(ctx, "SELECT sequence FROM net_meta WHERE id=1").Scan(&page.Head); e != nil {
		return page, e
	}
	if epoch != s.epoch {
		after = 0
	}
	if after > page.Head {
		return page, errors.New("peer restored an older replica; rebuild its network database")
	}
	if e = tx.QueryRowContext(ctx, "SELECT floor FROM net_storage WHERE id=1").Scan(&page.Floor); e != nil {
		return page, e
	}
	minimum := page.Floor
	if s.retention > 0 {
		minimum = max(minimum, time.Now().Add(-s.retention).Unix()-59)
	}
	query := "SELECT 0 AS kind," + sampleColumns + ",version FROM net_observations WHERE version>? AND version<=? AND window>=?"
	args := []any{after, page.Head, minimum}
	if s.journal {
		query += " UNION ALL SELECT 1,id,'',ip,bucket,payload,version FROM net_incidents WHERE version>? AND version<=? AND last>=?"
		args = append(args, after, page.Head, minimum)
	}
	query += " ORDER BY version LIMIT 128"
	rows, e := tx.QueryContext(ctx, query, args...)
	if e != nil {
		return page, e
	}
	defer rows.Close()
	page.Cursor = after
	size := 0
	count := 0
	for rows.Next() {
		var kind int
		var id, node, ip string
		var window, version int64
		var raw, wire []byte
		if e = rows.Scan(&kind, &id, &node, &ip, &window, &raw, &version); e != nil {
			return page, e
		}
		if kind == 0 {
			v, e := decodeSample(id, node, ip, window, raw)
			if e != nil {
				return page, e
			}
			wire, _ = json.Marshal(v)
			if size+len(wire) > 1<<20 && count > 0 {
				return page, nil
			}
			page.Samples = append(page.Samples, v)
		} else {
			v, e := decodeIncident(raw)
			if e != nil {
				return page, e
			}
			wire, _ = json.Marshal(v)
			if size+len(wire) > 1<<20 && count > 0 {
				return page, nil
			}
			page.Incidents = append(page.Incidents, v)
		}
		size += len(wire)
		count++
		page.Cursor = version
	}
	if e = rows.Err(); e != nil {
		return page, e
	}
	if count < 128 {
		page.Cursor = page.Head
	}
	return page, nil
}
func (s *disk) Prune(ctx context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.w.EnsureWAL(ctx); e != nil {
		return 0, e
	}
	return s.pruneLocked(ctx, false)
}

// capacityPressure reserves at most 256 KiB (5% for small databases). Ordinary
// writes still have SQLite's hard max_page_count guard; WAL is bounded separately.
func (s *disk) capacityPressure(ctx context.Context) (bool, error) {
	var count, free, limit, size int64
	for q, dst := range map[string]*int64{"PRAGMA page_count": &count, "PRAGMA freelist_count": &free, "PRAGMA max_page_count": &limit, "PRAGMA page_size": &size} {
		if e := s.w.DB.QueryRowContext(ctx, q).Scan(dst); e != nil {
			return false, e
		}
	}
	reserve := min(int64(256<<10)/size, max(int64(1), limit/20))
	return count-free >= limit-reserve, nil
}
func (s *disk) pruneLocked(ctx context.Context, capacity bool) (int, error) {
	tx, e := s.w.DB.BeginTx(ctx, nil)
	if e != nil {
		return 0, e
	}
	defer tx.Rollback()
	var floor int64
	if e = tx.QueryRowContext(ctx, "SELECT floor FROM net_storage WHERE id=1").Scan(&floor); e != nil {
		return 0, e
	}
	minimum := floor
	if s.retention > 0 {
		minimum = max(minimum, time.Now().Add(-s.retention).Unix()-59)
	}
	if capacity {
		var oldest int64
		oldestQuery := "SELECT min(window) FROM net_observations"
		if s.journal {
			oldestQuery = "SELECT min(t) FROM (SELECT min(window) t FROM net_observations UNION ALL SELECT min(last/60*60) t FROM net_incidents)"
		}
		var oldestValue sql.NullInt64
		e = tx.QueryRowContext(ctx, oldestQuery).Scan(&oldestValue)
		if e == nil && !oldestValue.Valid {
			return 0, nil
		}
		oldest = oldestValue.Int64
		if errors.Is(e, sql.ErrNoRows) {
			return 0, nil
		}
		if e != nil {
			return 0, e
		}
		if oldest >= minimum {
			// Never expire the still-active capture minute. If a single minute cannot
			// fit, keep the bounded queue/backpressure visible until a minute is eligible.
			if oldest >= time.Now().Unix()/60*60 {
				return 0, nil
			}
			minimum = oldest + 60
			floor = max(floor, minimum)
			if _, e = tx.ExecContext(ctx, "UPDATE net_storage SET floor=? WHERE id=1", floor); e != nil {
				return 0, e
			}
			if _, e = tx.ExecContext(ctx, "UPDATE net_meta SET sequence=sequence+1 WHERE id=1"); e != nil {
				return 0, e
			}
		}
	}
	removedEvents := 0
	if s.journal {
		eventRows, err := tx.QueryContext(ctx, "SELECT id,ip FROM net_incidents WHERE last<? ORDER BY last,id LIMIT 128", minimum)
		if err != nil {
			return 0, err
		}
		var ids []string
		eventIPs := map[string]bool{}
		for eventRows.Next() {
			var id, ip string
			if err = eventRows.Scan(&id, &ip); err != nil {
				eventRows.Close()
				return 0, err
			}
			ids = append(ids, id)
			eventIPs[ip] = true
		}
		err = eventRows.Err()
		eventRows.Close()
		if err != nil {
			return 0, err
		}
		for _, id := range ids {
			if _, err = tx.ExecContext(ctx, "DELETE FROM net_incidents WHERE id=?", id); err != nil {
				return 0, err
			}
		}
		removedEvents = len(ids)
		for ip := range eventIPs {
			if err = refreshCorrelation(ctx, tx, ip, s.policy); err != nil {
				return 0, err
			}
		}
	}
	rows, e := tx.QueryContext(ctx, "SELECT "+sampleColumns+" FROM net_observations WHERE window<? ORDER BY window,id LIMIT 128", minimum)
	if e != nil {
		return 0, e
	}
	var ids []string
	expired := map[string]observation.Counters{}
	expiredTraffic := map[string]observation.Traffic{}
	for rows.Next() {
		item, err := scanSample(rows)
		if err != nil {
			rows.Close()
			return 0, err
		}
		ids = append(ids, item.ID)
		expired[item.IP] = expired[item.IP].Plus(item.Counters)
		expiredTraffic[item.IP] = expiredTraffic[item.IP].Plus(item.Traffic())
	}

	e = rows.Err()
	rows.Close()
	if e != nil {
		return 0, e
	}
	if len(ids) == 0 {
		return removedEvents, tx.Commit()
	}
	totals, e := readTotals(ctx, tx)
	if e != nil {
		return 0, e
	}
	for _, id := range ids {
		if _, e = tx.ExecContext(ctx, "DELETE FROM net_observations WHERE id=?", id); e != nil {
			return 0, e
		}
	}
	for ip, removed := range expired {
		row, _, err := scanIPState(tx.QueryRowContext(ctx, "SELECT "+ipColumns+" FROM net_ips WHERE ip=?", ip))
		if err != nil {
			return 0, err
		}
		next := row.Counters.Minus(removed)
		totals.Counters = totals.Counters.Minus(row.Counters)
		totals.Counters = totals.Counters.Plus(next)
		best, err := scanSample(tx.QueryRowContext(ctx, "SELECT "+sampleColumns+" FROM net_observations WHERE ip=? ORDER BY priority DESC LIMIT 1", ip))
		if errors.Is(err, sql.ErrNoRows) {
			totals.IPs--
			if _, e = tx.ExecContext(ctx, "DELETE FROM net_ips WHERE ip=?", ip); e != nil {
				return 0, e
			}
			continue
		}
		if err != nil {
			return 0, err
		}
		correlation, e := loadCorrelation(ctx, tx, ip)
		if e != nil {
			return 0, e
		}
		risk := marshalIPState(best.Evidence, row.Traffic.Minus(expiredTraffic[ip]), correlation)
		if _, e = tx.ExecContext(ctx, "UPDATE net_ips SET packets=?,bytes=?,tcp=?,syn=?,udp=?,icmp=?,evidence=?,priority=? WHERE ip=?", next.Packets, next.Bytes, next.TCP, next.SYN, next.UDP, next.ICMP, risk, max(s.policy.Priority(best.Evidence), correlation.Priority(s.policy)), ip); e != nil {
			return 0, e
		}
	}
	if e = writeTotals(ctx, tx, totals); e != nil {
		return 0, e
	}
	if _, e = tx.ExecContext(ctx, "UPDATE net_storage SET evicted=evicted+? WHERE id=1", len(ids)); e != nil {
		return 0, e
	}
	return len(ids) + removedEvents, tx.Commit()
}
func readTotals(ctx context.Context, db interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}) (observation.Totals, error) {
	var t observation.Totals
	e := db.QueryRowContext(ctx, "SELECT ips,packets,bytes,tcp,syn,udp,icmp FROM net_totals WHERE id=1").Scan(&t.IPs, &t.Packets, &t.Bytes, &t.TCP, &t.SYN, &t.UDP, &t.ICMP)
	return t, e
}
func writeTotals(ctx context.Context, tx *sql.Tx, t observation.Totals) error {
	_, e := tx.ExecContext(ctx, "UPDATE net_totals SET ips=?,packets=?,bytes=?,tcp=?,syn=?,udp=?,icmp=? WHERE id=1", t.IPs, t.Packets, t.Bytes, t.TCP, t.SYN, t.UDP, t.ICMP)
	return e
}
func (s *disk) Peers(ctx context.Context) ([]Peer, error) {
	rows, e := s.r.DB.QueryContext(ctx, "SELECT url,node,name,epoch,cursor,success,error FROM net_peers ORDER BY url")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var peers []Peer
	for rows.Next() {
		var p Peer
		if e = rows.Scan(&p.URL, &p.Node, &p.Name, &p.Epoch, &p.Cursor, &p.Success, &p.Error); e != nil {
			return nil, e
		}
		peers = append(peers, p)
	}
	return peers, rows.Err()
}
func (s *disk) SavePeer(ctx context.Context, p Peer) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.w.EnsureWAL(ctx); e != nil {
		return e
	}
	_, e := s.w.DB.ExecContext(ctx, `INSERT INTO net_peers(url,node,name,epoch,cursor,success,error) VALUES(?,?,?,?,?,?,?) ON CONFLICT(url) DO UPDATE SET node=excluded.node,name=excluded.name,epoch=excluded.epoch,cursor=excluded.cursor,success=excluded.success,error=excluded.error`, p.URL, p.Node, p.Name, p.Epoch, p.Cursor, p.Success, p.Error)
	return e
}
func limitedError(e error) string {
	if e == nil {
		return ""
	}
	return limitedText(e.Error())
}
func limitedText(value string) string {
	s := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return '?'
		}
		return r
	}, value)
	if len(s) > 256 {
		s = s[:256]
	}
	return s
}
