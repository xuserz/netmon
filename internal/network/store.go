package network

import (
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
	w, r        *store.Store
	mu          sync.Mutex
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
	Epoch   string               `json:"epoch"`
	Cursor  int64                `json:"cursor"`
	Head    int64                `json:"head"`
	Samples []observation.Sample `json:"samples"`
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
			`CREATE TABLE IF NOT EXISTS net_totals(id INTEGER PRIMARY KEY CHECK(id=1),ips INTEGER NOT NULL,packets INTEGER NOT NULL,bytes INTEGER NOT NULL,tcp INTEGER NOT NULL,syn INTEGER NOT NULL,udp INTEGER NOT NULL,icmp INTEGER NOT NULL)`,
			`INSERT OR IGNORE INTO net_totals VALUES(1,0,0,0,0,0,0,0)`,
			`CREATE TABLE IF NOT EXISTS net_ips(ip TEXT PRIMARY KEY,packets INTEGER NOT NULL,bytes INTEGER NOT NULL,tcp INTEGER NOT NULL,syn INTEGER NOT NULL,udp INTEGER NOT NULL,icmp INTEGER NOT NULL,first INTEGER NOT NULL,last INTEGER NOT NULL,peak INTEGER NOT NULL,evidence BLOB NOT NULL,priority REAL NOT NULL,partial INTEGER NOT NULL) WITHOUT ROWID`,
			`CREATE INDEX IF NOT EXISTS net_rank_score ON net_ips(priority DESC,ip)`,
			`CREATE INDEX IF NOT EXISTS net_rank_packets ON net_ips(packets DESC,ip)`,
			`CREATE INDEX IF NOT EXISTS net_rank_bytes ON net_ips(bytes DESC,ip)`,
			`CREATE INDEX IF NOT EXISTS net_rank_syn ON net_ips(syn DESC,ip)`,
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
	if policy != string(expected) || retention != int64(s.retention/time.Second) {
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
	ok = true
	return s, nil
}
func (s *disk) Close() {
	if s.r != s.w {
		s.r.Close()
	}
	s.w.Close()
}
func parseEvidence(raw []byte) (observation.Evidence, error) {
	var e observation.Evidence
	err := json.Unmarshal(raw, &e)
	return e, err
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
	if len(items) > 128 {
		return errors.New("network page exceeds 128 observations")
	}
	now := time.Now()
	filtered := items[:0]
	for _, item := range items {
		if item.Window+60 > now.Add(-s.retention).Unix() {
			filtered = append(filtered, item)
		}
	}
	items = filtered
	for _, item := range items {
		if e := item.Validate(now, s.retention); e != nil {
			return e
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.w.EnsureWAL(ctx); e != nil {
		return e
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
	totals, e := readTotals(ctx, tx)
	if e != nil {
		return e
	}
	queries := []string{
		"SELECT payload FROM net_observations WHERE id=?",
		`INSERT INTO net_observations VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET version=excluded.version,priority=excluded.priority,payload=excluded.payload`,
		"SELECT ip,packets,bytes,tcp,syn,udp,icmp,first,last,peak,evidence,partial FROM net_ips WHERE ip=?",
		`INSERT INTO net_ips VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(ip) DO UPDATE SET packets=excluded.packets,bytes=excluded.bytes,tcp=excluded.tcp,syn=excluded.syn,udp=excluded.udp,icmp=excluded.icmp,first=excluded.first,last=excluded.last,peak=excluded.peak,evidence=excluded.evidence,priority=excluded.priority,partial=excluded.partial`,
	}
	stmts := make([]*sql.Stmt, len(queries))
	for i, q := range queries {
		stmt, err := tx.PrepareContext(ctx, q)
		if err != nil {
			return err
		}
		stmts[i] = stmt
		defer stmt.Close()
	}
	for _, item := range items {
		var raw []byte
		var old observation.Sample
		e = stmts[0].QueryRowContext(ctx, item.ID).Scan(&raw)
		if e != nil && !errors.Is(e, sql.ErrNoRows) {
			return e
		}
		if e == nil {
			if e = json.Unmarshal(raw, &old); e != nil {
				return e
			}
		}
		next, err := mergeSample(old, item, s.policy)
		if err != nil {
			return err
		}
		if e := next.Validate(now, s.retention); e != nil {
			return e
		}
		encoded, _ := json.Marshal(next)
		if string(raw) == string(encoded) {
			continue
		}
		row, evidence, e := scanIP(stmts[2].QueryRowContext(ctx, item.IP), s.policy, now)
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
		ev, _ := json.Marshal(evidence)
		seq++
		if _, e = stmts[1].ExecContext(ctx, next.ID, next.Node, next.IP, next.Window, seq, s.policy.Priority(next.Evidence), encoded); e != nil {
			return e
		}
		if _, e = stmts[3].ExecContext(ctx, row.IP, row.Packets, row.Bytes, row.TCP, row.SYN, row.UDP, row.ICMP, row.First, row.Last, row.PeakPPS, ev, s.policy.Priority(evidence), row.Partial); e != nil {
			return e
		}
	}
	if e = writeTotals(ctx, tx, totals); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, "UPDATE net_meta SET sequence=? WHERE id=1", seq); e != nil {
		return e
	}
	if peer != nil {
		if _, e = tx.ExecContext(ctx, `INSERT INTO net_peers(url,node,name,epoch,cursor,success,error) VALUES(?,?,?,?,?,?, '') ON CONFLICT(url) DO UPDATE SET node=excluded.node,name=excluded.name,epoch=excluded.epoch,cursor=excluded.cursor,success=excluded.success,error=''`, peer.URL, peer.Node, peer.Name, peer.Epoch, peer.Cursor, now.Unix()); e != nil {
			return e
		}
	}
	return tx.Commit()
}

const ipColumns = "ip,packets,bytes,tcp,syn,udp,icmp,first,last,peak,evidence,partial"

func scanIP(row interface{ Scan(...any) error }, policy observation.Policy, now time.Time) (observation.IP, observation.Evidence, error) {
	var ip observation.IP
	var raw []byte
	e := row.Scan(&ip.IP, &ip.Packets, &ip.Bytes, &ip.TCP, &ip.SYN, &ip.UDP, &ip.ICMP, &ip.First, &ip.Last, &ip.PeakPPS, &raw, &ip.Partial)
	if e != nil {
		return ip, observation.Evidence{}, e
	}
	evidence, e := parseEvidence(raw)
	if e != nil {
		return ip, evidence, e
	}
	ip.Score, ip.Reasons = policy.Score(evidence, now)
	ip.EvidenceAt = evidence.At
	return ip, evidence, nil
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
		row, _, err := scanIP(rows, s.policy, time.Now())
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
	row, _, e := scanIP(s.r.DB.QueryRowContext(ctx, "SELECT "+ipColumns+" FROM net_ips WHERE ip=?", addr.Unmap().String()), s.policy, time.Now())
	return row, e
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
	rows, e := tx.QueryContext(ctx, "SELECT payload,version FROM net_observations WHERE version>? AND version<=? AND window>? ORDER BY version LIMIT 128", after, page.Head, time.Now().Add(-s.retention).Unix()-60)
	if e != nil {
		return page, e
	}
	defer rows.Close()
	page.Cursor = after
	size := 0
	for rows.Next() {
		var raw []byte
		var version int64
		if e = rows.Scan(&raw, &version); e != nil {
			return page, e
		}
		if size+len(raw) > 1<<20 && len(page.Samples) > 0 {
			return page, nil
		}
		var sample observation.Sample
		if e = json.Unmarshal(raw, &sample); e != nil {
			return page, e
		}
		page.Samples = append(page.Samples, sample)
		size += len(raw)
		page.Cursor = version
	}
	if e = rows.Err(); e != nil {
		return page, e
	}
	if len(page.Samples) < 128 {
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
	tx, e := s.w.DB.BeginTx(ctx, nil)
	if e != nil {
		return 0, e
	}
	defer tx.Rollback()
	rows, e := tx.QueryContext(ctx, "SELECT id,ip,payload FROM net_observations WHERE window<=? LIMIT 128", time.Now().Add(-s.retention).Unix()-60)
	if e != nil {
		return 0, e
	}
	var ids []string
	expired := map[string]observation.Counters{}
	for rows.Next() {
		var id, ip string
		var raw []byte
		var sample observation.Sample
		if e = rows.Scan(&id, &ip, &raw); e != nil {
			rows.Close()
			return 0, e
		}
		if e = json.Unmarshal(raw, &sample); e != nil {
			rows.Close()
			return 0, e
		}
		ids = append(ids, id)
		expired[ip] = expired[ip].Plus(sample.Counters)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return 0, e
	}
	if len(ids) == 0 {
		return 0, nil
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
		row, _, err := scanIP(tx.QueryRowContext(ctx, "SELECT "+ipColumns+" FROM net_ips WHERE ip=?", ip), s.policy, time.Now())
		if err != nil {
			return 0, err
		}
		next := row.Counters.Minus(removed)
		totals.Counters = totals.Counters.Minus(row.Counters)
		totals.Counters = totals.Counters.Plus(next)
		var raw []byte
		err = tx.QueryRowContext(ctx, "SELECT payload FROM net_observations WHERE ip=? ORDER BY priority DESC LIMIT 1", ip).Scan(&raw)
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
		var best observation.Sample
		if e = json.Unmarshal(raw, &best); e != nil {
			return 0, e
		}
		risk, _ := json.Marshal(best.Evidence)
		if _, e = tx.ExecContext(ctx, "UPDATE net_ips SET packets=?,bytes=?,tcp=?,syn=?,udp=?,icmp=?,evidence=?,priority=? WHERE ip=?", next.Packets, next.Bytes, next.TCP, next.SYN, next.UDP, next.ICMP, risk, s.policy.Priority(best.Evidence), ip); e != nil {
			return 0, e
		}
	}
	if e = writeTotals(ctx, tx, totals); e != nil {
		return 0, e
	}
	return len(ids), tx.Commit()
}
func readTotals(ctx context.Context, tx *sql.Tx) (observation.Totals, error) {
	var t observation.Totals
	e := tx.QueryRowContext(ctx, "SELECT ips,packets,bytes,tcp,syn,udp,icmp FROM net_totals WHERE id=1").Scan(&t.IPs, &t.Packets, &t.Bytes, &t.TCP, &t.SYN, &t.UDP, &t.ICMP)
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
	s := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return '?'
		}
		return r
	}, e.Error())
	if len(s) > 256 {
		s = s[:256]
	}
	return s
}
