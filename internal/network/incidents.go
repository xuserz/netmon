package network

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"time"

	"netmon/internal/config"
	"netmon/internal/observation"
)

type incidentEncoder struct {
	writer *gzip.Writer
	output bytes.Buffer
}

func (encoder *incidentEncoder) encode(canonical []byte) ([]byte, error) {
	if encoder.writer == nil {
		encoder.writer = gzip.NewWriter(&encoder.output)
	} else {
		encoder.writer.Reset(&encoder.output)
	}
	// Detach the returned bytes from the encoder before the next incident.
	defer func() { encoder.output = bytes.Buffer{} }()
	if _, e := encoder.writer.Write(append(canonical, '\n')); e != nil {
		return nil, e
	}
	if e := encoder.writer.Close(); e != nil {
		return nil, e
	}
	return encoder.output.Bytes(), nil
}
func decodeIncident(raw []byte) (observation.Incident, error) {
	var v observation.Incident
	if len(raw) > 256<<10 {
		return v, errors.New("incident payload exceeds limit")
	}
	g, e := gzip.NewReader(bytes.NewReader(raw))
	if e != nil {
		return v, e
	}
	defer g.Close()
	data, e := io.ReadAll(io.LimitReader(g, (1<<20)+1))
	if e != nil {
		return v, e
	}
	if len(data) > 1<<20 {
		return v, errors.New("expanded incident payload exceeds limit")
	}
	e = json.Unmarshal(data, &v)
	return v, e
}
func normalizeIncident(v observation.Incident, p observation.Policy) (observation.Incident, error) {
	addr, e := netip.ParseAddr(v.IP)
	if e != nil || addr.Zone() != "" || addr.Unmap().String() != v.IP || len(v.Facts) == 0 || len(v.Facts) > observation.MaxFacts {
		return v, errors.New("invalid incident source")
	}
	facts, partial, e := observation.CombineFacts(nil, v.Facts)
	if e != nil {
		return v, e
	}
	out, eligible, e := observation.BuildIncident(v.IP, v.Kind, v.Bucket, facts, p)
	if e != nil {
		return v, e
	}
	out.Partial = out.Partial || v.Partial || partial
	if out.ID != v.ID || out.Last > time.Now().Unix()+300 {
		return v, errors.New("invalid incident identity/time")
	}
	if !eligible {
		if !out.Partial {
			return v, errors.New("incident evidence does not meet detection threshold")
		}
		out.Score = 0
		out.Reason = "incomplete capped evidence; original detection threshold cannot be reconstructed"
	}
	return out, nil
}
func incidentFloor(retention time.Duration, floor int64) int64 {
	if retention > 0 {
		return max(floor, time.Now().Add(-retention).Unix()-59)
	}
	return floor
}
func (s *disk) writeIncident(ctx context.Context, tx *sql.Tx, v observation.Incident, seq *int64, floor int64) error {
	if v.Last < floor {
		return nil
	}
	var oldRaw, oldCanonical []byte
	e := tx.QueryRowContext(ctx, "SELECT payload FROM net_incidents WHERE id=?", v.ID).Scan(&oldRaw)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	if e == nil {
		old, e := decodeIncident(oldRaw)
		oldCanonical, _ = json.Marshal(old)
		if e != nil {
			return e
		}
		facts, partial, e := observation.CombineFacts(old.Facts, v.Facts)
		if e != nil {
			return e
		}
		v.Facts = facts
		v.Partial = v.Partial || old.Partial || partial
	}
	next, e := normalizeIncident(v, s.policy)
	if e != nil {
		return e
	}
	canonical, e := json.Marshal(next)
	if e != nil {
		return e
	}
	if bytes.Equal(oldCanonical, canonical) {
		return nil
	}
	raw, e := s.encoder.encode(canonical)
	if e != nil {
		return e
	}
	*seq++
	_, e = tx.ExecContext(ctx, `INSERT INTO net_incidents VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET last=excluded.last,version=excluded.version,priority=excluded.priority,payload=excluded.payload`, next.ID, next.IP, next.Kind, next.Bucket, next.Last, *seq, (&observation.Correlation{Score: next.Score, At: next.Last}).Priority(s.policy), raw)
	return e
}
func loadCorrelation(ctx context.Context, tx *sql.Tx, ip string) (*observation.Correlation, error) {
	var raw []byte
	e := tx.QueryRowContext(ctx, "SELECT payload FROM net_incidents WHERE ip=? ORDER BY priority DESC,id LIMIT 1", ip).Scan(&raw)
	if errors.Is(e, sql.ErrNoRows) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	v, e := decodeIncident(raw)
	if e != nil {
		return nil, e
	}
	return &observation.Correlation{ID: v.ID, Score: v.Score, At: v.Last, Reason: v.Reason}, nil
}
func refreshCorrelation(ctx context.Context, tx *sql.Tx, ip string, p observation.Policy) error {
	row, evidence, e := scanIPState(tx.QueryRowContext(ctx, "SELECT "+ipColumns+" FROM net_ips WHERE ip=?", ip))
	if errors.Is(e, sql.ErrNoRows) {
		return nil
	}
	if e != nil {
		return e
	}
	correlation, e := loadCorrelation(ctx, tx, ip)
	if e != nil {
		return e
	}
	_, e = tx.ExecContext(ctx, "UPDATE net_ips SET evidence=?,priority=? WHERE ip=?", marshalIPState(evidence, row.Traffic, correlation), max(p.Priority(evidence), correlation.Priority(p)), ip)
	return e
}

const advanceAnalysisSQL = "UPDATE net_analysis SET sequence=?1 WHERE id=1 AND sequence<?1"

func (s *disk) advanceAnalysis(ctx context.Context, cursor int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.w.DB.ExecContext(ctx, advanceAnalysisSQL, cursor)
	return err
}

// Analyze follows committed observation versions outside capture. Each window's
// journal entries and analysis cursor commit together.
func (s *disk) Analyze(ctx context.Context, limit int) (int, error) {
	if !s.journal {
		return 0, nil
	}
	if limit < 1 || limit > 128 {
		return 0, errors.New("analysis batch must be 1..128")
	}
	var after, head int64
	if e := s.r.DB.QueryRowContext(ctx, "SELECT a.sequence,m.sequence FROM net_analysis a JOIN net_meta m ON a.id=m.id WHERE a.id=1").Scan(&after, &head); e != nil {
		return 0, e
	}
	if after >= head {
		return 0, nil
	}
	rows, e := s.r.DB.QueryContext(ctx, "SELECT "+sampleColumns+",version FROM net_observations WHERE version>? AND version<=? ORDER BY version LIMIT ?", after, head, limit)
	if e != nil {
		return 0, e
	}
	type window struct {
		ip     string
		bucket int64
	}
	type job struct {
		window
		version int64
	}
	var windows []job
	seen := map[window]bool{}
	cursor := after
	count := 0
	for rows.Next() {
		var id, node, ip string
		var minute, version int64
		var raw []byte
		if e = rows.Scan(&id, &node, &ip, &minute, &raw, &version); e != nil {
			rows.Close()
			return 0, e
		}
		v, e := decodeSample(id, node, ip, minute, raw)
		if e != nil {
			rows.Close()
			return 0, e
		}
		cursor = version
		count++
		if v.SYN == 0 && v.Evidence.PPS < s.policy.PPS*4 && v.Evidence.SYN < s.policy.SYN*4 {
			continue
		}
		w := window{v.IP, v.Window / observation.IncidentWindow * observation.IncidentWindow}
		if !seen[w] {
			seen[w] = true
			windows = append(windows, job{w, version})
		}
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return 0, e
	}
	if count < limit {
		cursor = head
	}
	if len(windows) == 0 {
		if e := s.advanceAnalysis(ctx, cursor); e != nil {
			return 0, e
		}
		return count, nil
	}
	for i, w := range windows {
		facts, partial, e := s.windowFacts(ctx, w.ip, w.bucket)
		if e != nil {
			return 0, e
		}
		incidents, e := observation.BuildIncidents(w.ip, w.bucket, facts, s.policy)
		if e != nil {
			return 0, e
		}
		for j := range incidents {
			incidents[j].Partial = incidents[j].Partial || partial
		}
		checkpoint := w.version
		if i == len(windows)-1 {
			checkpoint = cursor
		}
		if len(incidents) == 0 {
			e = s.advanceAnalysis(ctx, checkpoint)
		} else {
			e = s.mergeBatch(ctx, nil, nil, 0, incidents, checkpoint)
		}
		if e != nil {
			return 0, e
		}
	}
	return count, nil
}
func (s *disk) windowFacts(ctx context.Context, ip string, bucket int64) ([]observation.Fact, bool, error) {
	rows, e := s.r.DB.QueryContext(ctx, "SELECT "+sampleColumns+" FROM net_observations WHERE ip=? AND window>=? AND window<? ORDER BY node,window,id LIMIT 20001", ip, bucket, bucket+observation.IncidentWindow)
	if e != nil {
		return nil, false, e
	}
	defer rows.Close()
	var facts []observation.Fact
	count := 0
	for rows.Next() {
		count++
		if count > 20000 {
			break
		}
		v, e := scanSample(rows)
		if e != nil {
			return nil, false, e
		}
		if v.SYN > 0 || v.Evidence.PPS >= s.policy.PPS*4 || v.Evidence.SYN >= s.policy.SYN*4 {
			facts = append(facts, observation.SampleFact(v))
		}
	}
	if e = rows.Err(); e != nil {
		return nil, false, e
	}
	rows.Close()
	facts, partial, e := observation.CombineFacts(nil, facts)
	var floor int64
	if err := s.r.DB.QueryRowContext(ctx, "SELECT floor FROM net_storage WHERE id=1").Scan(&floor); err != nil {
		return nil, false, err
	}
	return facts, partial || count > 20000 || floor > bucket, e
}
func ReadIncidents(ctx context.Context, c config.Config, ip, id string, since int64, limit int) ([]observation.Incident, error) {
	if c.Storage.Mode != "full" {
		return nil, errors.New("incident history is stored on full nodes; inspect a full node")
	}
	s, e := openDisk(c, false)
	if e != nil {
		return nil, e
	}
	defer s.Close()
	return s.Incidents(ctx, ip, id, since, limit)
}
func (s *disk) Incidents(ctx context.Context, ip, id string, since int64, limit int) ([]observation.Incident, error) {
	if limit < 1 || limit > 1000 {
		return nil, errors.New("incident limit must be 1..1000")
	}
	if !s.journal {
		return nil, nil
	}
	q := "SELECT payload FROM net_incidents WHERE last>=?"
	args := []any{since}
	if ip != "" {
		q += " AND ip=?"
		args = append(args, ip)
	}
	if id != "" {
		q += " AND id=?"
		args = append(args, id)
	}
	q += " ORDER BY last DESC,id LIMIT ?"
	args = append(args, limit)
	rows, e := s.r.DB.QueryContext(ctx, q, args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []observation.Incident{}
	for rows.Next() {
		var raw []byte
		if e = rows.Scan(&raw); e != nil {
			return nil, e
		}
		v, e := decodeIncident(raw)
		if e != nil {
			return nil, fmt.Errorf("incident decode: %w", e)
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
