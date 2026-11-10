package store

import (
	"container/heap"
	"context"
	"database/sql"
	"fmt"
	"math"
	"math/big"
	"net/netip"
	"sort"
	"strings"
)

// Totals is cached once at startup and maintained by committed batches. No
// additional tables or per-request database work are needed for the live view.
type Totals struct {
	Unique   int64  `json:"unique_ips"`
	Requests string `json:"requests"`
	First    int64  `json:"first_seen"`
	Last     int64  `json:"last_seen"`
}
type Change struct {
	NewClients  int64
	Added       string
	First, Last int64
}

func (t Totals) With(c Change) Totals {
	n := new(big.Int)
	n.SetString(t.Requests, 10)
	d := new(big.Int)
	d.SetString(c.Added, 10)
	n.Add(n, d)
	t.Requests = n.String()
	t.Unique += c.NewClients
	if c.First != 0 && (t.First == 0 || c.First < t.First) {
		t.First = c.First
	}
	if c.Last > t.Last {
		t.Last = c.Last
	}
	return t
}
func (s *Store) Totals(ctx context.Context) (Totals, error) { return readTotals(ctx, s.DB) }

func readTotals(ctx context.Context, q interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}) (Totals, error) {
	t := Totals{Requests: "0"}
	n := new(big.Int)
	rows, e := q.QueryContext(ctx, "SELECT requests,first_seen,last_seen FROM clients")
	if e != nil {
		return t, e
	}
	defer rows.Close()
	for rows.Next() {
		var count, f, l int64
		if e = rows.Scan(&count, &f, &l); e != nil {
			return t, e
		}
		t.Unique++
		n.Add(n, big.NewInt(count))
		if t.Unique == 1 || f < t.First {
			t.First = f
		}
		if l > t.Last {
			t.Last = l
		}
	}
	t.Requests = n.String()
	return t, rows.Err()
}
func Apply(c Client, ip string, d Delta) Client {
	if c.IP == "" {
		return Client{ip, d.Requests, d.First, d.Last}
	}
	if c.Requests > math.MaxInt64-d.Requests {
		c.Requests = math.MaxInt64
	} else {
		c.Requests += d.Requests
	}
	if d.First < c.First {
		c.First = d.First
	}
	if d.Last > c.Last {
		c.Last = d.Last
	}
	return c
}
func changes(existing map[string]Client, batch map[netip.Addr]Delta) Change {
	c := Change{Added: "0"}
	n := new(big.Int)
	for ip, d := range batch {
		old := existing[ip.String()]
		next := Apply(old, ip.String(), d)
		if old.IP == "" {
			c.NewClients++
		}
		n.Add(n, big.NewInt(next.Requests-old.Requests))
		if c.First == 0 || next.First < c.First {
			c.First = next.First
		}
		if next.Last > c.Last {
			c.Last = next.Last
		}
	}
	c.Added = n.String()
	return c
}
func lookup(ctx context.Context, tx *sql.Tx, batch map[netip.Addr]Delta) (map[string]Client, error) {
	result := make(map[string]Client, len(batch))
	args := make([]any, 0, 400)
	query := func() error {
		if len(args) == 0 {
			return nil
		}
		q := "SELECT ip,requests,first_seen,last_seen FROM clients WHERE ip IN (" + strings.TrimSuffix(strings.Repeat("?,", len(args)), ",") + ")"
		rows, e := tx.QueryContext(ctx, q, args...)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			c, err := Scan(rows)
			if err != nil {
				return err
			}
			result[c.IP] = c
		}
		return rows.Err()
	}
	for ip := range batch {
		args = append(args, ip.String())
		if len(args) == cap(args) {
			if e := query(); e != nil {
				return nil, e
			}
			args = args[:0]
		}
	}
	if e := query(); e != nil {
		return nil, e
	}
	return result, nil
}

type clientHeap []Client

func (h clientHeap) Len() int           { return len(h) }
func (h clientHeap) Less(i, j int) bool { return better(h[j], h[i]) }
func (h clientHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *clientHeap) Push(v any)        { *h = append(*h, v.(Client)) }
func (h *clientHeap) Pop() any          { a := *h; v := a[len(a)-1]; *h = a[:len(a)-1]; return v }
func better(a, b Client) bool {
	if a.Requests != b.Requests {
		return a.Requests > b.Requests
	}
	return a.IP < b.IP
}

// View merges durable rows with bounded, volatile deltas. Caller coordinates
// with the writer to prevent observing a commit and its in-flight delta twice.
func (s *Store) View(ctx context.Context, limit int, overlay map[netip.Addr]Delta, base Totals) ([]Client, Totals, error) {
	if limit < 1 || limit > 1000 {
		return nil, base, fmt.Errorf("live view limit must be 1..1000")
	}
	tx, e := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return nil, base, e
	}
	defer tx.Rollback()
	rows, e := tx.QueryContext(ctx, "SELECT ip,requests,first_seen,last_seen FROM clients ORDER BY requests DESC,ip ASC LIMIT ?", limit)
	if e != nil {
		return nil, base, e
	}
	candidates := make(map[string]Client, limit+len(overlay))
	for rows.Next() {
		c, err := Scan(rows)
		if err != nil {
			rows.Close()
			return nil, base, err
		}
		candidates[c.IP] = c
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, base, e
	}
	existing, e := lookup(ctx, tx, overlay)
	if e != nil {
		return nil, base, e
	}
	for ip, d := range overlay {
		key := ip.String()
		candidates[key] = Apply(existing[key], key, d)
	}
	h := &clientHeap{}
	heap.Init(h)
	for _, c := range candidates {
		if h.Len() < limit {
			heap.Push(h, c)
		} else if better(c, (*h)[0]) {
			(*h)[0] = c
			heap.Fix(h, 0)
		}
	}
	result := []Client(*h)
	sort.Slice(result, func(i, j int) bool { return better(result[i], result[j]) })
	return result, base.With(changes(existing, overlay)), nil
}

// StoredView returns a single coherent WAL snapshot when the daemon is offline.
func (s *Store) StoredView(ctx context.Context, limit int) ([]Client, Totals, error) {
	tx, e := s.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return nil, Totals{}, e
	}
	defer tx.Rollback()
	total, e := readTotals(ctx, tx)
	if e != nil {
		return nil, total, e
	}
	rows, e := tx.QueryContext(ctx, "SELECT ip,requests,first_seen,last_seen FROM clients ORDER BY requests DESC,ip ASC LIMIT ?", limit)
	if e != nil {
		return nil, total, e
	}
	defer rows.Close()
	result := make([]Client, 0, limit)
	for rows.Next() {
		c, err := Scan(rows)
		if err != nil {
			return nil, total, err
		}
		result = append(result, c)
	}
	return result, total, rows.Err()
}
