package network

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"

	"netmon/internal/config"
	"netmon/internal/observation"
)

func ReadProfile(ctx context.Context, c config.Config, ip string, since, until int64) (observation.Profile, error) {
	if c.Storage.Mode != "full" {
		return observation.Profile{}, errors.New("saved history requires a full node")
	}
	addr, e := netip.ParseAddr(ip)
	if e != nil {
		return observation.Profile{}, e
	}
	s, e := openDisk(c, false)
	if e != nil {
		return observation.Profile{}, e
	}
	defer s.Close()
	return s.Profile(ctx, addr.Unmap().String(), since, until)
}
func (s *disk) Profile(ctx context.Context, ip string, since, until int64) (observation.Profile, error) {
	p := observation.NewProfile(ip, since/60*60, until)
	tx, e := s.r.DB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return p.Profile, e
	}
	defer tx.Rollback()
	var floor int64
	if e = tx.QueryRowContext(ctx, "SELECT floor FROM net_storage WHERE id=1").Scan(&floor); e != nil {
		return p.Profile, e
	}
	if p.Since < incidentFloor(s.retention, floor) {
		p.Partial = true
	}
	rows, e := tx.QueryContext(ctx, "SELECT "+sampleColumns+" FROM net_observations WHERE ip=? AND window>=? AND window<=? ORDER BY window,node,id", ip, p.Since, until/60*60)
	if e != nil {
		return p.Profile, e
	}
	defer rows.Close()
	for rows.Next() {
		if e := ctx.Err(); e != nil {
			return p.Profile, e
		}
		v, e := scanSample(rows)
		if e != nil {
			return p.Profile, e
		}
		p.Add(v)
	}
	if e = rows.Err(); e != nil {
		return p.Profile, e
	}
	return p.Finish(), nil
}
func (c *collector) profile(ip string) *observation.Profile {
	for i, n := int64(0), c.count.Load(); i < n; i++ {
		e := c.slots[i].Load()
		if e == nil || e.ip.String() != ip {
			continue
		}
		s := e.detail.Load()
		if s == nil {
			return nil
		}
		builder := observation.NewProfile(ip, s.Window, s.Last)
		builder.Add(*s)
		p := builder.Finish()
		p.Partial = true
		return &p
	}
	return nil
}
