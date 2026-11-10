package store

import (
	"math"
	"net/netip"
	"path/filepath"
	"testing"
)

func openTest(t *testing.T, path string) *Store {
	t.Helper()
	s, e := Open(path, true, 1, 1)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	return s
}
func TestPersistenceWALAndSaturation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stats.db")
	s := openTest(t, path)
	ip := netip.MustParseAddr("192.0.2.1")
	b := map[netip.Addr]Delta{}
	Add(b, ip, 5, 200)
	Add(b, ip, 2, 100)
	if e := s.Flush(b); e != nil {
		t.Fatal(e)
	}
	ro, e := Open(path, false, 0, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer ro.Close()
	tx, e := ro.DB.Begin()
	if e != nil {
		t.Fatal(e)
	}
	c, e := Scan(tx.QueryRow("SELECT ip,requests,first_seen,last_seen FROM clients"))
	if e != nil {
		t.Fatal(e)
	}
	if c.Requests != 7 || c.First != 100 || c.Last != 200 {
		t.Fatal(c)
	}
	if e = s.Flush(map[netip.Addr]Delta{ip: {math.MaxInt64, 50, 300}}); e != nil {
		t.Fatal(e)
	}
	c, e = Scan(tx.QueryRow("SELECT ip,requests,first_seen,last_seen FROM clients"))
	if e != nil || c.Requests != 7 {
		t.Fatal(c, e)
	}
	tx.Rollback()
	s.Close()
	s = openTest(t, path)
	c, e = Scan(s.DB.QueryRow("SELECT ip,requests,first_seen,last_seen FROM clients"))
	if e != nil {
		t.Fatal(e)
	}
	if c.Requests != math.MaxInt64 || c.First != 50 || c.Last != 300 {
		t.Fatal(c)
	}
	var count int
	s.DB.QueryRow("SELECT count(*) FROM clients").Scan(&count)
	if count != 1 {
		t.Fatal(count)
	}
	if _, e = ro.DB.Exec("DELETE FROM clients"); e == nil {
		t.Fatal("read client modified database")
	}
}
func TestDatabaseLimitRollsBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stats.db")
	s := openTest(t, path)
	ip := netip.MustParseAddr("192.0.2.1")
	if e := s.Flush(map[netip.Addr]Delta{ip: {5, 1, 2}}); e != nil {
		t.Fatal(e)
	}
	b := map[netip.Addr]Delta{}
	for i := 0; i < 30000; i++ {
		a := [16]byte{0x20, 1, 0xd, 0xb8}
		a[12] = byte(i >> 16)
		a[13] = byte(i >> 8)
		a[14] = byte(i)
		b[netip.AddrFrom16(a)] = Delta{1, 1, 1}
	}
	if e := s.Flush(b); e == nil {
		t.Fatal("expected configured page limit")
	}
	var count, requests int
	s.DB.QueryRow("SELECT count(*),sum(requests) FROM clients").Scan(&count, &requests)
	if count != 1 || requests != 5 {
		t.Fatal("transaction was not rolled back", count, requests)
	}
}
func TestAddSaturates(t *testing.T) {
	b := map[netip.Addr]Delta{}
	ip := netip.MustParseAddr("::1")
	Add(b, ip, math.MaxInt64, 1)
	Add(b, ip, 1, 2)
	if b[ip].Requests != math.MaxInt64 {
		t.Fatal(b)
	}
}
