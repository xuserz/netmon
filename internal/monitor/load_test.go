package monitor

import (
	"context"
	"encoding/binary"
	"fmt"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"netmon/internal/config"
	"netmon/internal/store"
)

// A deterministic full parser/aggregation/SQLite workload. Packet generation is
// in memory; this does NOT benchmark NIC delivery or the AF_PACKET system call.
type generatedSource struct {
	remaining, index int
	cancel           context.CancelFunc
}

func (s *generatedSource) Drops() (uint32, error) { return 0, nil }
func (s *generatedSource) Read(out []byte) (int, error) {
	if s.remaining == 0 {
		s.cancel()
		return 0, nil
	}
	s.remaining--
	s.index++
	p := query(1)
	ip := s.index % 2000
	binary.BigEndian.PutUint32(p[12:16], 0xc0000000+uint32(ip+1))
	if s.index%2 == 0 {
		v6 := make([]byte, 65)
		v6[0] = 0x60
		binary.BigEndian.PutUint16(v6[4:], 25)
		v6[6] = 17
		v6[8] = 0x20
		v6[9] = 1
		binary.BigEndian.PutUint32(v6[20:24], uint32(ip+1))
		v6[24] = 0x20
		v6[25] = 1
		v6[39] = 53
		copy(v6[40:], p[20:])
		p = v6
	}
	return copy(out, p), nil
}
func TestLoadCountsWithSingleCPUAndSmallWriteBuffers(t *testing.T) {
	old := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(old)
	c := config.Default()
	c.Database = filepath.Join(t.TempDir(), "stats.db")
	c.MaxPending = 64
	s, e := store.Open(c.Database, true, 16, 4)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	src := &generatedSource{remaining: 20000, cancel: cancel}
	start := time.Now()
	if e = consume(ctx, c, s, src); e != nil {
		t.Fatal(e)
	}
	totals, e := s.Totals(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if totals.Requests != "20000" || totals.Unique != 2000 {
		t.Fatal(totals)
	}
	t.Logf("20,000 IPv4/IPv6 requests, 2,000 IPs, one CPU, two 64-IP portions: %s", time.Since(start))
}
func BenchmarkPipeline(b *testing.B) {
	c := config.Default()
	c.Database = filepath.Join(b.TempDir(), "stats.db")
	s, e := store.Open(c.Database, true, 64, 16)
	if e != nil {
		b.Fatal(e)
	}
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	src := &generatedSource{remaining: b.N, cancel: cancel}
	b.ReportAllocs()
	b.ResetTimer()
	if e = consume(ctx, c, s, src); e != nil {
		b.Fatal(e)
	}
	b.StopTimer()
	total, _ := s.Totals(context.Background())
	if total.Requests != strconv.Itoa(b.N) {
		b.Fatal(fmt.Sprintf("count mismatch: %+v", total))
	}
}
