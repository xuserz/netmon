package monitor

import (
	"context"
	"encoding/binary"
	"path/filepath"
	"testing"

	"netmon/internal/config"
	"netmon/internal/store"
)

type fakeSource struct {
	packets [][]byte
	cancel  context.CancelFunc
}

func (f *fakeSource) Read(b []byte) (int, error) {
	if len(f.packets) == 0 {
		f.cancel()
		return 0, nil
	}
	p := f.packets[0]
	f.packets = f.packets[1:]
	return copy(b, p), nil
}
func (f *fakeSource) Drops() (uint32, error) { return 0, nil }
func query(ip byte) []byte {
	b := make([]byte, 45)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], 45)
	b[9] = 17
	copy(b[12:16], []byte{192, 0, 2, ip})
	copy(b[16:20], []byte{192, 0, 2, 53})
	binary.BigEndian.PutUint16(b[20:], 12345)
	binary.BigEndian.PutUint16(b[22:], 53)
	binary.BigEndian.PutUint16(b[24:], 25)
	b[30] = 1
	b[33] = 1
	b[42] = 1
	b[44] = 1
	return b
}
func TestShutdownAndEarlyFlush(t *testing.T) {
	for _, limit := range []int{1, 100} {
		t.Run(map[int]string{1: "early_flush", 100: "shutdown_flush"}[limit], func(t *testing.T) {
			c := config.Default()
			c.Database = filepath.Join(t.TempDir(), "stats.db")
			c.MaxPending = limit
			s, e := store.Open(c.Database, true, c.MaxDatabaseMB, c.MaxWALMB)
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			src := &fakeSource{packets: [][]byte{query(1), query(1), query(2), query(3)}, cancel: cancel}
			if e = consume(ctx, c, s, src); e != nil {
				t.Fatal(e)
			}
			var clients, count int
			if e = s.DB.QueryRow("SELECT count(*),sum(requests) FROM clients").Scan(&clients, &count); e != nil {
				t.Fatal(e)
			}
			if clients != 3 || count != 4 {
				t.Fatal(clients, count)
			}
		})
	}
}
