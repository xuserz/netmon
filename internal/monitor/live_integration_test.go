package monitor

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"dnsmon/internal/config"
	"dnsmon/internal/live"
	"dnsmon/internal/store"
)

// End-to-end native AF_PACKET + BPF + parser + async SQLite, on ephemeral
// loopback ports. CI runs it as root; local unprivileged runs may skip it.
func TestLivePacketPipeline(t *testing.T) {
	if os.Getenv("DNSMON_INTEGRATION") != "1" {
		t.Skip("set DNSMON_INTEGRATION=1 and grant CAP_NET_RAW")
	}
	for _, family := range []string{"4", "6"} {
		t.Run("IPv"+family, func(t *testing.T) {
			host := "127.0.0.1"
			if family == "6" {
				host = "::1"
			}
			udp, e := net.ListenPacket("udp"+family, net.JoinHostPort(host, "0"))
			if errors.Is(e, syscall.EPERM) {
				t.Skip("sandbox forbids network sockets")
			}
			if e != nil {
				t.Fatal(e)
			}
			defer udp.Close()
			port := udp.LocalAddr().(*net.UDPAddr).Port
			tcp, e := net.Listen("tcp"+family, net.JoinHostPort(host, strconv.Itoa(port)))
			if e != nil {
				t.Fatal(e)
			}
			defer tcp.Close()
			go func() {
				buf := make([]byte, 65536)
				for {
					if _, _, e := udp.ReadFrom(buf); e != nil {
						return
					}
				}
			}()
			go func() {
				for {
					conn, e := tcp.Accept()
					if e != nil {
						return
					}
					go func() { defer conn.Close(); io.Copy(io.Discard, conn) }()
				}
			}()
			c := config.Default()
			c.Interface = "lo"
			c.Port = uint16(port)
			c.FlushInterval = time.Second
			c.MaxPending = 64
			c.Database = filepath.Join(t.TempDir(), "stats.db")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- Run(ctx, c) }()
			ready := false
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				if _, e := live.Fetch(context.Background(), c.Database, live.Request{Op: "health"}); e == nil {
					ready = true
					break
				}
				select {
				case err := <-done:
					if errors.Is(err, syscall.EPERM) {
						t.Skip("CAP_NET_RAW unavailable")
					}
					t.Fatal(err)
				default:
				}
				time.Sleep(20 * time.Millisecond)
			}
			if !ready {
				t.Fatal("capture never became ready")
			}
			q := query(1)[28:]
			client, e := net.Dial("udp"+family, udp.LocalAddr().String())
			if e != nil {
				t.Fatal(e)
			}
			const datagrams = 200
			const streams = 10
			const perStream = 10
			for i := 0; i < datagrams; i++ {
				if _, e = client.Write(q); e != nil {
					t.Fatal(e)
				}
				if i%20 == 0 {
					time.Sleep(time.Millisecond)
				}
			}
			client.Close()
			framed := make([]byte, len(q)+2)
			binary.BigEndian.PutUint16(framed, uint16(len(q)))
			copy(framed[2:], q)
			for i := 0; i < streams; i++ {
				conn, err := net.Dial("tcp"+family, tcp.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				for j := 0; j < perStream; j++ {
					if _, err = conn.Write(framed[:1]); err == nil {
						_, err = conn.Write(framed[1:])
					}
					if err != nil {
						t.Fatal(err)
					}
				}
				conn.Close()
			}
			expected := uint64(datagrams + streams*perStream)
			deadline = time.Now().Add(5 * time.Second)
			var h live.Health
			for time.Now().Before(deadline) {
				r, err := live.Fetch(context.Background(), c.Database, live.Request{Op: "health"})
				if err == nil {
					h = r.Health
					if h.Counted >= expected {
						break
					}
				}
				time.Sleep(20 * time.Millisecond)
			}
			cancel()
			if e = <-done; e != nil {
				t.Fatal(e)
			}
			if h.Counted != expected || h.KernelDrops != 0 {
				t.Fatal("capture loss or duplicate", h)
			}
			s, e := store.Open(c.Database, false, 0, 0)
			if e != nil {
				t.Fatal(e)
			}
			defer s.Close()
			totals, e := s.Totals(context.Background())
			if e != nil {
				t.Fatal(e)
			}
			if totals.Requests != strconv.FormatUint(expected, 10) || totals.Unique != 1 {
				t.Fatal(totals)
			}
		})
	}
}
