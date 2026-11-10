package capture

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"dnsmon/internal/packet"
	"golang.org/x/sys/unix"
)

// Opt in: requires CAP_NET_RAW; uses only ephemeral loopback listeners, no DNS
// service, firewall or host configuration changes.
func TestLiveLoopback(t *testing.T) {
	if os.Getenv("DNSMON_INTEGRATION") != "1" {
		t.Skip("set DNSMON_INTEGRATION=1 to test AF_PACKET + kernel BPF")
	}
	for _, network := range []string{"udp4", "udp6"} {
		t.Run(network, func(t *testing.T) {
			addr := "127.0.0.1:0"
			if network == "udp6" {
				addr = "[::1]:0"
			}
			server, e := net.ListenPacket(network, addr)
			if e != nil {
				if errors.Is(e, unix.EPERM) {
					t.Skip("sandbox forbids network sockets")
				}
				t.Fatal(e)
			}
			defer server.Close()
			port := uint16(server.LocalAddr().(*net.UDPAddr).Port)
			sock, e := Open("lo", port, 1)
			if errors.Is(e, unix.EPERM) {
				t.Skip("CAP_NET_RAW unavailable")
			}
			if e != nil {
				t.Fatal(e)
			}
			defer sock.Close()
			client, e := net.Dial(network, server.LocalAddr().String())
			if e != nil {
				t.Fatal(e)
			}
			defer client.Close()
			var count int64
			engine := packet.New(port, netip.Addr{}, packet.Limits{Flows: 10, TCPBytes: 65537, Fragments: 10, FragmentBytes: 65535, Timeout: time.Minute}, func(_ netip.Addr, n, ts int64) { count += n })
			q := make([]byte, 17)
			q[2] = 1
			q[5] = 1
			q[14] = 1
			q[16] = 1
			if _, e = client.Write(q); e != nil {
				t.Fatal(e)
			}
			q[2] |= 128
			if _, e = client.Write(q); e != nil {
				t.Fatal(e)
			}
			buf := make([]byte, 65575)
			deadline := time.Now().Add(700 * time.Millisecond)
			for time.Now().Before(deadline) {
				n, err := sock.Read(buf)
				if err != nil {
					t.Fatal(err)
				}
				if n > 0 {
					engine.Feed(buf[:n], time.Now())
				}
			}
			if count != 1 {
				t.Fatalf("loopback query counted %d times (expected once, response excluded)", count)
			}
		})
	}
}

func TestKernelFilterCompiles(t *testing.T) {
	fd, e := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if e != nil {
		t.Fatal(e)
	}
	defer unix.Close(fd)
	code := Filter(5353)
	if e = unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &unix.SockFprog{Len: uint16(len(code)), Filter: &code[0]}); e != nil {
		if errors.Is(e, unix.EPERM) {
			t.Skip("sandbox forbids SO_ATTACH_FILTER")
		}
		t.Fatal("kernel rejected filter", e)
	}
}

func TestFilterDecisions(t *testing.T) {
	run := func(proto uint32, kind uint32, b []byte) bool {
		var a, x uint32
		code := Filter(53)
		load := func(off uint32, n int) uint32 {
			if uint64(off)+uint64(n) > uint64(len(b)) {
				return 0
			}
			var v uint32
			for _, c := range b[off : off+uint32(n)] {
				v = v<<8 | uint32(c)
			}
			return v
		}
		for pc := 0; pc < len(code); pc++ {
			i := code[pc]
			switch i.Code {
			case 0x20:
				if i.K == 0xfffff000 {
					a = proto
				} else if i.K == 0xfffff004 {
					a = kind
				} else {
					t.Fatal("unexpected ancillary load")
				}
			case 0x30:
				a = load(i.K, 1)
			case 0x28:
				a = load(i.K, 2)
			case 0xb1:
				x = (load(i.K, 1) & 15) * 4
			case 0x48:
				a = load(i.K+x, 2)
			case 0x15:
				if a == i.K {
					pc += int(i.Jt)
				} else {
					pc += int(i.Jf)
				}
			case 0x45:
				if a&i.K != 0 {
					pc += int(i.Jt)
				} else {
					pc += int(i.Jf)
				}
			case 0x06:
				return i.K != 0
			default:
				t.Fatalf("unexpected instruction %#x", i.Code)
			}
		}
		t.Fatal("filter fell through")
		return false
	}
	v4 := make([]byte, 64)
	v4[0] = 0x45
	v4[9] = 17
	v4[23] = 53
	if !run(unix.ETH_P_IP, unix.PACKET_HOST, v4) {
		t.Fatal("IPv4 DNS rejected")
	}
	if run(unix.ETH_P_IP, unix.PACKET_OUTGOING, v4) {
		t.Fatal("outgoing accepted")
	}
	v4[23] = 80
	if run(unix.ETH_P_IP, 0, v4) {
		t.Fatal("wrong port accepted")
	}
	v4[6] = 0x20
	if !run(unix.ETH_P_IP, 0, v4) {
		t.Fatal("fragment rejected")
	}
	v4[9] = 1
	if run(unix.ETH_P_IP, 0, v4) {
		t.Fatal("ICMP accepted")
	}
	v6 := make([]byte, 64)
	v6[0] = 0x60
	v6[6] = 6
	v6[43] = 53
	if !run(unix.ETH_P_IPV6, 0, v6) {
		t.Fatal("IPv6 TCP rejected")
	}
	v6[43] = 80
	if run(unix.ETH_P_IPV6, 0, v6) {
		t.Fatal("wrong IPv6 port accepted")
	}
	for _, next := range []byte{0, 43, 44, 51, 60} {
		v6[6] = next
		if !run(unix.ETH_P_IPV6, 0, v6) {
			t.Fatal("extension rejected", next)
		}
	}
	if run(unix.ETH_P_ARP, 0, v4) {
		t.Fatal("ARP accepted")
	}
}
