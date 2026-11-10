package packet

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

var instant = time.Unix(1794272400, 0)

func put16(b []byte, v int)    { binary.BigEndian.PutUint16(b, uint16(v)) }
func put32(b []byte, v uint32) { binary.BigEndian.PutUint32(b, v) }
func dns(reply bool) []byte {
	b := make([]byte, 17)
	b[2] = 1
	if reply {
		b[2] |= 128
	}
	b[5] = 1
	b[12] = 0
	b[14] = 1
	b[16] = 1
	return b
}
func udp(b []byte, port int) []byte {
	p := make([]byte, 8+len(b))
	put16(p, 12345)
	put16(p[2:], port)
	put16(p[4:], len(p))
	copy(p[8:], b)
	return p
}
func tcp(seq uint32, flags byte, b []byte) []byte {
	p := make([]byte, 20+len(b))
	put16(p, 12345)
	put16(p[2:], 53)
	put32(p[4:], seq)
	p[12] = 80
	p[13] = flags
	copy(p[20:], b)
	return p
}
func framed(b []byte) []byte { p := make([]byte, 2+len(b)); put16(p, len(b)); copy(p[2:], b); return p }
func ip4(proto byte, b []byte) []byte {
	p := make([]byte, 20+len(b))
	p[0] = 0x45
	put16(p[2:], len(p))
	p[9] = proto
	copy(p[12:16], []byte{192, 0, 2, 1})
	copy(p[16:20], []byte{192, 0, 2, 53})
	copy(p[20:], b)
	return p
}
func ip6(proto byte, b []byte) []byte {
	p := make([]byte, 40+len(b))
	p[0] = 0x60
	put16(p[4:], len(b))
	p[6] = proto
	src := netip.MustParseAddr("2001:db8::1").As16()
	dst := netip.MustParseAddr("2001:db8::53").As16()
	copy(p[8:], src[:])
	copy(p[24:], dst[:])
	copy(p[40:], b)
	return p
}
func harness() (*Engine, map[netip.Addr]int64) {
	counts := make(map[netip.Addr]int64)
	return New(53, netip.Addr{}, Limits{1024, 8 << 20, 256, 2 << 20, time.Minute}, func(ip netip.Addr, n, ts int64) { counts[ip] += n }), counts
}
func sum(m map[netip.Addr]int64) int64 {
	var n int64
	for _, v := range m {
		n += v
	}
	return n
}
func TestUDP(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		t.Run(map[bool]string{false: "IPv4", true: "IPv6"}[ipv6], func(t *testing.T) {
			e, m := harness()
			wrap := ip4
			if ipv6 {
				wrap = ip6
			}
			e.Feed(wrap(17, udp(dns(false), 53)), instant)
			e.Feed(wrap(17, udp(dns(true), 53)), instant)
			e.Feed(wrap(17, udp(dns(false), 5353)), instant)
			e.Feed(wrap(17, udp([]byte{0, 1}, 53)), instant)
			if sum(m) != 1 {
				t.Fatalf("got %v", m)
			}
		})
	}
}
func TestDestinationAndIPv4Options(t *testing.T) {
	e, m := harness()
	e.Destination = netip.MustParseAddr("192.0.2.99")
	p := ip4(17, udp(dns(false), 53))
	e.Feed(p, instant)
	if sum(m) != 0 {
		t.Fatal(m)
	}
	e.Destination = netip.MustParseAddr("192.0.2.53")
	p = append(p[:20], append(make([]byte, 4), p[20:]...)...)
	p[0] = 0x46
	put16(p[2:], len(p))
	e.Feed(p, instant)
	if sum(m) != 1 {
		t.Fatal(m)
	}
}
func TestTCPReassembly(t *testing.T) {
	for _, wrap := range []func(byte, []byte) []byte{ip4, ip6} {
		e, m := harness()
		feed := func(seq uint32, flags byte, b []byte) { e.Feed(wrap(6, tcp(seq, flags, b)), instant) }
		q := framed(dns(false))
		r := framed(dns(true))
		all := append(append(append([]byte{}, q...), q...), r...)
		feed(100, 2, nil)
		feed(100, 2, nil)
		feed(110, 16, all[9:])
		feed(110, 16, all[9:]) // out of order + retransmit
		feed(101, 16, all[:9])
		feed(101, 16, all) // fill gap + full retransmission
		if sum(m) != 2 {
			t.Fatalf("expected 2 requests, got %v", m)
		}
		feed(101+uint32(len(all)), 16, q[:1])
		feed(102+uint32(len(all)), 17, q[1:])
		if sum(m) != 3 {
			t.Fatalf("split length prefix/FIN: %v", m)
		}
		feed(101+uint32(len(all)), 16, q)
		if sum(m) != 3 {
			t.Fatal("retransmission counted")
		}
	}
}
func TestTCPOverlapAndWrap(t *testing.T) {
	e, m := harness()
	q := framed(dns(false))
	start := uint32(0xfffffff9)
	e.Feed(ip4(6, tcp(start-1, 2, nil)), instant)
	e.Feed(ip4(6, tcp(start, 16, q[:10])), instant)
	e.Feed(ip4(6, tcp(start+5, 16, q[5:])), instant)
	e.Feed(ip4(6, tcp(start, 16, q)), instant)
	if sum(m) != 1 {
		t.Fatal(m)
	}
}
func TestTCPMidstreamAndRST(t *testing.T) {
	e, m := harness()
	q := framed(dns(false))
	e.Feed(ip4(6, tcp(1, 16, q)), instant)
	if sum(m) != 0 || e.Counters.Midstream != 1 {
		t.Fatal(m, e.Counters)
	}
	e.Feed(ip4(6, tcp(10, 2, nil)), instant)
	e.Feed(ip4(6, tcp(11, 4, nil)), instant)
	e.Feed(ip4(6, tcp(11, 16, q)), instant)
	if sum(m) != 0 {
		t.Fatal(m)
	}
	e.Feed(ip4(6, tcp(100, 2, q)), instant)
	if sum(m) != 1 {
		t.Fatal("SYN data", m)
	}
}
func TestTCPBoundsAndExpiry(t *testing.T) {
	e, _ := harness()
	e.Limits.Flows = 1
	e.Feed(ip4(6, tcp(10, 2, nil)), instant)
	p := tcp(20, 2, nil)
	put16(p, 2222)
	e.Feed(ip4(6, p), instant)
	if e.Counters.TCPDiscarded != 1 {
		t.Fatal(e.Counters)
	}
	e.Feed(ip4(6, tcp(11, 16, []byte{1})), instant)
	e.Expire(instant.Add(time.Minute + time.Second))
	flows, mem, _, _ := e.Memory()
	if flows != 0 || mem != 0 {
		t.Fatal(flows, mem)
	}
	e.Feed(ip4(6, tcp(30, 2, nil)), instant)
	e.Limits.TCPBytes = 1
	e.Feed(ip4(6, tcp(31, 16, framed(dns(false)))), instant)
	flows, mem, _, _ = e.Memory()
	if flows != 0 || mem != 0 {
		t.Fatal(flows, mem)
	}
}
func frag4(b []byte, off int, more bool) []byte {
	p := ip4(17, b)
	put16(p[4:], 99)
	v := off / 8
	if more {
		v |= 0x2000
	}
	put16(p[6:], v)
	return p
}
func frag6(b []byte, off int, more bool) []byte {
	h := make([]byte, 8)
	h[0] = 17
	v := off
	if more {
		v |= 1
	}
	put16(h[2:], v)
	put32(h[4:], 99)
	return ip6(44, append(h, b...))
}
func TestIPFragments(t *testing.T) {
	for _, wrap := range []func([]byte, int, bool) []byte{frag4, frag6} {
		e, m := harness()
		b := udp(dns(false), 53)
		e.Feed(wrap(b[16:], 16, false), instant)
		e.Feed(wrap(b[16:], 16, false), instant)
		e.Feed(wrap(b[:16], 0, true), instant)
		if sum(m) != 1 {
			t.Fatal(m)
		}
		_, _, n, mem := e.Memory()
		if n != 0 || mem != 0 {
			t.Fatal(n, mem)
		}
	}
}
func TestFragmentOverlapAndLimits(t *testing.T) {
	e, m := harness()
	b := udp(dns(false), 53)
	e.Feed(frag4(b[:16], 0, true), instant)
	e.Feed(frag4(b[8:], 8, false), instant)
	if sum(m) != 0 || e.Counters.FragmentDiscarded != 1 {
		t.Fatal(m, e.Counters)
	}
	e.Limits.FragmentBytes = 1
	e.Feed(frag4(b[:16], 0, true), instant)
	_, _, n, mem := e.Memory()
	if n != 0 || mem != 0 {
		t.Fatal(n, mem)
	}
}
func TestIPv6Extensions(t *testing.T) {
	e, m := harness()
	b := udp(dns(false), 53)
	h := make([]byte, 8)
	h[0] = 17
	e.Feed(ip6(0, append(h, b...)), instant)
	h[0] = 60
	inner := make([]byte, 8)
	inner[0] = 17
	e.Feed(ip6(43, append(h, append(inner, b...)...)), instant)
	atomic := make([]byte, 8)
	atomic[0] = 17
	e.Feed(ip6(44, append(atomic, b...)), instant)
	if sum(m) != 3 {
		t.Fatal(m)
	}
}
func TestMalformedNeverCounts(t *testing.T) {
	e, m := harness()
	p := ip4(17, udp(dns(false), 53))
	for i := 0; i < len(p); i++ {
		e.Feed(p[:i], instant)
	}
	p = ip6(17, udp(dns(false), 53))
	for i := 0; i < len(p); i++ {
		e.Feed(p[:i], instant)
	}
	if sum(m) != 0 {
		t.Fatal(m)
	}
}
func FuzzFeed(f *testing.F) {
	f.Add(ip4(17, udp(dns(false), 53)))
	f.Add(ip6(6, tcp(1, 2, framed(dns(false)))))
	f.Fuzz(func(t *testing.T, b []byte) { e, _ := harness(); e.Feed(b, instant); e.Expire(instant.Add(time.Hour)) })
}

func TestRetransmissionAtMemoryLimit(t *testing.T) {
	e, m := harness()
	q := framed(dns(false))
	e.Limits.TCPBytes = len(q)
	e.Feed(ip4(6, tcp(100, 2, nil)), instant)
	e.Feed(ip4(6, tcp(102, 16, q[1:])), instant)
	e.Feed(ip4(6, tcp(102, 16, q[1:])), instant)
	e.Feed(ip4(6, tcp(101, 16, q[:1])), instant)
	if sum(m) != 1 || e.Counters.TCPDiscarded != 0 {
		t.Fatal(m, e.Counters)
	}
}
func BenchmarkUDP(b *testing.B) {
	e, _ := harness()
	p := ip4(17, udp(dns(false), 53))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.Feed(p, instant)
	}
}
