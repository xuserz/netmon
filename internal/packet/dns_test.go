package packet

import (
	"bytes"
	"testing"
	"time"
)

func TestDNSStructure(t *testing.T) {
	q := dns(false)
	edns := append(bytes.Clone(q), []byte{0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0}...)
	edns[11] = 1
	cookie := make([]byte, 12)
	cookie[2] = 1
	cookie[11] = 1
	cookie = append(cookie, []byte{0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 12, 0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8}...)
	update := bytes.Clone(q)
	update[2] = 5 << 3
	notify := bytes.Clone(q)
	notify[2] = 4 << 3
	dso := make([]byte, 20)
	dso[2] = 6 << 3
	dso[13] = 1
	dso[15] = 4
	for name, b := range map[string][]byte{"query": q, "edns": edns, "update": update, "notify": notify, "dso": dso, "cookie_probe": cookie} {
		if !validDNS(b) {
			t.Fatal("valid message rejected", name)
		}
	}
	cycle := bytes.Clone(q)
	cycle[12] = 0xc0
	cycle[13] = 12
	forward := bytes.Clone(q)
	forward[12] = 0xc0
	forward[13] = 14
	label := bytes.Clone(q)
	label[12] = 64
	truncated := bytes.Clone(edns)
	truncated[len(truncated)-1] = 10
	count := bytes.Clone(q)
	count[5] = 2
	reserved := bytes.Clone(q)
	reserved[3] = 0x40
	for name, b := range map[string][]byte{"empty": nil, "reply": dns(true), "cycle": cycle, "forward_pointer": forward, "label": label, "rdlength": truncated, "count": count, "trailing": append(bytes.Clone(q), 0), "reserved": reserved, "zero_question": make([]byte, 17)} {
		if validDNS(b) {
			t.Fatal("malformed message accepted", name)
		}
	}
	// Two questions, second name compressed to the first. Names are validated
	// transiently, never materialized as strings.
	compressed := append(bytes.Clone(q), []byte{0xc0, 12, 0, 28, 0, 1}...)
	compressed[5] = 2
	if !validDNS(compressed) {
		t.Fatal("valid compression rejected")
	}
}
func TestMalformedDNSDoesNotCountOrPoisonTCP(t *testing.T) {
	e, m := harness()
	bad := make([]byte, 17)
	bad[2] = 1
	e.Feed(ip4(17, udp(bad, 53)), instant)
	e.Feed(ip4(6, tcp(100, 2, nil)), instant)
	both := append(framed(bad), framed(dns(false))...)
	e.Feed(ip4(6, tcp(101, 16, both)), instant)
	if sum(m) != 1 || e.Counters.MalformedDNS != 2 {
		t.Fatal(m, e.Counters)
	}
}
func TestClosedTCPReleasesActiveSlotsAndDeduplicatesSYN(t *testing.T) {
	e, m := harness()
	e.Limits.Flows = 1
	q := framed(dns(false))
	e.Feed(ip4(6, tcp(100, 3, q)), instant) // Fast Open data and an in-order FIN.
	flows, mem, _, _ := e.Memory()
	if flows != 0 || mem != 0 {
		t.Fatal(flows, mem)
	}
	e.Feed(ip4(6, tcp(100, 3, q)), instant)
	p := tcp(200, 3, q)
	put16(p, 2222)
	e.Feed(ip4(6, p), instant)
	if sum(m) != 2 || e.Counters.TCPFlowLimit != 0 || len(e.closed) > 1 {
		t.Fatal(m, e.Counters)
	}
	e.Expire(instant.Add(2 * time.Minute))
	if len(e.closed) != 0 {
		t.Fatal("closed cache did not expire")
	}
}
func TestFINBeforeGapAndIndependentIdleTimeout(t *testing.T) {
	e, m := harness()
	e.TCPIdleTimeout = 10 * time.Minute
	q := framed(dns(false))
	e.Feed(ip4(6, tcp(100, 2, nil)), instant)
	e.Feed(ip4(6, tcp(110, 17, q[9:])), instant)
	e.Feed(ip4(6, tcp(101, 16, q[:9])), instant)
	if sum(m) != 1 || len(e.flows) != 0 {
		t.Fatal(m, len(e.flows))
	}
	e.Feed(ip4(6, tcp(200, 2, nil)), instant)
	e.Expire(instant.Add(3 * time.Minute))
	if len(e.flows) != 1 {
		t.Fatal("clean idle connection expired too early")
	}
	e.Feed(ip4(6, tcp(201, 16, q[:5])), instant.Add(3*time.Minute))
	e.Feed(ip4(6, tcp(206, 16, nil)), instant.Add(5*time.Minute))
	e.Expire(instant.Add(5 * time.Minute))
	if len(e.flows) != 0 || e.Counters.TCPTimeout != 1 {
		t.Fatal(e.Counters)
	}
}
func FuzzDNS(f *testing.F) {
	f.Add(dns(false))
	f.Add([]byte{0xc0, 12})
	f.Fuzz(func(t *testing.T, b []byte) { validDNS(b) })
}
