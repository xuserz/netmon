package observation

import (
	"encoding/binary"
	"testing"
	"time"
)

func TestRatingIsBoundedExplainableAndDecays(t *testing.T) {
	p := Policy{PPS: 1000, SYN: 100, Ports: 8, HalfLifeSeconds: 3600}
	now := time.Now()
	cases := []struct {
		e    Evidence
		want int
	}{{Evidence{At: now.Unix()}, 0}, {Evidence{At: now.Unix(), PPS: 16000}, 35}, {Evidence{At: now.Unix(), Ports: 32}, 30}, {Evidence{At: now.Unix(), PPS: 16000, SYN: 1600, Ports: 32}, 100}}
	for _, c := range cases {
		score, reasons := p.Score(c.e, now)
		if score != c.want {
			t.Fatal(c, score)
		}
		if score > 0 && len(reasons) == 0 {
			t.Fatal("rating has no explanation")
		}
	}
	peak := cases[3].e
	if score, _ := p.Score(peak, now.Add(time.Hour)); score != 50 {
		t.Fatal(score)
	}
	if score, _ := p.Score(peak, now.Add(2*time.Hour)); score != 25 {
		t.Fatal(score)
	}
	if score, _ := p.Score(peak, now.Add(24*time.Hour)); score != 0 {
		t.Fatal(score)
	}
}
func packet4(proto byte, payload []byte) []byte {
	b := make([]byte, 20+len(payload))
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	b[9] = proto
	copy(b[12:16], []byte{192, 0, 2, 1})
	copy(b[16:20], []byte{192, 0, 2, 2})
	copy(b[20:], payload)
	return b
}
func TestNetworkHeadersDoNotRequireDNSAndSYNACKIsNotAnAttempt(t *testing.T) {
	udp := make([]byte, 12)
	binary.BigEndian.PutUint16(udp, 1234)
	binary.BigEndian.PutUint16(udp[2:], 9999)
	binary.BigEndian.PutUint16(udp[4:], 12)
	copy(udp[8:], []byte("junk"))
	p, e := Decode(packet4(17, udp))
	if e != nil || p.Port != 9999 || p.Length != 32 || p.Protocol != 17 {
		t.Fatal(p, e)
	}
	tcp := make([]byte, 20)
	tcp[12] = 0x50
	tcp[13] = 2
	binary.BigEndian.PutUint16(tcp[2:], 22)
	p, e = Decode(packet4(6, tcp))
	if e != nil || !p.SYN || p.Port != 22 {
		t.Fatal(p, e)
	}
	tcp[13] = 0x12
	p, e = Decode(packet4(6, tcp))
	if e != nil || p.SYN {
		t.Fatal("SYN+ACK was counted as inbound attempt", p, e)
	}
	fragment := packet4(6, []byte{1, 2, 3, 4, 5, 6, 7, 8})
	binary.BigEndian.PutUint16(fragment[6:], 1)
	p, e = Decode(fragment)
	if e != nil || p.Port != 0 || p.SYN || !p.Fragment {
		t.Fatal(p, e)
	}
}
func TestIPv6ExtensionAndNoninitialFragments(t *testing.T) {
	b := make([]byte, 40+8+20)
	b[0] = 0x60
	b[6] = 0
	binary.BigEndian.PutUint16(b[4:], 28)
	b[8] = 0x20
	b[9] = 1
	b[24] = 0x20
	b[25] = 1
	b[40] = 6
	b[48+12] = 0x50
	b[48+13] = 2
	binary.BigEndian.PutUint16(b[50:], 443)
	p, e := Decode(b)
	if e != nil || !p.SYN || p.Port != 443 {
		t.Fatal(p, e)
	}
	b[6] = 44
	b[40] = 6
	binary.BigEndian.PutUint16(b[42:], 8)
	p, e = Decode(b)
	if e != nil || p.SYN || p.Port != 0 || !p.Fragment {
		t.Fatal(p, e)
	}
}
func FuzzNetworkDecode(f *testing.F) {
	f.Add(packet4(17, make([]byte, 8)))
	f.Add([]byte{0x60})
	f.Fuzz(func(t *testing.T, b []byte) { Decode(b) })
}
