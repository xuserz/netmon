package network

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"testing"
	"time"

	"netmon/internal/observation"
)

func codecSample() observation.Sample {
	s := oldSample("0123456789abcdef0123456789abcdef", 1794301200, "2001:db8::1234", 123456)
	s.ID = "abcdef0123456789abcdef0123456789"
	s.Name = "edge-eu-01"
	s.TCP = 10000
	s.SYN = 1200
	s.UDP = s.Packets - s.TCP
	s.Bytes = 76543210
	s.First = s.Window + 1
	s.Last = s.Window + 59
	s.PeakPPS = 9000
	s.Ports = []uint16{22, 53, 443, 65535}
	s.Evidence = observation.Evidence{At: s.Window - 10, PPS: 8000, SYN: 1000, Ports: 4}
	s.Partial = true
	return s
}
func TestCompactCodecRetainsEveryFieldAndReadsLegacyJSON(t *testing.T) {
	rich := codecSample()
	minimal := oldSample(rich.Node, 0, "192.0.2.1", 1)
	minimal.Name = ""
	minimal.ID = rich.ID
	maximum := minimal
	maximum.Window = rich.Window
	maximum.First = rich.Window
	maximum.Last = rich.Window
	maximum.Packets = math.MaxInt64
	maximum.Bytes = math.MaxInt64
	maximum.UDP = math.MaxInt64
	maximum.PeakPPS = math.MaxInt64
	for _, s := range []observation.Sample{rich, minimal, maximum} {
		old, e := json.Marshal(s)
		if e != nil {
			t.Fatal(e)
		}
		compact := encodeSample(s)
		for _, raw := range [][]byte{old, compact} {
			got, e := decodeSample(s.ID, s.Node, s.IP, s.Window, raw)
			if e != nil {
				t.Fatal(e)
			}
			encoded, _ := json.Marshal(got)
			if !bytes.Equal(old, encoded) {
				t.Fatalf("round trip changed data:\n%s\n%s", old, encoded)
			}
		}
		if len(compact) >= len(old) {
			t.Fatal("compact format grew", len(compact), len(old))
		}
	}
	raw := encodeSample(rich)
	for _, duplicate := range []string{rich.ID, rich.Node, rich.IP, "packets", "first_seen", "window"} {
		if bytes.Contains(raw, []byte(duplicate)) {
			t.Fatal("duplicated SQL metadata", duplicate)
		}
	}
}
func TestCompactCodecRejectsTruncationUnknownVersionsAndOverflow(t *testing.T) {
	s := codecSample()
	raw := encodeSample(s)
	for i := 0; i < len(raw); i++ {
		if _, e := decodeSample(s.ID, s.Node, s.IP, s.Window, raw[:i]); e == nil {
			t.Fatal("accepted truncated payload", i)
		}
	}
	unknown := append([]byte(nil), raw...)
	unknown[2]++
	flags := append([]byte(nil), raw...)
	flags[3] |= 128
	trailing := append(append([]byte(nil), raw...), 0)
	for _, bad := range [][]byte{unknown, flags, trailing, {'N', 'M', 1, 0, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255}} {
		if _, e := decodeSample(s.ID, s.Node, s.IP, s.Window, bad); e == nil {
			t.Fatal("accepted invalid payload")
		}
	}
	old, _ := json.Marshal(s)
	if _, e := decodeSample(s.ID, s.Node, "192.0.2.2", s.Window, old); e == nil {
		t.Fatal("legacy metadata mismatch ignored")
	}
}
func BenchmarkSampleCodec(b *testing.B) {
	s := codecSample()
	legacy, _ := json.Marshal(s)
	compact := encodeSample(s)
	b.Run("JSONEncode", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, e := json.Marshal(s); e != nil {
				b.Fatal(e)
			}
		}
	})
	b.Run("CompactEncode", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = encodeSample(s)
		}
	})
	b.Run("JSONDecode", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			var out observation.Sample
			if e := json.Unmarshal(legacy, &out); e != nil {
				b.Fatal(e)
			}
		}
	})
	b.Run("CompactDecode", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, e := decodeSample(s.ID, s.Node, s.IP, s.Window, compact); e != nil {
				b.Fatal(e)
			}
		}
	})
}
func FuzzCompactCodec(f *testing.F) {
	s := codecSample()
	f.Add(encodeSample(s))
	raw, _ := json.Marshal(s)
	f.Add(raw)
	f.Fuzz(func(t *testing.T, raw []byte) {
		got, e := decodeSample(s.ID, s.Node, s.IP, s.Window, raw)
		if e != nil {
			return
		}
		if e = got.Validate(time.Unix(max(time.Now().Unix(), got.Last), 0), 0); e != nil {
			return
		}
		again, e := decodeSample(got.ID, got.Node, got.IP, got.Window, encodeSample(got))
		if e != nil {
			t.Fatal(e)
		}
		a, _ := json.Marshal(got)
		b, _ := json.Marshal(again)
		if !bytes.Equal(a, b) {
			t.Fatal("lossy codec")
		}
	})
}

func TestMixedPayloadReplayKeepsVersionsAndUpdatesCountersOnce(t *testing.T) {
	ctx := context.Background()
	c := configForTest(t)
	d, e := openDisk(c, true)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	a, b := sample(observation.ID(), 7), sample(observation.ID(), 3)
	if e = d.Merge(ctx, []observation.Sample{a, b}, nil); e != nil {
		t.Fatal(e)
	}
	legacy, _ := json.Marshal(a)
	if _, e = d.w.DB.Exec("UPDATE net_observations SET payload=? WHERE id=?", legacy, a.ID); e != nil {
		t.Fatal(e)
	}
	before, e := d.Page(ctx, "", 0)
	if e != nil {
		t.Fatal(e)
	}
	if e = d.Merge(ctx, []observation.Sample{a, b}, nil); e != nil {
		t.Fatal(e)
	}
	after, e := d.Page(ctx, "", 0)
	if e != nil || before.Head != after.Head {
		t.Fatal("representation-only replay changed version", e)
	}
	a.Packets += 2
	a.Bytes += 200
	a.UDP += 2
	if e = d.Merge(ctx, []observation.Sample{a}, nil); e != nil {
		t.Fatal(e)
	}
	if e = d.Merge(ctx, []observation.Sample{a}, nil); e != nil {
		t.Fatal(e)
	}
	_, totals, e := d.View(ctx, "total", 20)
	if e != nil || totals.Packets != 12 {
		t.Fatal(totals, e)
	}
	assertStoredCounters(t, d)
}
