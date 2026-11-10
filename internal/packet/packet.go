// Package packet counts DNS messages from inbound IP datagrams. Packet content
// exists only in bounded volatile reassembly buffers and is never persisted.
package packet

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"sort"
	"time"
)

type Limits struct {
	Flows, TCPBytes, Fragments, FragmentBytes int
	Timeout                                   time.Duration
}
type Counters struct{ Malformed, FragmentDiscarded, TCPDiscarded, Midstream uint64 }
type Engine struct {
	Port                uint16
	Destination         netip.Addr
	Limits              Limits
	Counters            Counters
	flows               map[flowKey]*flow
	fragments           map[fragKey]*fragment
	tcpBytes, fragBytes int
	Count               func(netip.Addr, int64, int64)
}

func New(port uint16, dst netip.Addr, l Limits, count func(netip.Addr, int64, int64)) *Engine {
	return &Engine{Port: port, Destination: dst, Limits: l, Count: count, flows: make(map[flowKey]*flow), fragments: make(map[fragKey]*fragment)}
}
func u16(b []byte) uint16   { return binary.BigEndian.Uint16(b) }
func u32(b []byte) uint32   { return binary.BigEndian.Uint32(b) }
func request(b []byte) bool { return len(b) >= 12 && b[2]&0x80 == 0 }

func (e *Engine) Feed(b []byte, now time.Time) {
	if len(b) == 0 {
		return
	}
	switch b[0] >> 4 {
	case 4:
		if len(b) < 20 {
			e.Counters.Malformed++
			return
		}
		h := int(b[0]&15) * 4
		n := int(u16(b[2:4]))
		if h < 20 || n < h || n > len(b) {
			e.Counters.Malformed++
			return
		}
		src := netip.AddrFrom4([4]byte(b[12:16]))
		dst := netip.AddrFrom4([4]byte(b[16:20]))
		if !e.accept(dst) {
			return
		}
		proto := b[9]
		if proto != 6 && proto != 17 {
			return
		}
		flags := u16(b[6:8])
		payload := b[h:n]
		if flags&0x3fff != 0 {
			payload = e.reassemble(fragKey{src, dst, uint32(u16(b[4:6])), proto}, int(flags&0x1fff)*8, flags&0x2000 != 0, payload, now)
			if payload == nil {
				return
			}
		}
		e.transport(src, dst, proto, payload, now)
	case 6:
		if len(b) < 40 {
			e.Counters.Malformed++
			return
		}
		n := 40 + int(u16(b[4:6]))
		if n == 40 || n > len(b) {
			e.Counters.Malformed++
			return
		}
		src := netip.AddrFrom16([16]byte(b[8:24]))
		dst := netip.AddrFrom16([16]byte(b[24:40]))
		if !e.accept(dst) {
			return
		}
		e.ipv6(src, dst, b[6], b[40:n], now, 8, false)
	}
}
func (e *Engine) accept(dst netip.Addr) bool {
	return !e.Destination.IsValid() || e.Destination.Unmap() == dst.Unmap()
}
func (e *Engine) ipv6(src, dst netip.Addr, next byte, b []byte, now time.Time, budget int, fragmented bool) {
	for i := 0; i < budget; i++ {
		switch next {
		case 6, 17:
			e.transport(src, dst, next, b, now)
			return
		case 0, 43, 60, 51:
			if len(b) < 2 {
				e.Counters.Malformed++
				return
			}
			n := (int(b[1]) + 1) * 8
			if next == 51 {
				n = (int(b[1]) + 2) * 4
			}
			if n > len(b) {
				e.Counters.Malformed++
				return
			}
			next, b = b[0], b[n:]
		case 44:
			if fragmented {
				e.Counters.Malformed++
				return
			}
			fragmented = true
			if len(b) < 8 {
				e.Counters.Malformed++
				return
			}
			flags := u16(b[2:4])
			proto := b[0]
			// Atomic fragments need no cache. Repeated fragment headers are rejected.
			if flags&0xfff9 == 0 {
				next, b = proto, b[8:]
				continue
			}
			payload := e.reassemble(fragKey{src, dst, u32(b[4:8]), proto}, int(flags&0xfff8), flags&1 != 0, b[8:], now)
			if payload != nil && proto != 44 {
				e.ipv6(src, dst, proto, payload, now, budget-i-1, true)
			}
			return
		default:
			return
		}
	}
	e.Counters.Malformed++
}
func (e *Engine) transport(src, dst netip.Addr, proto byte, b []byte, now time.Time) {
	if len(b) < 4 {
		e.Counters.Malformed++
		return
	}
	if u16(b[2:4]) != e.Port {
		return
	}
	if proto == 17 {
		if len(b) < 8 {
			e.Counters.Malformed++
			return
		}
		n := int(u16(b[4:6]))
		if n < 20 || n > len(b) {
			e.Counters.Malformed++
			return
		}
		if request(b[8:n]) {
			e.Count(src.Unmap(), 1, now.Unix())
		}
		return
	}
	if len(b) < 20 {
		e.Counters.Malformed++
		return
	}
	h := int(b[12]>>4) * 4
	if h < 20 || h > len(b) {
		e.Counters.Malformed++
		return
	}
	e.tcp(flowKey{src, dst, u16(b[:2]), u16(b[2:4])}, u32(b[4:8]), b[13], b[h:], now)
}

type fragKey struct {
	src, dst netip.Addr
	id       uint32
	proto    byte
}
type piece struct {
	off  int
	data []byte
}
type fragment struct {
	pieces     []piece
	end, bytes int
	seen       time.Time
}

func (e *Engine) dropFragment(k fragKey) {
	if f := e.fragments[k]; f != nil {
		e.fragBytes -= f.bytes
		delete(e.fragments, k)
	}
}
func (e *Engine) reassemble(k fragKey, off int, more bool, b []byte, now time.Time) []byte {
	if len(b) == 0 || off+len(b) > 65535 || (more && len(b)%8 != 0) {
		e.Counters.FragmentDiscarded++
		e.dropFragment(k)
		return nil
	}
	f := e.fragments[k]
	if f == nil {
		if len(e.fragments) >= e.Limits.Fragments {
			e.Counters.FragmentDiscarded++
			return nil
		}
		f = &fragment{end: -1, seen: now}
		e.fragments[k] = f
	}
	end := off + len(b)
	for _, p := range f.pieces {
		if off == p.off && bytes.Equal(b, p.data) {
			return nil
		}
		if off < p.off+len(p.data) && end > p.off {
			e.Counters.FragmentDiscarded++
			e.dropFragment(k)
			return nil
		}
	}
	if (f.end >= 0 && (end > f.end || (!more && end != f.end))) || len(f.pieces) >= 256 || e.fragBytes+len(b) > e.Limits.FragmentBytes {
		e.Counters.FragmentDiscarded++
		e.dropFragment(k)
		return nil
	}
	if !more {
		f.end = end
		for _, p := range f.pieces {
			if p.off+len(p.data) > end {
				e.Counters.FragmentDiscarded++
				e.dropFragment(k)
				return nil
			}
		}
	}
	f.seen = now
	f.pieces = append(f.pieces, piece{off, bytes.Clone(b)})
	f.bytes += len(b)
	e.fragBytes += len(b)
	if f.end < 0 || f.bytes != f.end {
		return nil
	}
	sort.Slice(f.pieces, func(i, j int) bool { return f.pieces[i].off < f.pieces[j].off })
	result := make([]byte, f.end)
	pos := 0
	for _, p := range f.pieces {
		if p.off != pos {
			return nil
		}
		copy(result[pos:], p.data)
		pos += len(p.data)
	}
	e.dropFragment(k)
	return result
}

type flowKey struct {
	src, dst     netip.Addr
	sport, dport uint16
}
type segment struct {
	seq  uint32
	data []byte
}
type flow struct {
	syn, next uint32
	seen      time.Time
	buf       []byte
	pending   []segment
	bytes     int
	closed    bool
}

func (e *Engine) dropFlow(k flowKey) {
	if f := e.flows[k]; f != nil {
		e.tcpBytes -= f.bytes
		delete(e.flows, k)
	}
}
func (e *Engine) tcp(k flowKey, seq uint32, flags byte, b []byte, now time.Time) {
	f := e.flows[k]
	if flags&2 != 0 { // SYN gives an unambiguous DNS-over-TCP framing boundary.
		if f == nil || f.syn != seq {
			e.dropFlow(k)
			if len(e.flows) >= e.Limits.Flows {
				e.Counters.TCPDiscarded++
				return
			}
			f = &flow{syn: seq, next: seq + 1, seen: now}
			e.flows[k] = f
		}
		seq++
	}
	if f == nil {
		if len(b) > 0 {
			e.Counters.Midstream++
		}
		return
	}
	f.seen = now
	if f.closed {
		return
	}
	if len(b) > 0 {
		delta := int32(seq - f.next)
		if delta < 0 {
			trim := -int64(delta)
			if trim >= int64(len(b)) {
				b = nil
			} else {
				b = b[int(trim):]
				seq = f.next
				delta = 0
			}
		}
		if len(b) > 0 {
			// Do not retain exact retransmissions waiting behind a gap.
			for _, p := range f.pending {
				if p.seq == seq && bytes.Equal(p.data, b) {
					return
				}
			}
			if delta > 1<<20 || f.bytes+len(b) > 131074 || e.tcpBytes+len(b) > e.Limits.TCPBytes || len(f.pending) >= 128 {
				e.Counters.TCPDiscarded++
				e.dropFlow(k)
				return
			}

			f.pending = append(f.pending, segment{seq, bytes.Clone(b)})
			f.bytes += len(b)
			e.tcpBytes += len(b)
			sort.SliceStable(f.pending, func(i, j int) bool { return int32(f.pending[i].seq-f.next) < int32(f.pending[j].seq-f.next) })
			for len(f.pending) > 0 {
				p := f.pending[0]
				d := int32(p.seq - f.next)
				if d > 0 {
					break
				}
				f.pending[0] = segment{}
				f.pending = f.pending[1:]
				trim := int(-int64(d))
				if trim > len(p.data) {
					trim = len(p.data)
				}
				f.bytes -= trim
				e.tcpBytes -= trim
				f.buf = append(f.buf, p.data[trim:]...)
				f.next += uint32(len(p.data) - trim)
				for len(f.buf) >= 2 {
					n := int(u16(f.buf))
					if n < 12 {
						e.Counters.TCPDiscarded++
						e.dropFlow(k)
						return
					}
					if len(f.buf) < n+2 {
						break
					}
					if request(f.buf[2 : n+2]) {
						e.Count(k.src.Unmap(), 1, now.Unix())
					}
					f.buf = f.buf[n+2:]
					f.bytes -= n + 2
					e.tcpBytes -= n + 2
				}
				if len(f.buf) == 0 {
					f.buf = nil
				} else {
					f.buf = bytes.Clone(f.buf)
				}
			}
		}
	}
	// FIN may arrive ahead of a gap; keep the stream until idle expiry so late
	// segments can finish it. RST explicitly abandons incomplete messages.
	if flags&4 != 0 {
		e.tcpBytes -= f.bytes
		f.bytes = 0
		f.buf = nil
		f.pending = nil
		f.closed = true
	}
}

func (e *Engine) Expire(now time.Time) {
	for k, f := range e.flows {
		if now.Sub(f.seen) > e.Limits.Timeout {
			if f.bytes > 0 {
				e.Counters.TCPDiscarded++
			}
			e.dropFlow(k)
		}
	}
	for k, f := range e.fragments {
		if now.Sub(f.seen) > e.Limits.Timeout {
			e.Counters.FragmentDiscarded++
			e.dropFragment(k)
		}
	}
}
func (e *Engine) Memory() (flows, tcp, frags, frag int) {
	return len(e.flows), e.tcpBytes, len(e.fragments), e.fragBytes
}
