package observation

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

type Packet struct {
	Source, Destination netip.Addr
	Length              int
	Protocol            uint8
	SourcePort, Port    uint16
	SYN                 bool
	Fragment            bool
}

var ErrPacket = errors.New("malformed or unsupported IP packet")

// Decode reads headers only. A packet is not an application request. Noninitial
// fragments count as IP packets but have no trusted transport header/port.
func Decode(b []byte) (Packet, error) {
	var p Packet
	off := 0
	fragment := false
	if len(b) < 1 {
		return p, ErrPacket
	}
	switch b[0] >> 4 {
	case 4:
		if len(b) < 20 {
			return p, ErrPacket
		}
		off = int(b[0]&15) * 4
		total := int(binary.BigEndian.Uint16(b[2:]))
		if off < 20 || off > len(b) || total < off || total > len(b) {
			return p, ErrPacket
		}
		p.Source = netip.AddrFrom4([4]byte(b[12:16]))
		p.Destination = netip.AddrFrom4([4]byte(b[16:20]))
		p.Protocol = b[9]
		p.Length = total
		b = b[:total]
		frag := binary.BigEndian.Uint16(b[6:])
		p.Fragment = frag&0x3fff != 0
		fragment = frag&0x1fff != 0
	case 6:
		if len(b) < 40 {
			return p, ErrPacket
		}
		total := 40 + int(binary.BigEndian.Uint16(b[4:]))
		if total > len(b) || (total == 40 && b[6] != 59) {
			return p, ErrPacket
		}
		b = b[:total]
		p.Source = netip.AddrFrom16([16]byte(b[8:24])).Unmap()
		p.Destination = netip.AddrFrom16([16]byte(b[24:40])).Unmap()
		p.Protocol = b[6]
		p.Length = total
		off = 40
		for i := 0; i < 16; i++ {
			switch p.Protocol {
			case 0, 43, 60:
				if off+2 > len(b) {
					return p, ErrPacket
				}
				next := b[off]
				n := (int(b[off+1]) + 1) * 8
				if off+n > len(b) {
					return p, ErrPacket
				}
				off += n
				p.Protocol = next
			case 51:
				if off+2 > len(b) {
					return p, ErrPacket
				}
				next := b[off]
				n := (int(b[off+1]) + 2) * 4
				if off+n > len(b) {
					return p, ErrPacket
				}
				off += n
				p.Protocol = next
			case 44:
				if off+8 > len(b) {
					return p, ErrPacket
				}
				fragment = binary.BigEndian.Uint16(b[off+2:])&0xfff8 != 0
				p.Fragment = true
				p.Protocol = b[off]
				off += 8
				if fragment {
					return p, nil
				}
			default:
				return transport(p, b, off, fragment)
			}
		}
		return p, ErrPacket
	default:
		return p, ErrPacket
	}
	return transport(p, b, off, fragment)
}
func transport(p Packet, b []byte, off int, fragment bool) (Packet, error) {
	if fragment {
		return p, nil
	}
	switch p.Protocol {
	case 6:
		if off+20 > len(b) {
			if p.Fragment {
				return p, nil
			}
			return p, ErrPacket
		}
		header := int(b[off+12]>>4) * 4
		if header < 20 || off+header > len(b) && !p.Fragment {
			return p, ErrPacket
		}
		p.SourcePort = binary.BigEndian.Uint16(b[off:])
		p.Port = binary.BigEndian.Uint16(b[off+2:])
		p.SYN = b[off+13]&0x12 == 0x02
	case 17:
		if off+8 > len(b) {
			if p.Fragment {
				return p, nil
			}
			return p, ErrPacket
		}
		length := int(binary.BigEndian.Uint16(b[off+4:]))
		if length < 8 || (!p.Fragment && off+length > len(b)) {
			return p, ErrPacket
		}
		p.SourcePort = binary.BigEndian.Uint16(b[off:])
		p.Port = binary.BigEndian.Uint16(b[off+2:])
	}
	return p, nil
}
