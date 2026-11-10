//go:build linux

package capture

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const ringBlockSize = 1 << 20
const packetHeaderSize = 48
const blockHeaderSize = 48

func (s *Socket) setupRing(mebibytes int) error {
	if mebibytes < 1 || mebibytes > 64 {
		return errors.New("packet ring must be 1..64 MiB")
	}
	if e := unix.SetsockoptInt(s.fd, unix.SOL_PACKET, unix.PACKET_VERSION, unix.TPACKET_V3); e != nil {
		return fmt.Errorf("enable TPACKET_V3: %w", e)
	}
	req := unix.TpacketReq3{Block_size: ringBlockSize, Block_nr: uint32(mebibytes), Frame_size: 2048, Frame_nr: uint32(mebibytes * ringBlockSize / 2048), Retire_blk_tov: 64}
	if e := unix.SetsockoptTpacketReq3(s.fd, unix.SOL_PACKET, unix.PACKET_RX_RING, &req); e != nil {
		return fmt.Errorf("allocate %d MiB PACKET_MMAP ring: %w", mebibytes, e)
	}
	memory, e := unix.Mmap(s.fd, 0, mebibytes*ringBlockSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if e != nil {
		return fmt.Errorf("map packet ring: %w", e)
	}
	s.ring = memory
	s.blockSize = ringBlockSize
	s.blockCount = mebibytes
	s.BufferBytes = len(memory)
	return nil
}
func (s *Socket) status() *uint32 {
	return (*uint32)(unsafe.Pointer(&s.ring[s.blockIndex*s.blockSize+8]))
}
func (s *Socket) release() {
	atomic.StoreUint32(s.status(), unix.TP_STATUS_KERNEL)
	s.owned = false
	s.blockIndex = (s.blockIndex + 1) % s.blockCount
}
func native32(b []byte) uint32 { return binary.NativeEndian.Uint32(b) }

// Next returns a borrowed network-layer packet and its kernel timestamp. The
// bytes remain valid until the next call. UDP parsing is zero-copy; TCP/fragment
// reassembly explicitly copies only bytes it needs to retain.
func (s *Socket) Next() ([]byte, time.Time, error) {
	if len(s.ring) == 0 {
		return nil, time.Time{}, errors.New("packet ring is closed")
	}
	for {
		if s.owned && s.packets == 0 {
			s.release()
		}
		if !s.owned {
			if atomic.LoadUint32(s.status())&unix.TP_STATUS_USER == 0 {
				fds := []unix.PollFd{{Fd: int32(s.fd), Events: unix.POLLIN}}
				n, e := unix.Poll(fds, 250)
				if e == unix.EINTR {
					return nil, time.Time{}, nil
				}
				if e != nil {
					return nil, time.Time{}, e
				}
				if n == 0 {
					return nil, time.Time{}, nil
				}
				if fds[0].Revents&(unix.POLLERR|unix.POLLHUP|unix.POLLNVAL) != 0 {
					return nil, time.Time{}, fmt.Errorf("packet socket poll events: %#x", fds[0].Revents)
				}
				continue
			}
			base := s.blockIndex * s.blockSize
			count := native32(s.ring[base+12:])
			first := int(native32(s.ring[base+16:]))
			used := int(native32(s.ring[base+20:]))
			if used < blockHeaderSize || used > s.blockSize || first < blockHeaderSize || first > used || uint64(count) > uint64(s.blockSize/packetHeaderSize) {
				return nil, time.Time{}, errors.New("invalid TPACKET_V3 block metadata")
			}
			s.owned = true
			s.packets = count
			s.packetOffset = base + first
			s.blockEnd = base + used
			if count == 0 {
				continue
			}
		}
		data, at, next, e := decodeFrame(s.ring, s.packetOffset, s.blockEnd, s.packets)
		if e != nil {
			return nil, time.Time{}, e
		}
		s.Outgoing = false
		if s.trackOutgoing {
			if s.packetOffset+68 > s.blockEnd || binary.NativeEndian.Uint16(s.ring[s.packetOffset+26:]) < 68 {
				return nil, time.Time{}, errors.New("missing packet direction metadata")
			}
			s.Outgoing = s.ring[s.packetOffset+packetHeaderSize+10] == unix.PACKET_OUTGOING
		}
		s.packets--
		s.packetOffset = next
		return data, at, nil
	}
}
func decodeFrame(memory []byte, offset, end int, remaining uint32) ([]byte, time.Time, int, error) {
	fail := func() ([]byte, time.Time, int, error) {
		return nil, time.Time{}, 0, errors.New("invalid or truncated TPACKET_V3 frame")
	}
	if offset < 0 || end < 0 || end > len(memory) || offset > end || end-offset < packetHeaderSize {
		return fail()
	}
	h := memory[offset : offset+packetHeaderSize]
	next := uint64(native32(h))
	sec := native32(h[4:])
	nsec := native32(h[8:])
	snap := uint64(native32(h[12:]))
	wire := uint64(native32(h[16:]))
	mac := uint64(binary.NativeEndian.Uint16(h[24:]))
	network := uint64(binary.NativeEndian.Uint16(h[26:]))
	if nsec >= 1e9 || snap != wire || network < mac || mac < packetHeaderSize || network-mac > snap {
		return fail()
	}
	start := uint64(offset) + network
	size := snap - (network - mac)
	stop := start + size
	if start > uint64(end) || stop > uint64(end) {
		return fail()
	}
	nextOffset := offset
	if remaining > 1 {
		if next < packetHeaderSize || uint64(offset)+next < stop || uint64(offset)+next > uint64(end-packetHeaderSize) {
			return fail()
		}
		nextOffset = offset + int(next)
	}
	return memory[int(start):int(stop)], time.Unix(int64(sec), int64(nsec)), nextOffset, nil
}

// Read is retained for consumers that require an owned byte buffer. Production
// capture uses Next directly and avoids this copy.
func (s *Socket) Read(buf []byte) (int, error) {
	data, _, e := s.Next()
	if e != nil {
		return 0, e
	}
	if len(data) > len(buf) {
		return 0, fmt.Errorf("receive buffer too small: need %d bytes", len(data))
	}
	return copy(buf, data), nil
}
func (s *Socket) Drops() (uint32, error) {
	v, e := unix.GetsockoptTpacketStatsV3(s.fd, unix.SOL_PACKET, unix.PACKET_STATISTICS)
	if e != nil {
		return 0, e
	}
	return v.Drops, nil
}
func (s *Socket) Close() error {
	var e error
	if len(s.ring) > 0 {
		if s.owned {
			s.release()
		}
		e = unix.Munmap(s.ring)
		s.ring = nil
	}
	if s.fd >= 0 {
		e = errors.Join(e, unix.Close(s.fd))
		s.fd = -1
	}
	return e
}
