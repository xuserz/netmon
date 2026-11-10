//go:build linux

package capture

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"

	"golang.org/x/sys/unix"
)

type Socket struct {
	fd                                int
	Interface                         string
	BufferBytes                       int
	ring                              []byte
	blockSize, blockCount, blockIndex int
	owned                             bool
	packets                           uint32
	packetOffset, blockEnd            int
}

func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return binary.NativeEndian.Uint16(b[:])
}
func Open(name string, port uint16, bufferMB int) (*Socket, error) {
	iface, e := net.InterfaceByName(name)
	if e != nil {
		if errors.Is(e, unix.EPERM) || errors.Is(e, unix.EACCES) {
			return nil, fmt.Errorf("cannot inspect interface %q: %w", name, e)
		}
		var names []string
		if all, err := net.Interfaces(); err == nil {
			for _, i := range all {
				names = append(names, i.Name)
			}
		}
		return nil, fmt.Errorf("interface %q not found (available: %s); edit interface in config.yaml", name, strings.Join(names, ", "))
	}
	if iface.Flags&net.FlagUp == 0 {
		return nil, fmt.Errorf("interface %s is down", name)
	}
	// Protocol 0 leaves reception disabled until the filter and binding are ready.
	fd, e := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if e != nil {
		return nil, fmt.Errorf("AF_PACKET (requires CAP_NET_RAW): %w", e)
	}
	s := &Socket{fd: fd, Interface: name}
	ok := false
	defer func() {
		if !ok {
			s.Close()
		}
	}()
	if e = unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_IGNORE_OUTGOING, 1); e != nil {
		return nil, e
	}
	if e = s.setupRing(bufferMB); e != nil {
		return nil, e
	}

	filter := Filter(port)
	if e = unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}); e != nil {
		return nil, fmt.Errorf("attach BPF: %w", e)
	}
	if e = unix.Bind(fd, &unix.SockaddrLinklayer{Ifindex: iface.Index, Protocol: htons(unix.ETH_P_ALL)}); e != nil {
		return nil, e
	}
	ok = true
	return s, nil
}

// Tiny label assembler keeps BPF offsets reviewable. IPv4 checks port in the
// kernel; IPv6 extension chains and fragments need bounded userspace parsing.
func Filter(port uint16) []unix.SockFilter {
	type fix struct {
		i    int
		t, f string
	}
	var code []unix.SockFilter
	labels := map[string]int{}
	var fixes []fix
	emit := func(op uint16, k uint32) { code = append(code, unix.SockFilter{Code: op, K: k}) }
	label := func(s string) { labels[s] = len(code) }
	jump := func(op uint16, k uint32, t, f string) { fixes = append(fixes, fix{len(code), t, f}); emit(op, k) }
	emit(0x20, 0xfffff004) // SKF_AD_PKTTYPE: reject outgoing even on older kernels.
	jump(0x15, unix.PACKET_OUTGOING, "reject", "protocol")
	label("protocol")
	emit(0x20, 0xfffff000) // SKF_AD_PROTOCOL, host-order ethertype.
	jump(0x15, unix.ETH_P_IP, "v4", "try6")
	label("try6")
	jump(0x15, unix.ETH_P_IPV6, "v6", "reject")
	label("v4")
	emit(0x30, 9)
	jump(0x15, 6, "v4frag", "v4udp")
	label("v4udp")
	jump(0x15, 17, "v4frag", "reject")
	label("v4frag")
	emit(0x28, 6)
	jump(0x45, 0x3fff, "accept", "v4port")
	label("v4port")
	emit(0xb1, 0)
	emit(0x48, 2)
	jump(0x15, uint32(port), "accept", "reject")
	label("v6")
	emit(0x30, 6)
	jump(0x15, 6, "v6port", "v6udp")
	label("v6udp")
	jump(0x15, 17, "v6port", "ext0")
	label("ext0")
	jump(0x15, 0, "accept", "ext43")
	label("ext43")
	jump(0x15, 43, "accept", "ext44")
	label("ext44")
	jump(0x15, 44, "accept", "ext51")
	label("ext51")
	jump(0x15, 51, "accept", "ext60")
	label("ext60")
	jump(0x15, 60, "accept", "reject")
	label("v6port")
	emit(0x28, 42)
	jump(0x15, uint32(port), "accept", "reject")
	label("accept")
	emit(0x06, 65575)
	label("reject")
	emit(0x06, 0)
	for _, f := range fixes {
		code[f.i].Jt = uint8(labels[f.t] - f.i - 1)
		code[f.i].Jf = uint8(labels[f.f] - f.i - 1)
	}
	return code
}
