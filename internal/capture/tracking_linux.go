//go:build linux

package capture

import "golang.org/x/sys/unix"

// TrackingFilter keeps all ingress IP packets and only egress UDP / TCP SYN.
// Egress IPv6 extension chains use bounded userspace header parsing.
func TrackingFilter() []unix.SockFilter {
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
	emit(0x20, 0xfffff004)
	jump(0x15, unix.PACKET_OUTGOING, "out", "in")
	label("in")
	emit(0x20, 0xfffff000)
	jump(0x15, unix.ETH_P_IP, "accept", "in6")
	label("in6")
	jump(0x15, unix.ETH_P_IPV6, "accept", "reject")
	label("out")
	emit(0x20, 0xfffff000)
	jump(0x15, unix.ETH_P_IP, "v4", "out6")
	label("out6")
	jump(0x15, unix.ETH_P_IPV6, "v6", "reject")
	label("v4")
	emit(0x30, 9)
	jump(0x15, 17, "accept", "icmp4")
	label("icmp4")
	jump(0x15, 1, "accept", "tcp4")
	label("tcp4")
	jump(0x15, 6, "frag4", "reject")
	label("frag4")
	emit(0x28, 6)
	jump(0x45, 0x3fff, "reject", "flags4")
	label("flags4")
	emit(0xb1, 0)
	emit(0x50, 13)
	jump(0x45, 2, "ack", "reject")
	label("v6")
	emit(0x30, 6)
	jump(0x15, 17, "accept", "icmp6")
	label("icmp6")
	jump(0x15, 58, "accept", "tcp6")
	label("tcp6")
	jump(0x15, 6, "flags6", "ext0")
	label("flags6")
	emit(0x30, 53)
	jump(0x45, 2, "ack", "reject")
	label("ack")
	jump(0x45, 16, "reject", "accept")
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
