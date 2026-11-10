package packet

// validDNS validates wire structure without allocating or decoding/storing
// names. It accepts EDNS, NOTIFY, UPDATE and DSO as well as ordinary queries.
func validDNS(b []byte) bool {
	if len(b) < 12 || b[2]&0x80 != 0 || b[3]&0x40 != 0 {
		return false
	}
	opcode := (b[2] >> 3) & 15
	if opcode == 6 {
		for i := 4; i < 12; i++ {
			if b[i] != 0 {
				return false
			}
		}
		if len(b) < 16 {
			return false
		}
		for off := 12; off < len(b); {
			if off+4 > len(b) {
				return false
			}
			n := int(u16(b[off+2 : off+4]))
			off += 4
			if off+n > len(b) {
				return false
			}
			off += n
		}
		return true
	}
	switch opcode {
	case 0, 1, 2, 4, 5:
	default:
		return false
	}
	questions := int(u16(b[4:6]))
	// RFC 7873 permits zero-question COOKIE probes. Verify their OPT
	// structure below rather than discarding them or accepting empty junk.
	cookieProbe := false
	off := 12
	for i := 0; i < questions; i++ {
		var ok bool
		off, ok = dnsName(b, off)
		if !ok || off+4 > len(b) {
			return false
		}
		off += 4
	}
	records := int(u16(b[6:8])) + int(u16(b[8:10])) + int(u16(b[10:12]))
	for i := 0; i < records; i++ {
		var ok bool
		off, ok = dnsName(b, off)
		if !ok || off+10 > len(b) {
			return false
		}
		recordType := u16(b[off : off+2])
		n := int(u16(b[off+8 : off+10]))
		off += 10
		if off+n > len(b) {
			return false
		}
		if recordType == 41 {
			for option := off; option < off+n; {
				if option+4 > off+n {
					return false
				}
				code := u16(b[option : option+2])
				size := int(u16(b[option+2 : option+4]))
				option += 4
				if option+size > off+n {
					return false
				}
				if code == 10 && (size == 8 || size >= 16 && size <= 40) && i >= int(u16(b[6:8]))+int(u16(b[8:10])) {
					cookieProbe = true
				}
				option += size
			}
		}
		off += n
	}
	return off == len(b) && (opcode != 0 || questions > 0 || cookieProbe)
}
func dnsName(b []byte, start int) (int, bool) {
	pos, end, wire := start, -1, 0
	for steps := 0; steps < 256; steps++ {
		if pos >= len(b) {
			return 0, false
		}
		n := int(b[pos])
		switch n & 0xc0 {
		case 0:
			pos++
			wire += n + 1
			if wire > 255 || pos+n > len(b) {
				return 0, false
			}
			if n == 0 {
				if end < 0 {
					end = pos
				}
				return end, true
			}
			pos += n
		case 0xc0:
			if pos+1 >= len(b) {
				return 0, false
			}
			target := int(u16(b[pos:pos+2]) & 0x3fff)
			if target < 12 || target >= pos {
				return 0, false
			}
			if end < 0 {
				end = pos + 2
			}
			pos = target
		default:
			return 0, false
		}
	}
	return 0, false
}
