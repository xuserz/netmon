package network

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math"

	"netmon/internal/observation"
)

// Observation payload v1. Identity/node/IP/window live in SQLite columns; only
// the remaining fields are encoded here. The transport still uses normal JSON.
var sampleMagic = []byte{'N', 'M', 1}

const sampleColumns = "id,node,ip,window,payload"

var errPayload = errors.New("invalid network observation payload")

func encodeSample(s observation.Sample) []byte {
	out := make([]byte, 0, 64+len(s.Name)+len(s.Ports)*2)
	out = append(out, sampleMagic...)
	if s.Details != nil {
		out[2] = 2
	}
	flags := byte(0)
	if s.Partial {
		flags |= 1
	}
	if s.Evidence.At != 0 {
		flags |= 2
	}
	out = append(out, flags)
	out = binary.AppendUvarint(out, uint64(len(s.Name)))
	out = append(out, s.Name...)
	for _, n := range []int64{s.Packets, s.Bytes, s.TCP, s.SYN, s.UDP, s.ICMP, s.First - s.Window, s.Last - s.Window, s.PeakPPS} {
		out = binary.AppendUvarint(out, uint64(n))
	}
	out = binary.AppendUvarint(out, uint64(len(s.Ports)))
	for _, port := range s.Ports {
		out = binary.AppendUvarint(out, uint64(port))
	}
	if flags&2 != 0 {
		out = binary.AppendVarint(out, s.Evidence.At-s.Window)
		for _, n := range []int64{s.Evidence.PPS, s.Evidence.SYN, int64(s.Evidence.Ports)} {
			out = binary.AppendUvarint(out, uint64(n))
		}
	}
	if s.Details != nil {
		d := s.Details
		for _, v := range []int64{d.Traffic.Unknown, d.Traffic.Inbound, d.Traffic.Reply} {
			out = binary.AppendUvarint(out, uint64(v))
		}
		if d.Partial {
			out = append(out, 1)
		} else {
			out = append(out, 0)
		}
		out = binary.AppendUvarint(out, uint64(len(d.Targets)))
		targets := append([]observation.Target(nil), d.Targets...)
		observation.SortTargets(targets)
		for _, t := range targets {
			for _, v := range []int64{int64(t.Protocol), int64(t.Port), int64(t.Class), t.Packets, t.Bytes, t.TCP, t.SYN, t.UDP, t.ICMP} {
				out = binary.AppendUvarint(out, uint64(v))
			}
		}
	}
	return out
}

type sampleDecoder struct {
	data []byte
	err  error
}

func (d *sampleDecoder) unsigned() int64 {
	if d.err != nil {
		return 0
	}
	v, n := binary.Uvarint(d.data)
	if n <= 0 || v > math.MaxInt64 {
		d.err = errPayload
		return 0
	}
	d.data = d.data[n:]
	return int64(v)
}
func (d *sampleDecoder) signed() int64 {
	if d.err != nil {
		return 0
	}
	v, n := binary.Varint(d.data)
	if n <= 0 {
		d.err = errPayload
		return 0
	}
	d.data = d.data[n:]
	return v
}
func decodeSample(id, node, ip string, window int64, raw []byte) (observation.Sample, error) {
	s := observation.Sample{ID: id, Node: node, IP: ip, Window: window}
	if len(raw) > 0 && raw[0] == '{' {
		// Existing JSON databases remain readable without an eager rewrite.
		var legacy observation.Sample
		if e := json.Unmarshal(raw, &legacy); e != nil {
			return s, e
		}
		if legacy.ID != id || legacy.Node != node || legacy.IP != ip || legacy.Window != window {
			return s, errPayload
		}
		if legacy.Details != nil {
			observation.SortTargets(legacy.Details.Targets)
		}
		return legacy, nil
	}
	if len(raw) < 4 || !bytes.Equal(raw[:2], sampleMagic[:2]) || (raw[2] != 1 && raw[2] != 2) || raw[3]&^byte(3) != 0 {
		return s, errPayload
	}
	flags := raw[3]
	d := sampleDecoder{data: raw[4:]}
	n := d.unsigned()
	if d.err != nil || n > 128 || n > int64(len(d.data)) {
		return s, errPayload
	}
	s.Name = string(d.data[:int(n)])
	d.data = d.data[int(n):]
	s.Packets = d.unsigned()
	s.Bytes = d.unsigned()
	s.TCP = d.unsigned()
	s.SYN = d.unsigned()
	s.UDP = d.unsigned()
	s.ICMP = d.unsigned()
	first, last := d.unsigned(), d.unsigned()
	if first >= 60 || last >= 60 || window < 0 || window > math.MaxInt64-60 {
		return s, errPayload
	}
	s.First = window + first
	s.Last = window + last
	s.PeakPPS = d.unsigned()
	ports := d.unsigned()
	if d.err != nil || ports > observation.MaxPorts {
		return s, errPayload
	}
	for i := int64(0); i < ports; i++ {
		port := d.unsigned()
		if port < 1 || port > 65535 {
			return s, errPayload
		}
		s.Ports = append(s.Ports, uint16(port))
	}
	s.Partial = flags&1 != 0
	if flags&2 != 0 {
		at := d.signed()
		if at < -60 || at > 59 || window+at <= 0 {
			return s, errPayload
		}
		s.Evidence.At = window + at
		s.Evidence.PPS = d.unsigned()
		s.Evidence.SYN = d.unsigned()
		n = d.unsigned()
		if n > observation.MaxPorts {
			return s, errPayload
		}
		s.Evidence.Ports = int(n)
	}
	if raw[2] == 2 {
		detail := &observation.Details{Traffic: observation.Traffic{Unknown: d.unsigned(), Inbound: d.unsigned(), Reply: d.unsigned()}}
		partial := d.unsigned()
		count := d.unsigned()
		if partial > 1 || count > observation.MaxTargets {
			return s, errPayload
		}
		detail.Partial = partial == 1
		for i := int64(0); i < count; i++ {
			protocol, port, class := d.unsigned(), d.unsigned(), d.unsigned()
			if protocol > 255 || port > 65535 || class > 2 {
				return s, errPayload
			}
			t := observation.Target{Protocol: uint8(protocol), Port: uint16(port), Class: observation.Class(class)}
			t.Packets = d.unsigned()
			t.Bytes = d.unsigned()
			t.TCP = d.unsigned()
			t.SYN = d.unsigned()
			t.UDP = d.unsigned()
			t.ICMP = d.unsigned()
			detail.Targets = append(detail.Targets, t)
		}
		observation.SortTargets(detail.Targets)
		s.Details = detail
		if e := s.ValidateDetails(); e != nil {
			return s, e
		}
	}
	if d.err != nil || len(d.data) != 0 {
		return s, errPayload
	}
	return s, nil
}
func scanSample(row interface{ Scan(...any) error }) (observation.Sample, error) {
	var id, node, ip string
	var window int64
	var raw []byte
	if e := row.Scan(&id, &node, &ip, &window, &raw); e != nil {
		return observation.Sample{}, e
	}
	return decodeSample(id, node, ip, window, raw)
}
