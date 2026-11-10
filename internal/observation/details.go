package observation

import (
	"fmt"
	"sort"
)

type Traffic struct {
	Unknown int64 `json:"unknown"`
	Inbound int64 `json:"inbound"`
	Reply   int64 `json:"reply"`
}

func (t Traffic) Packets() int64 { return Add(Add(t.Unknown, t.Inbound), t.Reply) }
func (t Traffic) Plus(b Traffic) Traffic {
	return Traffic{Add(t.Unknown, b.Unknown), Add(t.Inbound, b.Inbound), Add(t.Reply, b.Reply)}
}
func (t Traffic) Minus(b Traffic) Traffic {
	return Traffic{t.Unknown - b.Unknown, t.Inbound - b.Inbound, t.Reply - b.Reply}
}

type Class uint8

const (
	Unknown Class = iota
	Inbound
	Reply
)

func (c Class) String() string {
	switch c {
	case Inbound:
		return "INBOUND"
	case Reply:
		return "REPLY"
	}
	return "UNKNOWN"
}

const MaxTargets = 64

type Target struct {
	Protocol uint8  `json:"protocol"`
	Port     uint16 `json:"port"`
	Class    Class  `json:"class"`
	Counters
}
type Details struct {
	Traffic Traffic  `json:"traffic"`
	Targets []Target `json:"targets,omitempty"`
	Partial bool     `json:"partial,omitempty"`
}

func (d *Details) Clone() *Details {
	if d == nil {
		return nil
	}
	copy := *d
	copy.Targets = append([]Target(nil), d.Targets...)
	return &copy
}
func (s Sample) Traffic() Traffic {
	if s.Details == nil {
		return Traffic{Unknown: s.Packets}
	}
	return s.Details.Traffic
}
func (d *Details) Add(p Packet, limit int) {
	switch p.Class {
	case Inbound:
		d.Traffic.Inbound = Add(d.Traffic.Inbound, 1)
	case Reply:
		d.Traffic.Reply = Add(d.Traffic.Reply, 1)
	default:
		d.Traffic.Unknown = Add(d.Traffic.Unknown, 1)
	}
	for i := range d.Targets {
		t := &d.Targets[i]
		if t.Protocol == p.Protocol && t.Port == p.Port && t.Class == p.Class {
			t.Counters = t.Counters.Plus(p.Counters())
			return
		}
	}
	if len(d.Targets) >= limit {
		d.Partial = true
		return
	}
	d.Targets = append(d.Targets, Target{Protocol: p.Protocol, Port: p.Port, Class: p.Class, Counters: p.Counters()})
}
func (p Packet) Counters() Counters {
	c := Counters{Packets: 1, Bytes: int64(p.Length)}
	switch p.Protocol {
	case 6:
		c.TCP = 1
		if p.SYN {
			c.SYN = 1
		}
	case 17:
		c.UDP = 1
	case 1, 58:
		c.ICMP = 1
	}
	return c
}
func (s Sample) ValidateDetails() error {
	d := s.Details
	if d == nil {
		return nil
	}
	t := d.Traffic
	if t.Unknown < 0 || t.Inbound < 0 || t.Reply < 0 || t.Unknown > s.Packets || t.Inbound > s.Packets-t.Unknown || t.Reply != s.Packets-t.Unknown-t.Inbound || len(d.Targets) > MaxTargets {
		return fmt.Errorf("invalid traffic classification totals")
	}
	seen := map[[3]uint16]bool{}
	var counters Counters
	var classes [3]int64
	for _, v := range d.Targets {
		k := [3]uint16{uint16(v.Protocol), v.Port, uint16(v.Class)}
		c := v.Counters
		if seen[k] || v.Class > Reply || c.Packets < 1 || c.Bytes < c.Packets || !counters.CanAdd(c) || c.TCP < 0 || c.SYN < 0 || c.UDP < 0 || c.ICMP < 0 || c.SYN > c.TCP {
			return fmt.Errorf("invalid target detail")
		}
		seen[k] = true
		expected := Counters{Packets: c.Packets, Bytes: c.Bytes}
		switch v.Protocol {
		case 6:
			expected.TCP = c.Packets
			expected.SYN = c.SYN
		case 17:
			expected.UDP = c.Packets
		case 1, 58:
			expected.ICMP = c.Packets
		}
		if c != expected {
			return fmt.Errorf("target protocol counters disagree")
		}
		counters = counters.Plus(c)
		classes[v.Class] = Add(classes[v.Class], c.Packets)
	}
	if counters.Packets > s.Packets || counters.Bytes > s.Bytes || counters.TCP > s.TCP || counters.SYN > s.SYN || counters.UDP > s.UDP || counters.ICMP > s.ICMP || classes[Unknown] > t.Unknown || classes[Inbound] > t.Inbound || classes[Reply] > t.Reply {
		return fmt.Errorf("target details exceed observation counters")
	}
	if !d.Partial && counters != s.Counters {
		return fmt.Errorf("complete target details do not cover observation")
	}
	return nil
}
func MergeDetails(a, b *Details) (*Details, error) {
	if a == nil || b == nil {
		if a == nil && b == nil {
			return nil, nil
		}
		return nil, fmt.Errorf("observation detail capability changed")
	}
	out := a.Clone()
	out.Traffic = Traffic{max(a.Traffic.Unknown, b.Traffic.Unknown), max(a.Traffic.Inbound, b.Traffic.Inbound), max(a.Traffic.Reply, b.Traffic.Reply)}
	out.Partial = a.Partial || b.Partial
	for _, v := range b.Targets {
		found := false
		for i := range out.Targets {
			t := &out.Targets[i]
			if t.Protocol == v.Protocol && t.Port == v.Port && t.Class == v.Class {
				t.Counters = t.Counters.Max(v.Counters)
				found = true
				break
			}
		}
		if !found {
			out.Targets = append(out.Targets, v)
		}
	}
	if len(out.Targets) > MaxTargets {
		return nil, fmt.Errorf("too many merged target details")
	}
	SortTargets(out.Targets)
	return out, nil
}
func SortTargets(ts []Target) {
	sort.Slice(ts, func(i, j int) bool {
		a, b := ts[i], ts[j]
		if a.Protocol != b.Protocol {
			return a.Protocol < b.Protocol
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		return a.Class < b.Class
	})
}
