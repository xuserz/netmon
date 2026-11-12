package network

import (
	"container/list"
	"net/netip"
	"time"

	"netmon/internal/observation"
)

type flowKey struct {
	source, dest netip.Addr
	sport, dport uint16
	protocol     uint8
}
type trackedFlow struct {
	key   flowKey
	class observation.Class
	at    time.Time
}
type flowTracker struct {
	limit          int
	ttl            time.Duration
	index          map[flowKey]*list.Element
	order          *list.List
	evictions      uint64
	uncertainUntil time.Time
	initialized    bool
}

func newFlowTracker(limit int, ttl time.Duration) *flowTracker {
	return &flowTracker{limit: limit, ttl: ttl, index: map[flowKey]*list.Element{}, order: list.New()}
}
func keyFor(p observation.Packet) flowKey {
	return flowKey{p.Source, p.Destination, p.SourcePort, p.Port, p.Protocol}
}
func reverseKey(p observation.Packet) flowKey {
	return flowKey{p.Destination, p.Source, p.Port, p.SourcePort, p.Protocol}
}
func (f *flowTracker) get(k flowKey, now time.Time) (observation.Class, bool) {
	e := f.index[k]
	if e == nil {
		return observation.Unknown, false
	}
	v := e.Value.(*trackedFlow)
	if now.Sub(v.at) > f.ttl {
		delete(f.index, k)
		f.order.Remove(e)
		return observation.Unknown, false
	}
	v.at = now
	f.order.MoveToBack(e)
	return v.class, true
}
func (f *flowTracker) put(k flowKey, class observation.Class, now time.Time) {
	if f.limit == 0 {
		return
	}
	if e := f.index[k]; e != nil {
		v := e.Value.(*trackedFlow)
		v.class = class
		v.at = now
		f.order.MoveToBack(e)
		return
	}
	if len(f.index) >= f.limit {
		e := f.order.Front()
		flow := e.Value.(*trackedFlow)
		delete(f.index, flow.key)
		*flow = trackedFlow{k, class, now}
		f.index[k] = e
		f.order.MoveToBack(e)
		f.evictions++
		f.uncertainUntil = now.Add(f.ttl)
		return
	}
	f.index[k] = f.order.PushBack(&trackedFlow{k, class, now})
}

// Observe sees only packet headers. A missed handshake, expired flow or UDP
// flow first seen inbound stays UNKNOWN; an outbound reply never creates a
// new locally initiated flow when its incoming tuple was already observed.
func (f *flowTracker) Observe(p observation.Packet, outgoing bool, now time.Time) observation.Class {
	if !f.initialized {
		f.initialized = true
		f.uncertainUntil = now.Add(f.ttl)
	}
	if (p.EchoRequest || p.EchoReply) && !p.Fragment {
		k := flowKey{source: p.Source, dest: p.Destination, sport: p.EchoID, protocol: p.Protocol}
		if outgoing {
			if p.EchoRequest && p.Source != p.Destination {
				k.source, k.dest = k.dest, k.source
				f.put(k, observation.Reply, now)
			}
			return observation.Unknown
		}
		if p.EchoRequest {
			return observation.Inbound
		}
		if c, ok := f.get(k, now); ok {
			return c
		}
		return observation.Unknown
	}
	if p.Fragment || p.SourcePort == 0 || p.Port == 0 || (p.Protocol != 6 && p.Protocol != 17) {
		return observation.Unknown
	}
	if outgoing {
		if p.Source == p.Destination {
			return observation.Unknown
		} // loopback duplicate
		k := reverseKey(p)
		if p.Protocol == 6 {
			if p.SYN {
				f.put(k, observation.Reply, now)
			}
		} else {
			if _, known := f.get(k, now); !known {
				class := observation.Reply
				if now.Before(f.uncertainUntil) {
					class = observation.Unknown
				}
				f.put(k, class, now)
			}
		}
		return observation.Unknown
	}
	k := keyFor(p)
	if p.Protocol == 6 && p.SYN {
		f.put(k, observation.Inbound, now)
		return observation.Inbound
	}
	if c, ok := f.get(k, now); ok {
		if p.Protocol == 17 && now.Before(f.uncertainUntil) {
			return observation.Unknown
		}
		return c
	}
	f.put(k, observation.Unknown, now)
	return observation.Unknown
}
