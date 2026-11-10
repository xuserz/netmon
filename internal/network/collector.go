package network

import (
	"container/list"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"sort"
	"sync/atomic"
	"time"

	"netmon/internal/observation"
)

type portTime struct {
	port uint16
	at   int64
}
type entry struct {
	detail                              atomic.Pointer[observation.Sample]
	inbound, reply, unknown             atomic.Int64
	ip                                  netip.Addr
	sample                              observation.Sample
	ack                                 *atomic.Int64
	dirty                               bool
	ports                               []portTime
	second, secondPackets, secondSyn    int64
	seq                                 atomic.Uint64
	packets, bytes, tcp, syn, udp, icmp atomic.Int64
	first, last, peak                   atomic.Int64
	riskAt, riskPPS, riskSYN, riskPorts atomic.Int64
	partial                             atomic.Bool
	slot                                int
}
type collector struct {
	node, name                                                        string
	policy                                                            observation.Policy
	limit                                                             int
	detailTargets                                                     int
	index                                                             map[netip.Addr]*list.Element
	order                                                             *list.List
	slots                                                             []atomic.Pointer[entry]
	count                                                             atomic.Int64
	sequence                                                          uint64
	seed                                                              [32]byte
	queue                                                             *memoryQueue
	evictions                                                         atomic.Uint64
	evictedAt                                                         atomic.Int64
	totalPackets, totalBytes, totalTCP, totalSYN, totalUDP, totalICMP atomic.Int64
}

func newCollector(node, name string, limit int, policy observation.Policy, q *memoryQueue) *collector {
	limit = max(1, limit)
	return &collector{detailTargets: 16, node: node, name: name, policy: policy, limit: limit, index: map[netip.Addr]*list.Element{}, order: list.New(), slots: make([]atomic.Pointer[entry], limit), queue: q, seed: sha256.Sum256([]byte(observation.ID()))}
}
func (c *collector) id() string {
	c.sequence++
	var b [40]byte
	copy(b[:32], c.seed[:])
	binary.BigEndian.PutUint64(b[32:], c.sequence)
	hash := sha256.Sum256(b[:])
	return hex.EncodeToString(hash[:16])
}
func (c *collector) emit(e *entry, final bool) {
	if e.sample.Packets == 0 || !e.dirty {
		return
	}
	snapshot := e.sample
	snapshot.Details = e.sample.Details.Clone()
	snapshot.Ports = append([]uint16(nil), e.sample.Ports...)
	e.detail.Store(&snapshot)
	if c.queue.put(e.sample, e.ack) {
		e.dirty = false
	} else if final {
		c.queue.discarded.Add(1)
	}
}
func (c *collector) add(p observation.Packet, at time.Time) {
	sec := at.Unix()
	if sec < 0 {
		return
	}
	element := c.index[p.Source]
	var e *entry
	if element == nil {
		slot := int(c.count.Load())
		if len(c.index) == c.limit {
			old := c.order.Front()
			prior := old.Value.(*entry)
			slot = prior.slot
			c.emit(prior, true)
			delete(c.index, prior.ip)
			c.order.Remove(old)
			c.evictions.Add(1)
			c.evictedAt.Store(sec)
		}
		e = &entry{ip: p.Source, slot: slot}
		e.first.Store(sec)
		element = c.order.PushBack(e)
		c.index[p.Source] = element
		c.slots[slot].Store(e)
		if c.count.Load() < int64(c.limit) {
			c.count.Add(1)
		}
	} else {
		c.order.MoveToBack(element)
		e = element.Value.(*entry)
	}
	window := sec / 60 * 60
	if e.sample.ID == "" || e.sample.Window != window {
		c.emit(e, true)
		e.sample = observation.Sample{ID: c.id(), Node: c.node, Name: c.name, IP: p.Source.String(), Window: window, First: sec, Last: sec, Details: &observation.Details{}}
		e.ack = &atomic.Int64{}
	}
	e.seq.Add(1)
	e.sample.First = min(e.sample.First, sec)
	e.sample.Last = max(e.sample.Last, sec)
	add := observation.Counters{Packets: 1, Bytes: int64(p.Length)}
	switch p.Protocol {
	case 6:
		add.TCP = 1
		if p.SYN {
			add.SYN = 1
		}
	case 17:
		add.UDP = 1
	case 1, 58:
		add.ICMP = 1
	}
	e.sample.Counters = e.sample.Counters.Plus(add)
	e.sample.Details.Add(p, c.detailTargets)
	switch p.Class {
	case observation.Inbound:
		e.inbound.Add(1)
	case observation.Reply:
		e.reply.Add(1)
	default:
		e.unknown.Add(1)
	}
	e.packets.Store(observation.Add(e.packets.Load(), 1))
	e.bytes.Store(observation.Add(e.bytes.Load(), int64(p.Length)))
	e.tcp.Store(observation.Add(e.tcp.Load(), add.TCP))
	e.syn.Store(observation.Add(e.syn.Load(), add.SYN))
	e.udp.Store(observation.Add(e.udp.Load(), add.UDP))
	e.icmp.Store(observation.Add(e.icmp.Load(), add.ICMP))
	e.last.Store(max(e.last.Load(), sec))
	e.first.Store(min(e.first.Load(), sec))
	if e.second != sec {
		e.second = sec
		e.secondPackets = 0
		e.secondSyn = 0
	}
	if p.Class != observation.Reply {
		e.secondPackets++
		e.secondSyn += add.SYN
	}
	e.sample.PeakPPS = max(e.sample.PeakPPS, e.secondPackets)
	e.peak.Store(max(e.peak.Load(), e.secondPackets))
	if p.SYN && p.Port != 0 {
		filtered := e.ports[:0]
		found := false
		for _, port := range e.ports {
			if port.at < sec-59 {
				continue
			}
			if port.port == p.Port {
				port.at = sec
				found = true
			}
			filtered = append(filtered, port)
		}
		e.ports = filtered
		if !found && len(e.ports) < observation.MaxPorts {
			e.ports = append(e.ports, portTime{p.Port, sec})
		}
		e.sample.Ports = unionPorts(e.sample.Ports, []uint16{p.Port})
	}
	ports := 0
	for _, port := range e.ports {
		if port.at >= sec-59 {
			ports++
		}
	}
	candidate := observation.Evidence{At: sec, PPS: e.secondPackets, SYN: e.secondSyn, Ports: ports}
	if c.policy.Better(candidate, e.sample.Evidence) {
		e.sample.Evidence = candidate
	}
	old := observation.Evidence{At: e.riskAt.Load(), PPS: e.riskPPS.Load(), SYN: e.riskSYN.Load(), Ports: int(e.riskPorts.Load())}
	if c.policy.Better(candidate, old) {
		e.riskAt.Store(sec)
		e.riskPPS.Store(candidate.PPS)
		e.riskSYN.Store(candidate.SYN)
		e.riskPorts.Store(int64(candidate.Ports))
	}
	if c.evictions.Load() > 0 && c.evictedAt.Load() >= sec-60 {
		e.sample.Partial = true
		e.partial.Store(true)
	}
	e.dirty = true
	e.seq.Add(1)
	c.totalPackets.Add(1)
	c.totalBytes.Add(int64(p.Length))
	c.totalTCP.Add(add.TCP)
	c.totalSYN.Add(add.SYN)
	c.totalUDP.Add(add.UDP)
	c.totalICMP.Add(add.ICMP)
}
func (c *collector) flush() {
	for _, value := range c.index {
		c.emit(value.Value.(*entry), false)
	}
}
func (c *collector) snapshot(now time.Time) ([]observation.IP, observation.Totals) {
	result := make([]observation.IP, 0, c.count.Load())
	seen := map[string]int{}
	for i, n := int64(0), c.count.Load(); i < n; i++ {
		e := c.slots[i].Load()
		if e == nil {
			continue
		}
		for attempt := 0; attempt < 8; attempt++ {
			seq := e.seq.Load()
			if seq&1 != 0 {
				continue
			}
			row := observation.IP{Traffic: observation.Traffic{Inbound: e.inbound.Load(), Reply: e.reply.Load(), Unknown: e.unknown.Load()}, IP: e.ip.String(), Counters: observation.Counters{Packets: e.packets.Load(), Bytes: e.bytes.Load(), TCP: e.tcp.Load(), SYN: e.syn.Load(), UDP: e.udp.Load(), ICMP: e.icmp.Load()}, First: e.first.Load(), Last: e.last.Load(), PeakPPS: e.peak.Load(), Partial: e.partial.Load()}
			evidence := observation.Evidence{At: e.riskAt.Load(), PPS: e.riskPPS.Load(), SYN: e.riskSYN.Load(), Ports: int(e.riskPorts.Load())}
			if row.Packets == 0 {
				break
			}
			if seq != e.seq.Load() {
				continue
			}
			row.Score, row.Reasons = c.policy.Score(evidence, now)
			row.IntensityScore = row.Score
			row.EvidenceAt = evidence.At
			if index, exists := seen[row.IP]; exists {
				old := result[index]
				old.Counters = old.Counters.Plus(row.Counters)
				old.Traffic = old.Traffic.Plus(row.Traffic)
				old.First = min(old.First, row.First)
				old.Last = max(old.Last, row.Last)
				old.PeakPPS = max(old.PeakPPS, row.PeakPPS)
				old.Partial = true
				if row.Score > old.Score || row.Score == old.Score && row.EvidenceAt > old.EvidenceAt {
					old.Score = row.Score
					old.Reasons = row.Reasons
					old.EvidenceAt = row.EvidenceAt
				}
				result[index] = old
			} else {
				seen[row.IP] = len(result)
				result = append(result, row)
			}
			break
		}
	}
	totals := observation.Totals{IPs: int64(len(result)), Counters: observation.Counters{Packets: c.totalPackets.Load(), Bytes: c.totalBytes.Load(), TCP: c.totalTCP.Load(), SYN: c.totalSYN.Load(), UDP: c.totalUDP.Load(), ICMP: c.totalICMP.Load()}}
	return result, totals
}
func sortRows(rows []observation.IP, kind string) {
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		switch kind {
		case "score":
			if a.Score != b.Score {
				return a.Score > b.Score
			}
		case "bytes":
			if a.Bytes != b.Bytes {
				return a.Bytes > b.Bytes
			}
		case "syn":
			if a.SYN != b.SYN {
				return a.SYN > b.SYN
			}
		}
		if a.Packets != b.Packets {
			return a.Packets > b.Packets
		}
		return a.IP < b.IP
	})
}
