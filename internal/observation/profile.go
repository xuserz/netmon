package observation

import "sort"

type NodeProfile struct {
	Node string `json:"node"`
	Name string `json:"name"`
	Counters
	Traffic Traffic `json:"traffic"`
}
type TargetProfile struct {
	Node string `json:"node"`
	Name string `json:"name"`
	Target
}
type Profile struct {
	IP      string `json:"ip"`
	Since   int64  `json:"since"`
	Until   int64  `json:"until"`
	Rows    int64  `json:"observation_rows"`
	Partial bool   `json:"partial"`
	Counters
	Traffic      Traffic         `json:"traffic"`
	Unattributed int64           `json:"packets_without_port_detail"`
	Nodes        []NodeProfile   `json:"nodes"`
	Targets      []TargetProfile `json:"targets"`
}
type targetKey struct {
	node     string
	protocol uint8
	port     uint16
	class    Class
}
type ProfileBuilder struct {
	Profile
	nodes   map[string]int
	targets map[targetKey]int
}

func NewProfile(ip string, since, until int64) *ProfileBuilder {
	return &ProfileBuilder{Profile: Profile{IP: ip, Since: since, Until: until}, nodes: map[string]int{}, targets: map[targetKey]int{}}
}
func (p *ProfileBuilder) Add(s Sample) {
	p.Rows++
	p.Counters = p.Counters.Plus(s.Counters)
	p.Traffic = p.Traffic.Plus(s.Traffic())
	p.Partial = p.Partial || s.Partial
	i, ok := p.nodes[s.Node]
	if !ok {
		if len(p.Nodes) < 512 {
			i = len(p.Nodes)
			p.nodes[s.Node] = i
			p.Nodes = append(p.Nodes, NodeProfile{Node: s.Node, Name: s.Name})
		} else {
			p.Partial = true
			i = -1
		}
	}
	if i >= 0 {
		n := &p.Nodes[i]
		n.Counters = n.Counters.Plus(s.Counters)
		n.Traffic = n.Traffic.Plus(s.Traffic())
	}
	var attributed int64
	if s.Details == nil {
		p.Partial = true
	} else {
		p.Partial = p.Partial || s.Details.Partial
		for _, t := range s.Details.Targets {
			key := targetKey{s.Node, t.Protocol, t.Port, t.Class}
			j, ok := p.targets[key]
			if !ok {
				if len(p.Targets) >= 4096 {
					p.Partial = true
					continue
				}
				j = len(p.Targets)
				p.targets[key] = j
				p.Targets = append(p.Targets, TargetProfile{Node: s.Node, Name: s.Name, Target: Target{Protocol: t.Protocol, Port: t.Port, Class: t.Class}})
			}
			p.Targets[j].Counters = p.Targets[j].Counters.Plus(t.Counters)
			attributed = Add(attributed, t.Packets)
		}
	}
	p.Unattributed = Add(p.Unattributed, s.Packets-attributed)
}
func (p *ProfileBuilder) Finish() Profile {
	sort.Slice(p.Nodes, func(i, j int) bool {
		a, b := p.Nodes[i], p.Nodes[j]
		if a.Packets != b.Packets {
			return a.Packets > b.Packets
		}
		return a.Node < b.Node
	})
	sort.Slice(p.Targets, func(i, j int) bool {
		a, b := p.Targets[i], p.Targets[j]
		if a.Packets != b.Packets {
			return a.Packets > b.Packets
		}
		if a.Node != b.Node {
			return a.Node < b.Node
		}
		if a.Protocol != b.Protocol {
			return a.Protocol < b.Protocol
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		return a.Class < b.Class
	})
	return p.Profile
}
