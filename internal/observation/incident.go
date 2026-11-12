package observation

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
)

const IncidentWindow int64 = 600
const MaxFacts = 512

type Fact struct {
	ID      string   `json:"id"`
	Node    string   `json:"node"`
	Name    string   `json:"name"`
	Window  int64    `json:"window"`
	First   int64    `json:"first"`
	Last    int64    `json:"last"`
	Packets int64    `json:"packets"`
	SYN     int64    `json:"syn"`
	PPS     int64    `json:"pps"`
	SynPPS  int64    `json:"syn_pps"`
	Ports   []uint16 `json:"ports,omitempty"`
	Partial bool     `json:"partial,omitempty"`
}

func SampleFact(s Sample) Fact {
	return Fact{ID: s.ID, Node: s.Node, Name: s.Name, Window: s.Window, First: s.First, Last: s.Last, Packets: s.Packets - s.Traffic().Reply, SYN: min(s.SYN, s.Packets-s.Traffic().Reply), PPS: s.Evidence.PPS, SynPPS: s.Evidence.SYN, Ports: append([]uint16(nil), s.Ports...), Partial: s.Partial || s.Details == nil || s.Details.Partial}
}

type Incident struct {
	ID      string   `json:"id"`
	IP      string   `json:"ip"`
	Kind    string   `json:"kind"`
	Bucket  int64    `json:"bucket"`
	First   int64    `json:"first"`
	Last    int64    `json:"last"`
	Score   int      `json:"severity"`
	Nodes   int      `json:"nodes"`
	Ports   []uint16 `json:"ports"`
	Packets int64    `json:"packets"`
	SYN     int64    `json:"syn"`
	Reason  string   `json:"reason"`
	Partial bool     `json:"partial"`
	Facts   []Fact   `json:"facts"`
}

func IncidentID(ip, kind string, bucket int64) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("netmon-incident-v1/%s/%s/%d", ip, kind, bucket)))
	return hex.EncodeToString(h[:16])
}
func CombineFacts(a, b []Fact) ([]Fact, bool, error) {
	byID := map[string]Fact{}
	for _, f := range append(append([]Fact(nil), a...), b...) {
		f.Ports = append([]uint16(nil), f.Ports...)
		if old, ok := byID[f.ID]; ok {
			if old.Node != f.Node || old.Window != f.Window {
				return nil, false, fmt.Errorf("incident fact identity reused")
			}
			f.Name = min(old.Name, f.Name)
			f.First = min(old.First, f.First)
			f.Last = max(old.Last, f.Last)
			f.Packets = max(old.Packets, f.Packets)
			f.SYN = max(old.SYN, f.SYN)
			f.PPS = max(old.PPS, f.PPS)
			f.SynPPS = max(old.SynPPS, f.SynPPS)
			f.Partial = f.Partial || old.Partial
			ports := map[uint16]bool{}
			for _, p := range old.Ports {
				ports[p] = true
			}
			for _, p := range f.Ports {
				ports[p] = true
			}
			f.Ports = nil
			for p := range ports {
				f.Ports = append(f.Ports, p)
			}
			sort.Slice(f.Ports, func(i, j int) bool { return f.Ports[i] < f.Ports[j] })
			if len(f.Ports) > MaxPorts {
				f.Ports = f.Ports[:MaxPorts]
				f.Partial = true
			}
		}
		sort.Slice(f.Ports, func(i, j int) bool { return f.Ports[i] < f.Ports[j] })
		byID[f.ID] = f
	}
	out := make([]Fact, 0, len(byID))
	for _, v := range byID {
		out = append(out, v)
	}
	// Stable selection lets independently derived evidence converge. Capped
	// evidence is an explicit lower bound, never a claim of complete visibility.
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.SYN != b.SYN {
			return a.SYN > b.SYN
		}
		if a.PPS != b.PPS {
			return a.PPS > b.PPS
		}
		return a.ID < b.ID
	})
	partial := len(out) > MaxFacts
	if partial {
		out = out[:MaxFacts]
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, partial, nil
}
func BuildIncident(ip, kind string, bucket int64, facts []Fact, policy Policy) (Incident, bool, error) {
	summary, err := summarizeIncident(ip, bucket, facts, policy)
	if err != nil {
		in := summary.base
		in.Kind = kind
		in.ID = IncidentID(ip, kind, bucket)
		return in, false, err
	}
	return summary.build(kind, policy)
}

// BuildIncidents evaluates all local detection rules from one set of facts.
// The results share read-only facts and ports.
func BuildIncidents(ip string, bucket int64, facts []Fact, policy Policy) ([]Incident, error) {
	summary, err := summarizeIncident(ip, bucket, facts, policy)
	if err != nil {
		return nil, err
	}
	var incidents []Incident
	for _, kind := range [...]string{"port_scan", "distributed_scan", "flood"} {
		in, eligible, err := summary.build(kind, policy)
		if err != nil {
			return nil, err
		}
		if eligible {
			incidents = append(incidents, in)
		}
	}
	return incidents, nil
}

type incidentSummary struct {
	base        Incident
	portCount   int
	allNodes    int
	pps, synPPS int64
	localScan   bool
}

func summarizeIncident(ip string, bucket int64, facts []Fact, policy Policy) (incidentSummary, error) {
	summary := incidentSummary{base: Incident{IP: ip, Bucket: bucket}}
	if bucket < 0 || bucket%IncidentWindow != 0 || len(facts) > MaxFacts {
		return summary, fmt.Errorf("invalid incident bounds")
	}
	in := &summary.base
	seen := map[string]bool{}
	allNodes := map[string]bool{}
	ports := map[uint16]bool{}
	localPorts := map[string]map[uint16]bool{}
	localSYN := map[string]int64{}
	for _, f := range facts {
		if !ValidID(f.ID) || !ValidID(f.Node) || seen[f.ID] || len(f.Name) > 128 || InvalidName(f.Name) || f.Window%60 != 0 || f.Window < bucket || f.Window >= bucket+IncidentWindow || f.First < f.Window || f.Last < f.First || f.Last >= f.Window+60 || f.Packets < 0 || f.SYN < 0 || f.SYN > f.Packets || f.PPS < 0 || f.PPS > f.Packets || f.SynPPS < 0 || f.SynPPS > f.SYN || len(f.Ports) > MaxPorts {
			return summary, fmt.Errorf("invalid incident fact")
		}
		seen[f.ID] = true
		if len(in.Facts) == 0 {
			in.First = f.First
		}
		in.First = min(in.First, f.First)
		in.Last = max(in.Last, f.Last)
		in.Packets = Add(in.Packets, f.Packets)
		in.SYN = Add(in.SYN, f.SYN)
		summary.pps = max(summary.pps, f.PPS)
		summary.synPPS = max(summary.synPPS, f.SynPPS)
		in.Partial = in.Partial || f.Partial
		if f.Packets > 0 {
			allNodes[f.Node] = true
		}
		if f.SYN > 0 {
			localSYN[f.Node] = Add(localSYN[f.Node], f.SYN)
			if localPorts[f.Node] == nil {
				localPorts[f.Node] = map[uint16]bool{}
			}
		}
		distinct := map[uint16]bool{}
		for _, p := range f.Ports {
			if p == 0 || distinct[p] || f.SYN == 0 {
				return summary, fmt.Errorf("invalid incident port evidence")
			}
			distinct[p] = true
			ports[p] = true
			localPorts[f.Node][p] = true
		}
		in.Facts = append(in.Facts, f)
	}
	in.Nodes = len(localSYN)
	summary.allNodes = len(allNodes)
	for node, ports := range localPorts {
		if len(ports) >= policy.Ports && localSYN[node] >= int64(len(ports)*2) {
			summary.localScan = true
			break
		}
	}
	for p := range ports {
		in.Ports = append(in.Ports, p)
	}
	sort.Slice(in.Ports, func(i, j int) bool { return in.Ports[i] < in.Ports[j] })
	// Global distinct-port storage is capped while facts preserve their own sets.
	summary.portCount = len(in.Ports)
	if summary.portCount > MaxPorts {
		in.Ports = in.Ports[:MaxPorts]
		in.Partial = true
	}
	return summary, nil
}

func (summary incidentSummary) build(kind string, policy Policy) (Incident, bool, error) {
	in := summary.base
	in.Kind = kind
	in.ID = IncidentID(in.IP, kind, in.Bucket)
	count := summary.portCount
	eligible := false
	switch kind {
	case "distributed_scan":
		eligible = (in.Nodes >= 2 && count >= policy.Ports && in.SYN >= int64(count*2)) || (in.Nodes >= 3 && count >= 1 && in.SYN >= int64(in.Nodes*2))
		in.Score = min(90, 45+max(0, in.Nodes-2)*5+max(0, count-policy.Ports)*2)
		in.Reason = fmt.Sprintf("observed TCP SYN to %d ports on %d nodes in a fixed 10-minute window", count, in.Nodes)
	case "port_scan":
		eligible = summary.localScan
		in.Score = min(80, 30+max(0, count-policy.Ports)*2)
		in.Reason = fmt.Sprintf("observed repeated TCP SYN to %d ports, including a single-node port scan", count)
	case "flood":
		in.Nodes = summary.allNodes
		eligible = summary.pps >= policy.PPS*4 || summary.synPPS >= policy.SYN*4
		in.Score, _ = policy.Base(Evidence{PPS: summary.pps, SYN: summary.synPPS})
		in.Reason = fmt.Sprintf("observed eligible packet peak %d/s; SYN peak %d/s (retransmissions included)", summary.pps, summary.synPPS)
	default:
		return in, false, fmt.Errorf("unknown incident kind")
	}
	return in, eligible, nil
}
