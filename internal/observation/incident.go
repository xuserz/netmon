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
	in := Incident{IP: ip, Kind: kind, Bucket: bucket, ID: IncidentID(ip, kind, bucket)}
	if bucket < 0 || bucket%IncidentWindow != 0 || len(facts) > MaxFacts {
		return in, false, fmt.Errorf("invalid incident bounds")
	}
	seen := map[string]bool{}
	nodes := map[string]bool{}
	ports := map[uint16]bool{}
	localPorts := map[string]map[uint16]bool{}
	localSYN := map[string]int64{}
	var pps, synPPS int64
	for _, f := range facts {
		if !ValidID(f.ID) || !ValidID(f.Node) || seen[f.ID] || len(f.Name) > 128 || InvalidName(f.Name) || f.Window%60 != 0 || f.Window < bucket || f.Window >= bucket+IncidentWindow || f.First < f.Window || f.Last < f.First || f.Last >= f.Window+60 || f.Packets < 0 || f.SYN < 0 || f.SYN > f.Packets || f.PPS < 0 || f.PPS > f.Packets || f.SynPPS < 0 || f.SynPPS > f.SYN || len(f.Ports) > MaxPorts {
			return in, false, fmt.Errorf("invalid incident fact")
		}
		seen[f.ID] = true
		if len(in.Facts) == 0 {
			in.First = f.First
		}
		in.First = min(in.First, f.First)
		in.Last = max(in.Last, f.Last)
		in.Packets = Add(in.Packets, f.Packets)
		in.SYN = Add(in.SYN, f.SYN)
		pps = max(pps, f.PPS)
		synPPS = max(synPPS, f.SynPPS)
		in.Partial = in.Partial || f.Partial
		if f.SYN > 0 {
			nodes[f.Node] = true
			localSYN[f.Node] = Add(localSYN[f.Node], f.SYN)
			if localPorts[f.Node] == nil {
				localPorts[f.Node] = map[uint16]bool{}
			}
		}
		distinct := map[uint16]bool{}
		for _, p := range f.Ports {
			if p == 0 || distinct[p] || f.SYN == 0 {
				return in, false, fmt.Errorf("invalid incident port evidence")
			}
			distinct[p] = true
			ports[p] = true
			localPorts[f.Node][p] = true
		}
		in.Facts = append(in.Facts, f)
	}
	in.Nodes = len(nodes)
	for p := range ports {
		in.Ports = append(in.Ports, p)
	}
	sort.Slice(in.Ports, func(i, j int) bool { return in.Ports[i] < in.Ports[j] })
	// Global distinct-port storage is capped while facts preserve their own sets.
	count := len(in.Ports)
	if count > MaxPorts {
		in.Ports = in.Ports[:MaxPorts]
		in.Partial = true
	}
	eligible := false
	switch kind {
	case "distributed_scan":
		eligible = (in.Nodes >= 2 && count >= policy.Ports && in.SYN >= int64(count*2)) || (in.Nodes >= 3 && count >= 1 && in.SYN >= int64(in.Nodes*2))
		in.Score = min(90, 45+max(0, in.Nodes-2)*5+max(0, count-policy.Ports)*2)
		in.Reason = fmt.Sprintf("observed TCP SYN to %d ports on %d nodes in a fixed 10-minute window", count, in.Nodes)
	case "port_scan":
		for n, p := range localPorts {
			if len(p) >= policy.Ports && localSYN[n] >= int64(len(p)*2) {
				eligible = true
			}
		}
		in.Score = min(80, 30+max(0, count-policy.Ports)*2)
		in.Reason = fmt.Sprintf("observed repeated TCP SYN to %d ports, including a single-node port scan", count)
	case "flood":
		allNodes := map[string]bool{}
		for _, f := range facts {
			if f.Packets > 0 {
				allNodes[f.Node] = true
			}
		}
		in.Nodes = len(allNodes)
		eligible = pps >= policy.PPS*4 || synPPS >= policy.SYN*4
		in.Score, _ = policy.Base(Evidence{PPS: pps, SYN: synPPS})
		in.Reason = fmt.Sprintf("observed eligible packet peak %d/s; SYN peak %d/s (retransmissions included)", pps, synPPS)
	default:
		return in, false, fmt.Errorf("unknown incident kind")
	}
	return in, eligible, nil
}
