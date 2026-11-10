// Package observation defines network metrics and an explicitly heuristic rating.
package observation

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"net/netip"
	"strings"
	"time"
	"unicode"
)

const MaxPorts = 64
const PolicyVersion = "network-risk-v1"

type Policy struct {
	PPS             int64 `json:"pps"`
	SYN             int64 `json:"syn"`
	Ports           int   `json:"ports"`
	HalfLifeSeconds int64 `json:"half_life_seconds"`
}
type Counters struct {
	Packets int64 `json:"packets"`
	Bytes   int64 `json:"bytes"`
	TCP     int64 `json:"tcp"`
	SYN     int64 `json:"syn"`
	UDP     int64 `json:"udp"`
	ICMP    int64 `json:"icmp"`
}
type Evidence struct {
	At    int64 `json:"at"`
	PPS   int64 `json:"pps"`
	SYN   int64 `json:"syn_pps"`
	Ports int   `json:"syn_ports"`
}
type Sample struct {
	ID     string `json:"id"`
	Node   string `json:"node"`
	Name   string `json:"name"`
	IP     string `json:"ip"`
	Window int64  `json:"window"`
	Counters
	First    int64    `json:"first_seen"`
	Last     int64    `json:"last_seen"`
	PeakPPS  int64    `json:"peak_pps"`
	Ports    []uint16 `json:"ports,omitempty"`
	Evidence Evidence `json:"evidence"`
	Partial  bool     `json:"partial"`
}
type IP struct {
	ServerName           string `json:"server_name,omitempty"`
	ServerSource         string `json:"server_source,omitempty"`
	Whitelisted          bool   `json:"whitelisted,omitempty"`
	WhitelistDescription string `json:"whitelist_description,omitempty"`
	IP                   string `json:"ip"`
	Counters
	First      int64    `json:"first_seen"`
	Last       int64    `json:"last_seen"`
	PeakPPS    int64    `json:"peak_pps"`
	Score      int      `json:"suspicion"`
	Reasons    []string `json:"reasons"`
	EvidenceAt int64    `json:"evidence_at"`
	Partial    bool     `json:"partial"`
}
type Totals struct {
	IPs int64 `json:"ips"`
	Counters
}

func ID() string {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b[:])
}
func ValidID(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 16 && s == hex.EncodeToString(b)
}
func Add(a, b int64) int64 {
	if b > math.MaxInt64-a {
		return math.MaxInt64
	}
	return a + b
}
func (a Counters) Plus(b Counters) Counters {
	return Counters{Add(a.Packets, b.Packets), Add(a.Bytes, b.Bytes), Add(a.TCP, b.TCP), Add(a.SYN, b.SYN), Add(a.UDP, b.UDP), Add(a.ICMP, b.ICMP)}
}
func (a Counters) CanAdd(b Counters) bool {
	return b.Packets >= 0 && b.Bytes >= 0 && b.TCP >= 0 && b.SYN >= 0 && b.UDP >= 0 && b.ICMP >= 0 &&
		a.Packets <= math.MaxInt64-b.Packets && a.Bytes <= math.MaxInt64-b.Bytes && a.TCP <= math.MaxInt64-b.TCP &&
		a.SYN <= math.MaxInt64-b.SYN && a.UDP <= math.MaxInt64-b.UDP && a.ICMP <= math.MaxInt64-b.ICMP
}
func (a Counters) Max(b Counters) Counters {
	return Counters{max(a.Packets, b.Packets), max(a.Bytes, b.Bytes), max(a.TCP, b.TCP), max(a.SYN, b.SYN), max(a.UDP, b.UDP), max(a.ICMP, b.ICMP)}
}
func (a Counters) Minus(b Counters) Counters {
	return Counters{a.Packets - b.Packets, a.Bytes - b.Bytes, a.TCP - b.TCP, a.SYN - b.SYN, a.UDP - b.UDP, a.ICMP - b.ICMP}
}
func (s Sample) Validate(now time.Time, retention time.Duration) error {
	ip, e := netip.ParseAddr(s.IP)
	if !ValidID(s.ID) || !ValidID(s.Node) || e != nil || ip.Zone() != "" || ip.Unmap().String() != s.IP || len(s.Name) > 128 || InvalidName(s.Name) {
		return fmt.Errorf("invalid observation identity")
	}
	if s.Window < 0 || s.Window%60 != 0 || s.First < s.Window || s.Last < s.First || s.Last >= s.Window+60 || s.Last > now.Unix()+300 || s.Window+60 <= now.Add(-retention).Unix() {
		return fmt.Errorf("observation outside its minute/retention window")
	}
	c := s.Counters
	if c.Packets < 1 || c.Bytes < c.Packets || c.TCP < 0 || c.SYN < 0 || c.UDP < 0 || c.ICMP < 0 || c.TCP > c.Packets || c.SYN > c.TCP || c.UDP > c.Packets-c.TCP || c.ICMP > c.Packets-c.TCP-c.UDP || s.PeakPPS < 0 || s.PeakPPS > c.Packets || len(s.Ports) > MaxPorts {
		return fmt.Errorf("invalid packet counters")
	}
	if (s.Evidence.At == 0 && (s.Evidence.PPS != 0 || s.Evidence.SYN != 0 || s.Evidence.Ports != 0)) || s.Evidence.At < 0 || s.Evidence.At > s.Last || (s.Evidence.At != 0 && s.Evidence.At < s.Window-60) || s.Evidence.PPS < 0 || s.Evidence.PPS > c.Packets || s.Evidence.SYN < 0 || s.Evidence.SYN > c.SYN || s.Evidence.Ports < 0 || s.Evidence.Ports > MaxPorts {
		return fmt.Errorf("invalid rating evidence")
	}
	seen := map[uint16]bool{}
	for _, p := range s.Ports {
		if p == 0 || seen[p] {
			return fmt.Errorf("invalid port sample")
		}
		seen[p] = true
	}
	return nil
}
func tier(value, threshold int64, weight int) int {
	if value < threshold {
		return 0
	}
	if value >= threshold*16 {
		return weight
	}
	if value >= threshold*4 {
		return weight * 2 / 3
	}
	return weight / 3
}
func (p Policy) Base(e Evidence) (int, []string) {
	score := 0
	var reasons []string
	if n := tier(e.PPS, p.PPS, 35); n > 0 {
		score += n
		reasons = append(reasons, fmt.Sprintf("observed %d incoming IP packets/s", e.PPS))
	}
	if n := tier(e.SYN, p.SYN, 35); n > 0 {
		score += n
		reasons = append(reasons, fmt.Sprintf("observed %d TCP SYN packets/s (retransmissions included)", e.SYN))
	}
	// Port diversity uses SYN without ACK, not ephemeral destination ports in replies.
	n := 0
	if e.Ports >= p.Ports*4 {
		n = 30
	} else if e.Ports >= p.Ports*2 {
		n = 20
	} else if e.Ports >= p.Ports {
		n = 10
	}
	if n > 0 {
		score += n
		reasons = append(reasons, fmt.Sprintf("TCP SYN addressed %d ports in a bounded 60s sample", e.Ports))
	}
	return min(100, score), reasons
}

// baseScore avoids formatting human-readable reasons on the packet capture path.
func (p Policy) baseScore(e Evidence) int {
	n := tier(e.PPS, p.PPS, 35) + tier(e.SYN, p.SYN, 35)
	if e.Ports >= p.Ports*4 {
		n += 30
	} else if e.Ports >= p.Ports*2 {
		n += 20
	} else if e.Ports >= p.Ports {
		n += 10
	}
	return min(100, n)
}
func InvalidName(name string) bool {
	for _, r := range name {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

// Better provides a deterministic winner even for equally ranked evidence.
func (p Policy) Better(a, b Evidence) bool {
	x, y := p.Priority(a), p.Priority(b)
	if x != y {
		return x > y
	}
	if a.At != b.At {
		return a.At > b.At
	}
	if a.PPS != b.PPS {
		return a.PPS > b.PPS
	}
	if a.SYN != b.SYN {
		return a.SYN > b.SYN
	}
	return a.Ports > b.Ports
}
func (p Policy) Priority(e Evidence) float64 {
	base := p.baseScore(e)
	if base == 0 {
		return -1e30
	}
	return math.Log(float64(base)) + math.Ln2*float64(e.At)/float64(p.HalfLifeSeconds)
}
func (p Policy) Score(e Evidence, now time.Time) (int, []string) {
	base, reasons := p.Base(e)
	age := max(int64(0), now.Unix()-e.At)
	score := int(math.Round(float64(base) * math.Exp(-math.Ln2*float64(age)/float64(p.HalfLifeSeconds))))
	return max(0, min(100, score)), reasons
}

func (ip IP) Tag() string {
	if ip.ServerName != "" && ip.Whitelisted {
		return "SERVER+WL"
	}
	if ip.ServerName != "" {
		return "SERVER"
	}
	if ip.Whitelisted {
		return "WL"
	}
	return "-"
}
func (ip IP) Label() string {
	var parts []string
	if ip.ServerName != "" {
		parts = append(parts, ip.ServerName)
	}
	if ip.WhitelistDescription != "" {
		parts = append(parts, ip.WhitelistDescription)
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, " · ")
}
