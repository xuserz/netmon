package ui

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

func renderNetwork(s State, width, height int) string {
	width = max(1, width)
	height = max(1, height)
	if width < 50 || height < 12 {
		lines := []string{"NETWORK MONITOR · enlarge terminal", "Need at least 50×12; q quits"}
		for len(lines) < height {
			lines = append(lines, "")
		}
		for i := range lines {
			lines[i] = pad(lines[i], width)
		}
		return strings.Join(lines[:height], "\r\n")
	}
	inner := width - 2
	var lines []string
	box := func(text string, color int) {
		lines = append(lines, paint("│", 60, s.Color)+paint(pad(text, inner), color, s.Color)+paint("│", 60, s.Color))
	}
	edge := func(title string) {
		title = cut(" "+title+" ", inner)
		lines = append(lines, paint("├"+title+strings.Repeat("─", inner-len([]rune(title)))+"┤", 60, s.Color))
	}
	title := cut(" netmon · NETWORK · "+s.Version+" ", inner)
	lines = append(lines, paint("╭"+title+strings.Repeat("─", inner-len([]rune(title)))+"╮", 81, s.Color))
	h := s.Data.Health
	t := s.Data.NetworkTotals
	scope := "SAVED NETWORK OBSERVATIONS"
	if h.StorageMode == "forward" {
		scope = "FORWARD · RAM SAMPLE"
	} else if s.Data.Partial {
		scope = "LOCAL RAM SAMPLE"
	}
	if s.Data.Source == "stored" {
		scope = "STORED NETWORK OBSERVATIONS"
	}
	if s.Paused {
		scope = "PAUSED"
	} else if !s.Data.SnapshotAt.IsZero() && time.Since(s.Data.SnapshotAt) > 3*time.Second {
		scope += " · STALE"
	}
	connections := "standalone"
	if h.ClusterEnabled {
		connections = fmt.Sprintf("Nodes %d/%d online", h.ClusterOnline, h.ClusterPeers)
	}
	box(" "+connections+" · "+scope+"   "+h.Interface, 120)
	box(fmt.Sprintf(" Packets %s   IPs %s   Bytes %s", number(strconv.FormatInt(t.Packets, 10)), number(strconv.FormatInt(t.IPs, 10)), bytes(uint64(max(int64(0), t.Bytes)))), 255)
	if height >= 14 {
		box(fmt.Sprintf(" Local %.1f packets/s   CPU %.1f%%   RAM %s", s.Rate, s.CPU, bytes(h.RSSBytes)), 153)
	}
	u := h.Storage
	dbLine := " DB metrics unavailable"
	if h.StorageMode == "forward" {
		dbLine = " DB disabled · FORWARD / RAM only"
	} else if u.Enabled && u.DatabaseKnown {
		dbLine = fmt.Sprintf(" DB %s / %s   WAL %s   Files %s", storageBytes(u.DatabaseBytes), storageBytes(u.LimitBytes), storageBytes(u.WALBytes), storageBytes(u.FilesBytes))
	}
	box(dbLine, 146)
	diskLine := " Disk free unavailable"
	if u.DiskKnown {
		diskLine = " Disk free " + storageBytes(u.DiskAvailableBytes)
		if u.Enabled && u.DatabaseKnown && h.StorageMode != "forward" {
			diskLine += "   Headroom " + storageBytes(u.HeadroomBytes)
		}
	}
	box(diskLine, 146)
	box(fmt.Sprintf(" Kernel drops %d   Malformed %d   RAM queue %.1f/%.1f MiB", h.KernelDrops, h.MalformedPackets, float64(h.QueueBytes)/(1<<20), float64(h.QueueLimit)/(1<<20)), 146)
	if height >= 14 {
		box(fmt.Sprintf(" SYN %s   UDP %s   Queue rejects %d   Discarded samples %d", number(strconv.FormatInt(t.SYN, 10)), number(strconv.FormatInt(t.UDP, 10)), h.QueueRejected, h.DiscardedSamples), 146)
	}
	warning := " Suspicion is a decaying heuristic, not a probability or attribution"
	if s.Error != "" {
		warning = " ! " + s.Error
	} else if h.FlushError != "" {
		warning = " ! " + h.FlushError
	} else if h.Storage.Error != "" {
		warning = " ! Storage metrics: " + h.Storage.Error
	} else if h.NodeCacheEvictions > 0 {
		warning = " ! Incoming node cache limit reached; some contacts are omitted"
	} else if h.DiscardedSamples > 0 {
		warning = " ! Some RAM observations were discarded; statistics may be incomplete"
	}
	box(warning, 220)
	if s.Nodes {
		edge("NODE CONNECTIONS · local authenticated contacts")
		nameWidth := max(6, inner-28)
		wide := inner >= 78
		if wide {
			nameWidth = max(6, inner-47)
		}
		format := func(state, role, name, seen, rtt, pending string) string {
			text := fmt.Sprintf(" %-9s %-7s %-*s %8s", cut(state, 9), cut(role, 7), nameWidth, cut(name, nameWidth), cut(seen, 8))
			if wide {
				text += fmt.Sprintf(" %8s %9s", cut(rtt, 8), cut(pending, 9))
			}
			return text
		}
		box(format("STATE", "ROLE", "NAME / NODE", "SEEN", "RTT", "SYNC GAP"), 109)
		available := height - len(lines) - 2
		visible := max(1, (available+1)/2)
		offset := max(0, min(s.Offset, max(0, len(s.Data.NetworkNodes)-visible)))
		for i := 0; i < available; i++ {
			index := offset + i/2
			if index >= len(s.Data.NetworkNodes) {
				if i == 0 {
					box(" No node contacts yet; check cluster configuration", 146)
				} else {
					box("", 255)
				}
				continue
			}
			node := s.Data.NetworkNodes[index]
			color := 146
			switch node.State {
			case "ONLINE":
				color = 120
			case "DEGRADED", "UNKNOWN":
				color = 220
			case "OFFLINE":
				color = 203
			}
			if i%2 == 0 {
				name := node.Name
				if name == "" {
					name = node.Node
				}
				if name == "" {
					name = "unidentified"
				}
				rtt := "-"
				if !node.LastAttempt.IsZero() && !node.LastSeen.IsZero() {
					rtt = fmt.Sprintf("%.1fms", node.RTTMillis)
				}
				pending := "-"
				if node.SyncKnown {
					pending = strconv.FormatInt(max(int64(0), node.Head-node.Cursor), 10)
				}
				box(format(node.State, node.Role, name, ago(node.LastSeen), rtt, pending), color)
			} else {
				detail := " " + node.Direction + " · " + node.Address
				if node.SyncError != "" {
					detail += " · SYNC: " + node.SyncError
				} else if node.Error != "" {
					detail += " · " + node.Error
				} else if node.Node != "" {
					detail += " · id " + cut(node.Node, 8)
				}
				box(detail, color)
			}
		}
		edge("q quit · n IPs · ↑↓ scroll · space pause · r refresh")
		lines = append(lines, paint("╰"+strings.Repeat("─", inner)+"╯", 60, s.Color))
		return strings.Join(lines, "\r\n")
	}
	edge("IP ACTIVITY · sort " + s.Sort)
	// Keep descriptions visible on narrow terminals; SYN gets its own
	// column when the terminal has room. The per-IP detail remains complete.
	ipWidth := min(39, max(15, inner/3))
	if inner >= 108 {
		ipWidth = 39
	}
	countWidth := 7
	tagWidth := 3
	showSYN := inner >= 98
	if inner >= 78 {
		countWidth = 10
		tagWidth = 10
	}
	labelWidth := inner - (1 + ipWidth + 1 + 4 + 1 + countWidth + 1 + tagWidth + 1)
	if showSYN {
		labelWidth -= 9
	}
	formatRow := func(ip, risk, packets, syn, tag, label string) string {
		text := fmt.Sprintf(" %-*s %4s %*s", ipWidth, cut(ip, ipWidth), risk, countWidth, cut(packets, countWidth))
		if showSYN {
			text += fmt.Sprintf(" %8s", cut(syn, 8))
		}
		return text + fmt.Sprintf(" %-*s %s", tagWidth, cut(tag, tagWidth), cut(label, max(1, labelWidth)))
	}
	box(formatRow("SOURCE IP", "RISK", "PACKETS", "SYN", "TAG", "DESCRIPTION"), 109)
	available := height - len(lines) - 2
	offset := max(0, min(s.Offset, max(0, len(s.Data.NetworkIPs)-available)))
	for i := 0; i < available; i++ {
		index := offset + i
		if index >= len(s.Data.NetworkIPs) {
			if i == 0 && len(s.Data.NetworkIPs) == 0 {
				box(" Waiting for observed network activity…", 146)
			} else {
				box("", 255)
			}
			continue
		}
		row := s.Data.NetworkIPs[index]
		color := 255
		if row.Whitelisted {
			color = 120
		} else if row.ServerName != "" {
			color = 153
		}
		if row.Score >= 70 {
			color = 203
		} else if row.Score >= 30 {
			color = 220
		} else if row.Score > 0 {
			color = 153
		}
		tag := row.DisplayTag()
		if tagWidth == 3 {
			if row.ServerName != "" && row.Whitelisted {
				tag = "S+W"
			} else if row.ServerName != "" {
				tag = "S"
			} else if row.Whitelisted {
				tag = "W"
			}
		}
		box(formatRow(row.IP, strconv.Itoa(row.Score), number(strconv.FormatInt(row.Packets, 10)), number(strconv.FormatInt(row.SYN, 10)), tag, row.Label()), color)
	}
	edge("q quit · n nodes · ↑↓ scroll · space pause · r refresh · c color · s sort")
	lines = append(lines, paint("╰"+strings.Repeat("─", inner)+"╯", 60, s.Color))
	return strings.Join(lines, "\r\n")
}

func networkPageRows(height int) int {
	if height >= 14 {
		return max(1, height-13)
	}
	return max(1, height-11)
}

func storageBytes(n int64) string {
	n = max(int64(0), n)
	for _, unit := range []struct {
		size int64
		name string
	}{{1 << 40, "TiB"}, {1 << 30, "GiB"}, {1 << 20, "MiB"}, {1 << 10, "KiB"}} {
		if n >= unit.size {
			return fmt.Sprintf("%.1f %s", float64(n)/float64(unit.size), unit.name)
		}
	}
	return fmt.Sprintf("%d B", n)
}

func (s State) networkPageRows(height int) int {
	rows := networkPageRows(height)
	if s.Nodes {
		return max(1, (rows+1)/2)
	}
	return rows
}
