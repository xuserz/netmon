package ui

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode"

	"netmon/internal/live"
)

type State struct {
	Nodes     bool
	Sort      string
	Data      live.Response
	Error     string
	Paused    bool
	Offset    int
	CPU, Rate float64
	History   []float64
	Version   string
	Color     bool
}

func (s State) rowCount() int {
	if s.Data.Network {
		if s.Nodes {
			return len(s.Data.NetworkNodes)
		}
		return len(s.Data.NetworkIPs)
	}
	if s.Sort == "rate" || s.Sort == "minute" {
		return len(s.Data.Activity)
	}
	return len(s.Data.Clients)
}
func (s State) active() bool { return s.Sort == "rate" || s.Sort == "minute" }

func plain(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
}
func cut(s string, n int) string {
	if n <= 0 {
		return ""
	}
	r := []rune(plain(s))
	if len(r) <= n {
		return string(r)
	}
	if n < 2 {
		return string(r[:n])
	}
	return string(r[:n-1]) + "…"
}
func pad(s string, n int) string {
	s = cut(s, n)
	return s + strings.Repeat(" ", max(0, n-len([]rune(s))))
}
func paint(s string, color int, on bool) string {
	if !on {
		return s
	}
	return fmt.Sprintf("\x1b[38;5;%dm%s\x1b[0m", color, s)
}
func number(s string) string {
	if s == "" {
		return "0"
	}
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}
func bytes(n uint64) string {
	if n == 0 {
		return "—"
	}
	return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
}
func ago(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := time.Since(t)
	if d < 0 {
		d = 0
	}
	if d < time.Minute {
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	}
	return d.Round(time.Second).String() + " ago"
}
func duration(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return time.Since(t).Truncate(time.Second).String()
}
func spark(values []float64, n int) string {
	if n < 1 {
		return ""
	}
	if len(values) > n {
		values = values[len(values)-n:]
	}
	peak := 1.0
	for _, v := range values {
		peak = math.Max(peak, v)
	}
	glyph := []rune("▁▂▃▄▅▆▇█")
	var b strings.Builder
	for _, v := range values {
		i := int(math.Round(7 * v / peak))
		b.WriteRune(glyph[max(0, min(7, i))])
	}
	return b.String()
}

// Render produces exactly height bounded lines. Width calculation only sees
// plain text; color sequences are added after clipping, so IPv6 and tiny SSH
// windows cannot wrap into another row or displace the footer.
func Render(s State, width, height int) string {
	if s.Data.Network {
		return renderNetwork(s, width, height)
	}
	width = max(1, width)
	height = max(1, height)
	if width < 42 || height < 12 {
		lines := []string{"netmon · enlarge terminal", fmt.Sprintf("Need at least 42×12; current %d×%d", width, height), "q: quit"}
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
	box := func(text string, c int) {
		lines = append(lines, paint("│", 60, s.Color)+paint(pad(text, inner), c, s.Color)+paint("│", 60, s.Color))
	}
	edge := func(title string) {
		title = " " + plain(title) + " "
		title = cut(title, inner)
		lines = append(lines, paint("├"+title+strings.Repeat("─", inner-len([]rune(title)))+"┤", 60, s.Color))
	}
	top := " netmon " + s.Version + " "
	top = cut(top, inner)
	lines = append(lines, paint("╭"+top+strings.Repeat("─", inner-len([]rune(top)))+"╮", 81, s.Color))
	h := s.Data.Health
	mode := "LIVE"
	if s.Data.Source != "live" {
		mode = "STORED · monitor unavailable"
	}
	if s.Data.Source == "live" && !s.Data.SnapshotAt.IsZero() && time.Since(s.Data.SnapshotAt) > 3*time.Second {
		mode = "STALE · snapshot " + ago(s.Data.SnapshotAt)
	}
	if h.ClusterEnabled && !s.Data.Cluster && s.Data.Source == "live" {
		mode = "LOCAL · this server"
	}
	if s.Data.Cluster {
		mode = "CLUSTER · saved totals"
		if !s.Data.SnapshotAt.IsZero() && time.Since(s.Data.SnapshotAt) > 3*time.Second {
			mode = "CLUSTER · STALE"
		}
		if h.ClusterCatchingUp {
			mode = "CLUSTER · catching up"
		}
		if s.Data.Source != "live" {
			mode = "CLUSTER · stored"
		}
	}
	if s.Paused {
		mode = "PAUSED"
	}
	statusColor := 120
	if s.Data.Source != "live" || s.Paused || strings.Contains(mode, "STALE") {
		statusColor = 220
	}
	box(fmt.Sprintf(" %s   %s:%d   %s", mode, h.Interface, h.Port, time.Now().Format("15:04:05")), statusColor)
	totalsLabel := "Requests"
	if s.active() || s.Data.Cluster {
		totalsLabel = "Saved requests"
	}
	box(fmt.Sprintf(" %s %s   Clients %s   %.1f req/s", totalsLabel, number(s.Data.Totals.Requests), number(strconv.FormatInt(s.Data.Totals.Unique, 10)), s.Rate), 255)
	if s.Data.Source == "live" {
		box(fmt.Sprintf(" CPU %.1f%%   RAM %s   Uptime %s", s.CPU, bytes(h.RSSBytes), duration(h.Started)), 153)
	} else {
		box(" Showing committed SQLite counters; live data unavailable", 220)
	}
	dropColor := 120
	if h.KernelDrops > 0 || h.Parser.TCPDiscarded > 0 || h.Parser.Midstream > 0 || h.Parser.FragmentDiscarded > 0 || h.Parser.MalformedDNS > 0 {
		dropColor = 203
	}
	box(fmt.Sprintf(" Drops %d  TCP issues %d  Frag issues %d  Bad DNS %d", h.KernelDrops, h.Parser.TCPDiscarded+h.Parser.Midstream, h.Parser.FragmentDiscarded, h.Parser.MalformedDNS), dropColor)
	box(fmt.Sprintf(" Pending %d requests / %d IP slots   Retries %d   Saved %s", h.PendingRequests, h.PendingIPs, h.WriteRetries, ago(h.LastFlush)), 146)
	if s.Error != "" {
		box(" ! "+s.Error, 203)
	} else if s.Data.Cluster && h.ClusterError != "" {
		box(" ! Cluster: "+h.ClusterError, 203)
	} else if h.CaptureError != "" {
		box(" ! "+h.CaptureError, 203)
	} else if h.FlushError != "" {
		box(" ! "+h.FlushError, 203)
	} else if h.BlockedFor > 0 {
		box(fmt.Sprintf(" ! Waiting for storage %s; pending age %s", h.BlockedFor.Round(time.Second), h.PendingAge.Round(time.Second)), 203)
	} else if s.active() && s.Data.ActivityPartial {
		box(" ! Activity cache incomplete: IP eviction or concurrent sample", 220)
	} else if s.Data.Cluster && s.Data.Source == "live" {
		box(fmt.Sprintf(" Peers %d/%d online   Last exchange %s · CPU/RAM/activity are local", h.ClusterOnline, h.ClusterPeers, ago(h.ClusterLastSync)), 146)
	} else {
		box(" Rate "+spark(s.History, inner-8), 81)
	}
	title := "TOP CLIENTS · total requests ↓"
	if s.Sort == "rate" {
		title = "TOP CLIENTS · requests/s over 5 complete seconds ↓"
	}
	if s.Sort == "minute" {
		title = "TOP CLIENTS · requests over 60 complete seconds ↓"
	}
	if s.Data.Cluster && s.active() {
		title = "LOCAL " + title
	}
	edge(title)
	// Header + rows share the same adaptive columns. Full IPv6 is retained in
	// normal-width windows; narrow views shorten it explicitly with an ellipsis.
	detailed := inner >= 100
	extra := 0
	if detailed {
		extra = 26
	} else if inner >= 72 {
		extra = 11
	}
	ipWidth := min(39, max(14, inner-35))
	countWidth := min(25, max(10, inner-ipWidth-3-8-extra))
	header := fmt.Sprintf(" %-*s %*s %8s", ipWidth, "IP ADDRESS", countWidth, "REQUESTS", "RELATIVE")
	if detailed {
		header += "   FIRST SEEN   LAST SEEN"
	} else if inner >= 72 {
		header += "   LAST SEEN"
	}
	if s.active() {
		ipWidth = min(39, max(14, inner-33))
		header = fmt.Sprintf(" %-*s %8s", ipWidth, "IP ADDRESS", "REQ/S")
		if inner >= 48 {
			header += fmt.Sprintf(" %10s", "LAST 60S")
		}
		if inner >= 64 {
			header += fmt.Sprintf(" %7s", "SHARE")
		}
	}
	box(header, 109)
	available := height - len(lines) - 2
	offset := max(0, min(s.Offset, max(0, s.rowCount()-available)))
	peak := int64(1)
	if len(s.Data.Clients) > 0 {
		peak = max(1, s.Data.Clients[0].Requests)
	}
	for i := 0; i < available; i++ {
		index := offset + i
		if index >= s.rowCount() {
			if i == 0 && s.rowCount() == 0 {
				text := " Waiting for DNS requests…"
				if s.active() {
					text = " Waiting for activity in completed seconds…"
				}
				if s.active() && s.Data.Source != "live" {
					text = " Activity unavailable: monitor is offline"
				}
				if s.active() && s.Data.Source == "live" && h.ActivityLimit == 0 {
					text = " Activity unavailable: cache disabled or older daemon"
				}
				box(text, 146)
			} else {
				box("", 255)
			}
			continue
		}
		if s.active() {
			c := s.Data.Activity[index]
			row := fmt.Sprintf(" %-*s %8.1f", ipWidth, cut(c.IP, ipWidth), c.Rate)
			if inner >= 48 {
				row += fmt.Sprintf(" %10s", cut(number(strconv.FormatUint(c.Minute, 10)), 10))
			}
			if inner >= 64 {
				row += fmt.Sprintf(" %6.1f%%", c.Share)
			}
			color := 255
			if index == 0 {
				color = 120
			}
			box(row, color)
			continue
		}
		c := s.Data.Clients[index]
		// The bar is relative to the highest count, not a claim about all clients.
		bar := strings.Repeat("▰", int(math.Ceil(6*float64(c.Requests)/float64(peak))))
		row := fmt.Sprintf(" %-*s %*s %8s", ipWidth, cut(c.IP, ipWidth), countWidth, cut(number(strconv.FormatInt(c.Requests, 10)), countWidth), bar)
		if detailed {
			row += "   " + time.Unix(c.First, 0).Format("02.01.2006") + "   " + time.Unix(c.Last, 0).Format("02.01.2006")
		} else if inner >= 72 {
			row += "   " + time.Unix(c.Last, 0).Format("15:04:05")
		}
		color := 255
		if index == 0 {
			color = 120
		}
		box(row, color)
	}
	footer := fmt.Sprintf(" q quit · ↑↓ scroll · space pause · r refresh · c color · s sort  %d–%d/%d ", min(s.rowCount(), offset+1), min(s.rowCount(), offset+available), s.rowCount())
	edge(footer)
	lines = append(lines, paint("╰"+strings.Repeat("─", inner)+"╯", 60, s.Color))
	return strings.Join(lines, "\r\n")
}
