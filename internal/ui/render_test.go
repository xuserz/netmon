package ui

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"netmon/internal/live"
	"netmon/internal/observation"
	"netmon/internal/store"
)

var ansi = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

func TestRendererFitsSmallAndLargeTerminals(t *testing.T) {
	s := State{Version: "build-123-1-deadbeef", Color: true, Data: live.Response{Source: "live", Totals: store.Totals{Unique: 500, Requests: "18446744073709551614"}, Health: live.Health{Interface: "ens3", Port: 53, Started: time.Now(), Updated: time.Now(), KernelDrops: 1}}}
	for i := 0; i < 100; i++ {
		s.Data.Clients = append(s.Data.Clients, store.Client{IP: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", Requests: 123456789, First: 1, Last: 2})
	}
	for _, size := range [][2]int{{1, 1}, {20, 8}, {42, 12}, {80, 24}, {110, 40}, {180, 60}} {
		rendered := ansi.ReplaceAllString(Render(s, size[0], size[1]), "")
		lines := strings.Split(rendered, "\r\n")
		if len(lines) != size[1] {
			t.Fatalf("%v: got %d lines", size, len(lines))
		}
		for _, line := range lines {
			if len([]rune(line)) != size[0] {
				t.Fatalf("%v: wrapped line %q (%d)", size, line, len([]rune(line)))
			}
		}
	}
}
func TestNoColorPausedAndTerminalControlSanitization(t *testing.T) {
	s := State{Paused: true, Error: "bad\x1b[2Jmessage", Data: live.Response{Source: "stored"}}
	output := Render(s, 80, 24)
	if strings.Contains(output, "\x1b") || !strings.Contains(output, "PAUSED") || !strings.Contains(output, "message") {
		t.Fatal(output)
	}
}
func TestKeyboardSequencesAcrossReads(t *testing.T) {
	for sequence, want := range map[string]string{"q": "quit", " ": "pause", "r": "refresh", "c": "color", "\x1b[A": "up", "\x1b[B": "down", "\x1b[5~": "page_up", "\x1b[6~": "page_down", "G": "end"} {
		var d keyDecoder
		var got string
		for _, b := range []byte(sequence) {
			if action := d.Feed(b); action != "" {
				got = action
			}
		}
		if got != want {
			t.Fatal(sequence, got, want)
		}
	}
}

func TestStaleSnapshotKeepsCountsAndShowsRetryDiagnostic(t *testing.T) {
	s := State{Data: live.Response{Source: "live", SnapshotAt: time.Now().Add(-10 * time.Second), Totals: store.Totals{Requests: "123"}, Health: live.Health{WriteRetries: 3, FlushError: "database is locked"}}}
	out := Render(s, 110, 24)
	for _, want := range []string{"STALE", "123", "Retries 3", "database is locked"} {
		if !strings.Contains(out, want) {
			t.Fatal(want, out)
		}
	}
}

func TestActivityRendererFitsAndLabelsWindows(t *testing.T) {
	for _, sort := range []string{"rate", "minute"} {
		s := State{Sort: sort, Color: true, Data: live.Response{Source: "live", ActivityPartial: true, Activity: []live.ActivityClient{{IP: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", Rate: 1234.5, Minute: 123456, Share: 10.5}}}}
		for _, size := range [][2]int{{42, 12}, {80, 24}, {110, 28}} {
			out := ansi.ReplaceAllString(Render(s, size[0], size[1]), "")
			lines := strings.Split(out, "\r\n")
			if len(lines) != size[1] {
				t.Fatal(size, len(lines))
			}
			for _, line := range lines {
				if len([]rune(line)) != size[0] {
					t.Fatal(size, line)
				}
			}
			if !strings.Contains(out, "REQ/S") {
				t.Fatal(out)
			}
		}
	}
}

func TestNetworkRendererFitsAndShowsRiskAndLoss(t *testing.T) {
	s := State{Sort: "score", Color: true, Data: live.Response{Network: true, Source: "live", SnapshotAt: time.Now(), Health: live.Health{StorageMode: "forward", QueueRejected: 42, DiscardedSamples: 3}, NetworkIPs: []observation.IP{{IP: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", Score: 85, Counters: observation.Counters{Packets: 123456, SYN: 999}}}}}
	for _, size := range [][2]int{{1, 1}, {20, 8}, {50, 12}, {80, 24}, {110, 40}} {
		output := ansi.ReplaceAllString(Render(s, size[0], size[1]), "")
		lines := strings.Split(output, "\r\n")
		if len(lines) != size[1] {
			t.Fatal(size, len(lines))
		}
		for _, line := range lines {
			if len([]rune(line)) != size[0] {
				t.Fatal(size, line)
			}
		}
	}
	output := Render(s, 110, 24)
	for _, want := range []string{"85", "123,456", "RAM SAMPLE", "discarded", "Queue rejects 42"} {
		if !strings.Contains(output, want) {
			t.Fatal(want, output)
		}
	}
}

func TestNetworkDescriptionsAndTrustTagsStayVisibleWithoutMaskingRisk(t *testing.T) {
	s := State{Sort: "score", Color: true, Data: live.Response{Network: true, NetworkIPs: []observation.IP{{IP: "2001:db8::1234", Score: 85, ServerName: "DNS node", Whitelisted: true, WhitelistDescription: "Uptime Kuma", Counters: observation.Counters{Packets: 777777}}}}}
	for _, width := range []int{50, 70, 80, 100, 110, 180} {
		output := ansi.ReplaceAllString(Render(s, width, 24), "")
		for _, line := range strings.Split(output, "\r\n") {
			if len([]rune(line)) != width {
				t.Fatal(width, line)
			}
		}
		if !strings.Contains(output, "DNS node") {
			t.Fatal(width, output)
		}
	}
	output := Render(s, 110, 24)
	if !strings.Contains(output, "SERVER+WL") || !strings.Contains(output, "Uptime Kuma") || !strings.Contains(output, "\x1b[38;5;203m") {
		t.Fatal(output)
	}
}
