package ui

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"dnsmon/internal/live"
	"dnsmon/internal/store"
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
