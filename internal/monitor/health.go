package monitor

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"dnsmon/internal/packet"
	"golang.org/x/sys/unix"
)

// Only the capture goroutine touches Engine. Health reads immutable samples and
// kernel statistics independently, even when capture is waiting for storage.
type captureSample struct {
	at                                   time.Time
	received                             uint64
	flows, tcp, fragments, fragmentBytes int
	parser                               packet.Counters
	lag                                  time.Duration
}

func (b *batcher) recordCapture(engine *packet.Engine, received uint64, arrival time.Time) {
	f, t, fr, bytes := engine.Memory()
	sample := &captureSample{at: time.Now(), received: received, flows: f, tcp: t, fragments: fr, fragmentBytes: bytes, parser: engine.Counters}
	if !arrival.IsZero() {
		sample.lag = max(0, time.Since(arrival))
	}
	b.capture.Store(sample)
}
func (b *batcher) startHealth(parent context.Context, sock source, actual int, mapped bool) func() {
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	b.mu.Lock()
	b.health.ActualBuffer = actual
	if mapped {
		b.health.CaptureMode = "tpacket_v3"
	}
	b.mu.Unlock()
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			b.sampleHealth(sock)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return func() { cancel(); <-done }
}
func (b *batcher) sampleHealth(sock source) {
	var usage unix.Rusage
	unix.Getrusage(unix.RUSAGE_SELF, &usage)
	cpu := float64(usage.Utime.Sec+usage.Stime.Sec) + float64(usage.Utime.Usec+usage.Stime.Usec)/1e6
	var rss uint64
	if data, e := os.ReadFile("/proc/self/statm"); e == nil {
		fields := strings.Fields(string(data))
		if len(fields) > 1 {
			pages, _ := strconv.ParseUint(fields[1], 10, 64)
			rss = pages * uint64(os.Getpagesize())
		}
	}
	drops, e := sock.Drops()
	if drops > 0 {
		log.Printf("WARNING: kernel dropped %d packets; totals may be incomplete", drops)
	}
	sample := b.capture.Load()
	b.mu.Lock()
	defer b.mu.Unlock()
	b.health.Updated = time.Now()
	b.health.RSSBytes = rss
	b.health.CPUSeconds = cpu
	if e != nil {
		b.captureErr = fmt.Errorf("read packet statistics: %w", e)
		b.health.CaptureError = b.captureErr.Error()
		select {
		case b.changed <- struct{}{}:
		default:
		}
	} else {
		b.health.KernelDrops += uint64(drops)
	}
	if sample != nil {
		b.health.CaptureUpdated = sample.at
		b.health.Received = sample.received
		b.health.TCPFlows = sample.flows
		b.health.TCPBytes = sample.tcp
		b.health.Fragments = sample.fragments
		b.health.FragmentBytes = sample.fragmentBytes
		b.health.Parser = sample.parser
		b.health.CaptureLag = sample.lag
	}
}
