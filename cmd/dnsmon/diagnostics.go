package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os/exec"
	"time"

	"dnsmon/internal/config"
	"dnsmon/internal/diagnostic"
	"dnsmon/internal/live"
)

func check(c config.Config, args []string, out, errOut io.Writer) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(errOut)
	startup := fs.Bool("startup", false, "validate startup settings without requiring a running service")
	if e := fs.Parse(args); e != nil {
		if errors.Is(e, flag.ErrHelp) {
			return nil
		}
		return e
	}
	if fs.NArg() != 0 {
		return errors.New("check takes no positional arguments")
	}
	failed := false
	for _, f := range diagnostic.Checks(c, *startup) {
		fmt.Fprintf(out, "[%s] %s\n", f.Level, f.Message)
		if f.Level == "FAIL" {
			failed = true
		}
	}
	if failed {
		return errors.New("startup checks failed; correct the reported settings")
	}
	return nil
}
func status(c config.Config, out, errOut io.Writer) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	r, e := live.Fetch(ctx, c.Database, live.Request{Op: "health"})
	if e == nil {
		h := r.Health
		fmt.Fprintf(out, "DNSMON · RUNNING · PID %d\nInterface: %s  Port: %d\nUptime: %s\nCaptured packets: %d\nCounted this run: %d\nKernel drops: %d\n", h.PID, h.Interface, h.Port, time.Since(h.Started).Truncate(time.Second), h.Received, h.Counted, h.KernelDrops)
		fmt.Fprintf(out, "Last request: %s\nLast successful flush: %s\nLast flush duration: %s\nPending: %d requests / %d IP slots\nWriter busy: %t  Backpressure waits: %d\n", timestamp(h.LastRequest), timestamp(h.LastFlush), h.FlushDuration, h.PendingRequests, h.PendingIPs, h.Writing, h.Backpressure)
		fmt.Fprintf(out, "TCP: %d active flows / %d buffered bytes\nFragments: %d sets / %d buffered bytes\nParser: %+v\nReceive ring: requested=%d actual=%d\nRSS: %.1f MiB\n", h.TCPFlows, h.TCPBytes, h.Fragments, h.FragmentBytes, h.Parser, h.RequestedBuffer, h.ActualBuffer, float64(h.RSSBytes)/(1<<20))
		fmt.Fprintf(out, "Capture: %s; lag=%s\nWriter retries: %d\n", h.CaptureMode, h.CaptureLag.Round(time.Millisecond), h.WriteRetries)
		fmt.Fprintf(out, "Capture sample age: %s\nBlocked for: %s  Oldest pending: %s\nActivity cache: %d/%d IPs; evictions=%d\nSQLite: %s\n", time.Since(h.CaptureUpdated).Round(time.Millisecond), h.BlockedFor.Round(time.Millisecond), h.PendingAge.Round(time.Millisecond), h.ActivityEntries, h.ActivityLimit, h.ActivityEvictions, h.SQLiteVersion)
		if h.CaptureError != "" {
			return errors.New(h.CaptureError)
		}
		if h.FlushError != "" {
			return fmt.Errorf("writer: %s", h.FlushError)
		}
		return nil
	}
	fmt.Fprintln(out, "Live capture unavailable; systemd state:")
	cmd := exec.CommandContext(ctx, "systemctl", "show", "dnsmon.service", "--no-pager", "--property=LoadState,ActiveState,SubState,MainPID,ExecMainStatus")
	cmd.Stdout = out
	cmd.Stderr = errOut
	stateErr := cmd.Run()
	fmt.Fprintln(out, "Details: journalctl -u dnsmon -b -n 30 --no-pager -o cat")
	if stateErr != nil {
		return stateErr
	}
	return errors.New("monitor is not responding on its diagnostic socket")
}
func timestamp(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.Local().Format(time.RFC3339)
}
