package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"time"

	"netmon/internal/config"
	"netmon/internal/network"
	"netmon/internal/observation"
)

func historySince(value string, now time.Time) (int64, error) {
	if value == "all" {
		return 0, nil
	}
	if d, e := time.ParseDuration(value); e == nil && d > 0 {
		return max(int64(0), now.Add(-d).Unix()/60*60), nil
	}
	at, e := time.Parse(time.RFC3339, value)
	if e != nil || at.After(now) {
		return 0, errors.New("--since must be a positive duration, past RFC3339 timestamp, or all")
	}
	return max(int64(0), at.Unix()/60*60), nil
}
func incidentCommand(args []string, c config.Config, out, errOut io.Writer) error {
	fs := flag.NewFlagSet("incidents", flag.ContinueOnError)
	fs.SetOutput(errOut)
	since := fs.String("since", "24h", "duration, RFC3339 timestamp, or all")
	ip := fs.String("ip", "", "source IP filter")
	id := fs.String("id", "", "incident ID; show full evidence")
	limit := fs.Int("n", 20, "maximum incidents, 1..1000")
	asJSON := fs.Bool("json", false, "print complete evidence as JSON")
	timeout := fs.Duration("timeout", 10*time.Second, "read deadline, 1s..5m")
	if e := fs.Parse(args); e != nil {
		if errors.Is(e, flag.ErrHelp) {
			return nil
		}
		return e
	}
	if fs.NArg() != 0 {
		return errors.New("use incidents [--ip IP] [--id ID] [--since 24h] [--json]")
	}
	if *timeout < time.Second || *timeout > 5*time.Minute {
		return errors.New("--timeout must be 1s..5m")
	}
	cutoff, e := historySince(*since, time.Now())
	if e != nil {
		return e
	}
	if *id != "" {
		if !observation.ValidID(*id) {
			return errors.New("invalid incident ID")
		}
		cutoff = 0
	}
	if *ip != "" {
		addr, e := netip.ParseAddr(*ip)
		if e != nil || addr.Zone() != "" {
			return errors.New("invalid source IP")
		}
		*ip = addr.Unmap().String()
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	events, e := network.ReadIncidents(ctx, c, *ip, *id, cutoff, *limit)
	if e != nil {
		return e
	}
	if *asJSON {
		return json.NewEncoder(out).Encode(events)
	}
	if len(events) == 0 {
		fmt.Fprintln(out, "No saved incidents in this range. Analysis is asynchronous; missing evidence is not proof of safety.")
		return nil
	}
	for _, v := range events {
		fmt.Fprintf(out, "%s  %s  %s  severity=%d/100  nodes=%d  SYN=%s  partial=%t\n", v.ID, v.IP, v.Kind, v.Score, v.Nodes, commas(fmt.Sprint(v.SYN)), v.Partial)
		fmt.Fprintf(out, "  %s → %s\n  %s\n", time.Unix(v.First, 0).Format(time.RFC3339), time.Unix(v.Last, 0).Format(time.RFC3339), v.Reason)
		if *id != "" {
			for _, f := range v.Facts {
				fmt.Fprintf(out, "  Node %s (%s), minute %s: eligible packets=%d SYN=%d peak=%d/s SYN peak=%d/s ports=%v partial=%t\n", f.Node, f.Name, time.Unix(f.Window, 0).Format(time.RFC3339), f.Packets, f.SYN, f.PPS, f.SynPPS, f.Ports, f.Partial)
			}
		}
	}
	fmt.Fprintln(out, "Incidents are heuristic observations; source IPs may be shared or spoofed.")
	return nil
}
func printProfile(out io.Writer, p observation.Profile) {
	fmt.Fprintf(out, "\nDetail range: %s → %s (minute granularity)\nObservation rows: %d; partial detail: %t\nTraffic: INBOUND=%s REPLY=%s UNKNOWN=%s\nPackets without port detail: %s\n", time.Unix(p.Since, 0).Format(time.RFC3339), time.Unix(p.Until, 0).Format(time.RFC3339), p.Rows, p.Partial, commas(fmt.Sprint(p.Traffic.Inbound)), commas(fmt.Sprint(p.Traffic.Reply)), commas(fmt.Sprint(p.Traffic.Unknown)), commas(fmt.Sprint(p.Unattributed)))
	fmt.Fprintln(out, "NODE / NAME                        PROTO PORT  CLASS         PACKETS          SYN       IP BYTES")
	for _, t := range p.Targets {
		node := t.Name
		if node == "" {
			node = t.Node
		}
		proto := fmt.Sprint(t.Protocol)
		switch t.Protocol {
		case 6:
			proto = "TCP"
		case 17:
			proto = "UDP"
		case 1:
			proto = "ICMP"
		case 58:
			proto = "ICMP6"
		}
		fmt.Fprintf(out, "%-34s %-5s %-5d %-8s %12s %12s %14s\n", node, proto, t.Port, t.Class.String(), commas(fmt.Sprint(t.Packets)), commas(fmt.Sprint(t.SYN)), commas(fmt.Sprint(t.Bytes)))
	}
	for _, n := range p.Nodes {
		fmt.Fprintf(out, "Node totals: %s (%s) packets=%s SYN=%s\n", n.Node, n.Name, commas(fmt.Sprint(n.Packets)), commas(fmt.Sprint(n.SYN)))
	}
}
