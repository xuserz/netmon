package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"netmon/internal/config"
	"netmon/internal/live"
	"netmon/internal/network"
	"netmon/internal/observation"
	"netmon/internal/ui"
)

func networkFetch(ctx context.Context, c config.Config, kind string, n int, local bool, labels *network.Labeler) (live.Response, error) {
	if r, e := live.Fetch(ctx, network.RuntimeBase(c), live.Request{Op: "top", Sort: kind, Limit: n, Local: local}); e == nil && r.Network {
		r.NetworkIPs = append([]observation.IP(nil), r.NetworkIPs...)
		if e := labels.Annotate(r.NetworkIPs); e != nil {
			return live.Response{}, e
		}
		return r, nil
	}
	if c.Storage.Mode == "forward" || local {
		return live.Response{}, errors.New("forward/local RAM statistics require a running network monitor; inspect a storage node for history")
	}
	rows, totals, e := network.Read(ctx, c, kind, n)
	if e != nil {
		return live.Response{}, e
	}
	nodes, e := network.StoredNodes(ctx, c)
	if e != nil {
		return live.Response{}, e
	}
	return live.Response{Network: true, NetworkNodes: nodes, NetworkIPs: rows, NetworkTotals: totals, Source: "stored", SnapshotAt: time.Now(), Health: live.Health{Mode: "network", StorageMode: c.Storage.Mode, Storage: network.StorageUsage(ctx, c), ClusterEnabled: c.Cluster.Enabled, ClusterPeers: len(nodes)}}, nil
}
func printNetworkRow(w io.Writer, r observation.IP) error {
	_, e := fmt.Fprintf(w, "%-39s %5d %16s %16s %12s %-9s %s\n", r.IP, r.Score, commas(fmt.Sprint(r.Packets)), commas(fmt.Sprint(r.Bytes)), commas(fmt.Sprint(r.SYN)), r.DisplayTag(), r.Label())
	return e
}
func printNetworkRows(w io.Writer, rows []observation.IP) {
	fmt.Fprintf(w, "%-39s %5s %16s %16s %12s %-9s %s\n", "SOURCE IP", "RISK", "PACKETS", "IP BYTES", "TCP SYN", "TYPE", "DESCRIPTION")
	for _, r := range rows {
		printNetworkRow(w, r)
	}
}
func printNetworkTotals(w io.Writer, r live.Response) {
	scope := "Saved network window"
	if r.Partial {
		scope = "Local RAM sample (bounded; totals since process start)"
	}
	fmt.Fprintf(w, "%s\nObserved IPs: %s\nPackets: %s\nIP bytes: %s\nTCP SYN packets: %s\nUDP packets: %s\n", scope, commas(fmt.Sprint(r.NetworkTotals.IPs)), commas(fmt.Sprint(r.NetworkTotals.Packets)), commas(fmt.Sprint(r.NetworkTotals.Bytes)), commas(fmt.Sprint(r.NetworkTotals.SYN)), commas(fmt.Sprint(r.NetworkTotals.UDP)))
}
func networkCommand(command string, args []string, c config.Config, out, errOut io.Writer) error {
	if command == "run" {
		if len(args) != 0 {
			return errors.New("run takes no arguments")
		}
		syscall.Umask(0027)
		ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer cancel()
		return network.Run(ctx, c)
	}
	if command == "compact" {
		return compactCommand(args, c, out, errOut)
	}
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(errOut)
	local := fs.Bool("local", false, "show bounded current-process RAM counters")
	n := fs.Int("n", 20, "top rows (maximum 1000)")
	sort := fs.String("sort", "score", "rank by score, total, bytes, or syn")
	once := fs.Bool("once", false, "print once")
	showNodes := fs.Bool("nodes", false, "start top on the node-connections view; n switches views")
	jsonNodes := fs.Bool("json", false, "nodes: print machine-readable node presence")
	watch := fs.Bool("watch", false, "require interactive top")
	noColor := fs.Bool("no-color", false, "disable colors")
	interval := fs.Duration("interval", 2*time.Second, "refresh interval")
	csv := fs.String("csv", "", "CSV destination")
	timeout := fs.Duration("timeout", 5*time.Minute, "export deadline")
	snapshotDirectory := fs.String("snapshot-dir", ".", "filesystem for an isolated bulk-list snapshot")
	startup := fs.Bool("startup", false, "startup checks")
	since := fs.String("since", "24h", "show: saved detail duration, RFC3339 timestamp, or all")
	if command == "show" && len(args) > 0 {
		if _, e := netip.ParseAddr(args[0]); e == nil {
			args = append(append([]string(nil), args[1:]...), args[0])
		}
	}
	if e := fs.Parse(args); e != nil {
		if errors.Is(e, flag.ErrHelp) {
			return nil
		}
		return e
	}
	_ = startup
	if *showNodes && command != "top" {
		return errors.New("--nodes applies to top; use netmon nodes")
	}
	if *jsonNodes && ((command != "nodes" && command != "show") || *watch) {
		return errors.New("--json applies to nodes/show without --watch")
	}
	if command == "nodes" && *once && *watch {
		return errors.New("--once and --watch are mutually exclusive")
	}
	labels := network.NewLabeler(c)
	if *n < 1 || *n > 1000 {
		return errors.New("network -n must be 1..1000")
	}
	if *sort != "score" && *sort != "total" && *sort != "bytes" && *sort != "syn" {
		return errors.New("network --sort must be score, total, bytes, or syn")
	}
	if command != "show" && fs.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if command == "check" {
		if e := network.Check(c); e != nil {
			return e
		}
		if e := labels.Annotate(nil); e != nil {
			return e
		}
		if c.Network.Capture {
			iface, e := net.InterfaceByName(c.Interface)
			if e != nil {
				return e
			}
			if iface.Flags&net.FlagUp == 0 {
				return errors.New("capture interface is down")
			}
		}
		fmt.Fprintf(out, "[OK] network mode; storage=%s; capture=%t\n", c.Storage.Mode, c.Network.Capture)
		if c.Storage.Mode == "forward" {
			fmt.Fprintln(out, "[OK] statistics are RAM-only; no local SQLite database will be opened")
		}
		return nil
	}
	if command == "export" {
		if *csv == "" {
			return errors.New("export requires --csv FILE")
		}
		if c.Storage.Mode == "forward" || *local {
			return errors.New("export history on a full storage node; RAM samples are available through top/show")
		}
		if *timeout < time.Second || *timeout > 24*time.Hour {
			return errors.New("--timeout must be 1s..24h")
		}
		ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer cancel()
		ctx, stop := context.WithTimeout(ctx, *timeout)
		defer stop()
		if e := network.Export(ctx, c, *csv); e != nil {
			return e
		}
		fmt.Fprintln(out, "Exported network statistics:", *csv)
		return nil
	}
	if command == "list" && c.Storage.Mode == "full" && !*local {
		if *timeout < time.Second || *timeout > 24*time.Hour {
			return errors.New("--timeout must be 1s..24h")
		}
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		ctx, cancel := context.WithTimeout(ctx, *timeout)
		defer cancel()
		printNetworkRows(out, nil)
		totals, e := network.List(ctx, c, *snapshotDirectory, *sort, func(row observation.IP) error {
			return printNetworkRow(out, row)
		})
		if e != nil {
			return e
		}
		printNetworkTotals(out, live.Response{Network: true, NetworkTotals: totals})
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if command == "status" {
		r, e := live.Fetch(ctx, network.RuntimeBase(c), live.Request{Op: "health"})
		if e != nil {
			return fmt.Errorf("network monitor unavailable: %w", e)
		}
		h := r.Health
		fmt.Fprintf(out, "NETWORK MONITOR · %s · PID %d\nNode: %s\nLocal captured packets: %d\nKernel drops: %d\nMalformed packets: %d\nRAM queue: %d/%d bytes\nQueue rejections: %d\nDiscarded observations: %d\nDelivery ACKs: %d\nLast durable delivery: %s\nNodes online: %d/%d\nError: %s\n", h.StorageMode, h.PID, h.ClusterNode, h.Counted, h.KernelDrops, h.MalformedPackets, h.QueueBytes, h.QueueLimit, h.QueueRejected, h.DiscardedSamples, h.DeliveryAcks, timestamp(h.LastFlush), h.ClusterOnline, h.ClusterPeers, h.FlushError)
		fmt.Fprintf(out, "Build: %s\nUpdate: %s; target: %s\n", h.BuildVersion, h.Update.State, h.Update.Target)
		fmt.Fprintf(out, "Flow cache: %d; evictions: %d\nSaved incidents: %d; analysis lag: %d changes\nAnalysis: %s\n", h.TrackedFlows, h.FlowEvictions, h.IncidentCount, h.AnalysisLag, h.AnalysisError)
		printNetworkStorage(out, h)

		if h.StorageMode == "full" {
			retention := "unlimited age; oldest windows removed at capacity"
			if h.RetentionSeconds > 0 {
				retention = (time.Duration(h.RetentionSeconds) * time.Second).String()
			}
			floor := "none"
			if h.StorageFloor > 0 {
				floor = time.Unix(h.StorageFloor, 0).Format(time.RFC3339)
			}
			fmt.Fprintf(out, "Retention: %s\nStorage cutoff: %s\nPruned observations: %d\n", retention, floor, h.PrunedObservations)
		}
		if h.FlushError != "" {
			return errors.New(h.FlushError)
		}
		return nil
	}
	if command == "nodes" && !*watch {
		response, e := networkNodesFetch(ctx, c)
		if e != nil {
			return e
		}
		return printNetworkNodes(out, response, *jsonNodes)
	}
	if command == "show" {
		if *timeout < time.Second || *timeout > 5*time.Minute {
			return errors.New("show --timeout must be 1s..5m")
		}
		ctx, cancel := context.WithTimeout(context.Background(), min(*timeout, 5*time.Minute))
		defer cancel()
		if fs.NArg() != 1 {
			return errors.New("show requires exactly one IP")
		}
		addr, e := netip.ParseAddr(fs.Arg(0))
		if e != nil || addr.Zone() != "" {
			return errors.New("invalid IP address")
		}
		cutoff, e := historySince(*since, time.Now())
		if e != nil {
			return e
		}
		var profile *observation.Profile
		var events []observation.Incident
		var row observation.IP
		if c.Storage.Mode == "full" && !*local {
			row, e = network.ReadIP(ctx, c, addr.Unmap().String())
			if e == nil {
				work, cancel := context.WithTimeout(ctx, min(*timeout, 5*time.Minute))
				p, pe := network.ReadProfile(work, c, addr.Unmap().String(), cutoff, time.Now().Unix())
				if pe == nil {
					profile = &p
					events, pe = network.ReadIncidents(work, c, addr.Unmap().String(), "", cutoff, 20)
				}
				cancel()
				if pe != nil {
					return pe
				}
			}
		} else {
			var response live.Response
			response, e = live.Fetch(ctx, network.RuntimeBase(c), live.Request{Op: "show", IP: addr.Unmap().String(), Sort: *sort, Limit: 1, Local: true})
			if e == nil && len(response.NetworkIPs) == 1 {
				row = response.NetworkIPs[0]
				profile = response.Profile
			} else if e == nil {
				e = errors.New("IP is not in the bounded RAM sample")
			}
		}
		if e != nil {
			return e
		}
		one := []observation.IP{row}
		if e = labels.Annotate(one); e != nil {
			return e
		}
		row = one[0]
		if *jsonNodes {
			return json.NewEncoder(out).Encode(struct {
				Summary   observation.IP         `json:"summary"`
				Profile   *observation.Profile   `json:"profile"`
				Incidents []observation.Incident `json:"incidents"`
			}{row, profile, events})
		}
		printNetworkRows(out, []observation.IP{row})
		if row.Correlation != nil {
			fmt.Fprintf(out, "Intensity suspicion: %d/100; correlation: incident %s\n", row.IntensityScore, row.Correlation.ID)
		}
		fmt.Fprintf(out, "All saved traffic: INBOUND=%s REPLY=%s UNKNOWN=%s\n", commas(fmt.Sprint(row.Traffic.Inbound)), commas(fmt.Sprint(row.Traffic.Reply)), commas(fmt.Sprint(row.Traffic.Unknown)))
		if profile != nil {
			if c.Storage.Mode == "forward" || *local {
				fmt.Fprintln(out, "Local RAM detail: latest published minute; no saved history.")
			}
			printProfile(out, *profile)
		}
		for _, v := range events {
			fmt.Fprintf(out, "Incident: %s %s severity=%d/100 nodes=%d partial=%t\n  %s\n", v.ID, v.Kind, v.Score, v.Nodes, v.Partial, v.Reason)
		}
		if row.ServerName != "" {
			fmt.Fprintf(out, "Server: %s (%s)\n", row.ServerName, row.ServerSource)
		}
		for _, p := range row.Providers {
			fmt.Fprintf(out, "Provider: %s (%s); matched %s; catalog %s @ %s\n", p.Name, p.Category, p.CIDR, row.ProviderDate, row.ProviderRevision)
		}
		if row.Whitelisted {
			fmt.Fprintf(out, "Whitelist: %s (counts and suspicion are retained)\n", row.WhitelistDescription)
		}
		fmt.Fprintf(out, "Suspicion: %d/100 (heuristic)\nFirst seen: %s\nLast seen: %s\nEvidence at: %s\nPartial evidence: %t\n", row.Score, time.Unix(row.First, 0).Format(time.RFC3339), time.Unix(row.Last, 0).Format(time.RFC3339), timestamp(time.Unix(row.EvidenceAt, 0)), row.Partial)
		if len(row.Reasons) == 0 {
			fmt.Fprintln(out, "No threshold signal observed; this is not proof that an IP is safe.")
		}
		for _, reason := range row.Reasons {
			fmt.Fprintln(out, "-", reason)
		}
		return nil
	}
	if command == "top" && *once && *watch {
		return errors.New("--once and --watch are mutually exclusive")
	}
	if *interval < 250*time.Millisecond || *interval > time.Minute {
		return errors.New("--interval must be 250ms..1m")
	}
	if (command == "top" || command == "nodes") && !*once && (*watch || terminalOutput(out)) {
		file, ok := out.(*os.File)
		if !ok {
			return errors.New("live top requires a terminal")
		}
		background, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		_, envNoColor := os.LookupEnv("NO_COLOR")
		return ui.Run(background, ui.Options{Network: true, Nodes: command == "nodes" || *showNodes, In: os.Stdin, Out: file, Interval: *interval, Version: version, Sort: *sort, Color: !*noColor && !envNoColor}, func(ctx context.Context, sort string) (live.Response, error) {
			return networkFetch(ctx, c, sort, *n, *local, labels)
		})
	}
	r, e := networkFetch(ctx, c, *sort, *n, *local, labels)
	if e != nil {
		return e
	}
	if command == "top" && *showNodes {
		return printNetworkNodes(out, r, false)
	}
	if command == "top" || command == "list" {
		printNetworkRows(out, r.NetworkIPs)
	}
	printNetworkTotals(out, r)
	if command == "top" {
		printNetworkStorage(out, r.Health)
	}
	return nil
}

func printNetworkStorage(out io.Writer, h live.Health) {
	u := h.Storage
	if h.StorageMode == "forward" {
		fmt.Fprintln(out, "Database: disabled (forward / RAM only)")
	} else if u.Enabled && u.DatabaseKnown {
		fmt.Fprintf(out, "Database: %.2f MiB / %.0f MiB limit; WAL: %.2f MiB; files: %.2f MiB\n", float64(u.DatabaseBytes)/(1<<20), float64(u.LimitBytes)/(1<<20), float64(u.WALBytes)/(1<<20), float64(u.FilesBytes)/(1<<20))
	}
	if u.DiskKnown {
		fmt.Fprintf(out, "Disk available: %.2f MiB\n", float64(u.DiskAvailableBytes)/(1<<20))
		if u.Enabled && u.DatabaseKnown {
			fmt.Fprintf(out, "Estimated write headroom before cleanup: %.2f MiB\n", float64(u.HeadroomBytes)/(1<<20))
		}
	}
	if u.Error != "" {
		fmt.Fprintf(out, "Storage metrics error: %s\n", u.Error)
	}
}
