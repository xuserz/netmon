package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"netmon/internal/config"
	"netmon/internal/live"
	"netmon/internal/network"
)

func networkNodesFetch(ctx context.Context, c config.Config) (live.Response, error) {
	r, e := live.Fetch(ctx, network.RuntimeBase(c), live.Request{Op: "health"})
	if e == nil && r.Network {
		return r, nil
	}
	if c.Storage.Mode == "forward" {
		return live.Response{}, errors.New("network monitor unavailable; forward node presence exists only in RAM")
	}
	nodes, e := network.StoredNodes(ctx, c)
	if e != nil {
		return live.Response{}, e
	}
	return live.Response{Network: true, NetworkNodes: nodes, Source: "stored", SnapshotAt: time.Now(), Health: live.Health{ClusterEnabled: c.Cluster.Enabled, ClusterPeers: len(nodes), StorageMode: c.Storage.Mode}}, nil
}
func printNetworkNodes(w io.Writer, r live.Response, jsonOutput bool) error {
	if jsonOutput {
		return json.NewEncoder(w).Encode(struct {
			Source         string             `json:"source"`
			LocalNode      string             `json:"local_node"`
			Online         int                `json:"online"`
			Nodes          []live.NetworkNode `json:"nodes"`
			CacheEvictions uint64             `json:"cache_evictions"`
		}{r.Source, r.Health.ClusterNode, r.Health.ClusterOnline, r.NetworkNodes, r.Health.NodeCacheEvictions})
	}
	if !r.Health.ClusterEnabled {
		fmt.Fprintln(w, "Cluster is disabled; showing any saved peer records.")
	}
	fmt.Fprintf(w, "Nodes online: %d/%d · source: %s · local node: %s\n", r.Health.ClusterOnline, len(r.NetworkNodes), r.Source, r.Health.ClusterNode)
	fmt.Fprintf(w, "%-9s %-7s %-5s %-24s %-10s %-10s %-10s %s\n", "STATE", "ROLE", "LINK", "NAME / NODE", "SEEN", "RTT", "SYNC GAP", "ADDRESS")
	for _, n := range r.NetworkNodes {
		name := n.Name
		if name == "" {
			name = n.Node
		}
		if name == "" {
			name = "unidentified"
		}
		pending := "-"
		if n.SyncKnown {
			pending = fmt.Sprint(max(int64(0), n.Head-n.Cursor))
		}
		rtt := "-"
		if !n.LastAttempt.IsZero() && !n.LastSeen.IsZero() {
			rtt = fmt.Sprintf("%.1fms", n.RTTMillis)
		}
		fmt.Fprintf(w, "%-9s %-7s %-5s %-24s %-10s %-10s %-10s %s\n", n.State, n.Role, n.Direction, name, nodeAge(n.LastSeen), rtt, pending, n.Address)
		fmt.Fprintf(w, "  ID: %s · contact: %s · delivery: %s · sync: %s\n", n.Node, timestamp(n.LastSeen), timestamp(n.LastDelivery), timestamp(n.LastSync))
		if n.SyncKnown {
			fmt.Fprintf(w, "  Cursor: %d / %d\n", n.Cursor, n.Head)
		}
		if n.Error != "" {
			fmt.Fprintln(w, "  Connection:", n.Error)
		}
		if n.SyncError != "" {
			fmt.Fprintln(w, "  Synchronization:", n.SyncError)
		}
	}
	if r.Source != "live" {
		fmt.Fprintln(w, "STALE: local daemon is unavailable; saved contacts do not establish current availability.")
	}
	if r.Health.NodeCacheEvictions > 0 {
		fmt.Fprintf(w, "Incoming node cache evictions: %d; contact list may be incomplete.\n", r.Health.NodeCacheEvictions)
	}
	return nil
}
func nodeAge(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return max(time.Duration(0), time.Since(t)).Round(time.Second).String()
}
