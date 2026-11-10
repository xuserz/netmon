package network

import (
	"context"
	"net"
	"sort"
	"sync"
	"time"

	"netmon/internal/config"
	"netmon/internal/live"
)

const maxIncomingNodes = 128

type contact struct {
	confirmed bool
	node      live.NetworkNode
	ttl       time.Duration
}
type presence struct {
	mu        sync.Mutex
	outgoing  map[string]contact
	incoming  map[string]contact
	evictions uint64
}

func newPresence() *presence {
	return &presence{outgoing: map[string]contact{}, incoming: map[string]contact{}}
}
func (t *transport) heartbeatInterval() time.Duration {
	return min(10*time.Second, cappedInterval(t.cfg.Cluster.SyncInterval))
}
func (t *transport) contactTTL() time.Duration {
	return max(15*time.Second, 3*t.heartbeatInterval()+time.Duration((len(t.list())+3)/4)*5*time.Second)
}
func (p *presence) recordOutgoing(url string, reply message, at time.Time, elapsed time.Duration, err error, ttl time.Duration) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	c := p.outgoing[url]
	if at.Before(c.node.LastAttempt) {
		return
	}
	c.node.Address = url
	c.node.Direction = "OUT"
	c.node.LastAttempt = at
	c.ttl = ttl
	if err == nil {
		c.confirmed = true
		c.node.Node = reply.Node
		c.node.Name = reply.Name
		c.node.Role = reply.Role
		c.node.LastSeen = at
		c.node.RTTMillis = float64(elapsed) / float64(time.Millisecond)
		c.node.Error = ""
	} else {
		c.node.Error = limitedError(err)
	}
	p.outgoing[url] = c
}
func (p *presence) recordIncoming(m message, remote string, now time.Time, fallback time.Duration) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	c, exists := p.incoming[m.Node]
	if !exists && len(p.incoming) >= maxIncomingNodes {
		oldest := ""
		for id, entry := range p.incoming {
			if oldest == "" || entry.node.LastSeen.Before(p.incoming[oldest].node.LastSeen) {
				oldest = id
			}
		}
		delete(p.incoming, oldest)
		p.evictions++
	}
	ip, _, e := net.SplitHostPort(remote)
	if e != nil {
		ip = remote
	}
	c.confirmed = true
	c.node.Node = m.Node
	c.node.Name = m.Name
	c.node.Role = m.Role
	c.node.Address = ip
	c.node.Direction = "IN"
	c.node.LastSeen = now
	c.ttl = fallback
	if m.ContactTTLSeconds > 0 {
		c.ttl = time.Duration(m.ContactTTLSeconds) * time.Second
	}
	p.incoming[m.Node] = c
}
func (p *presence) delivery(node string, at time.Time, err error) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	c, ok := p.incoming[node]
	if !ok {
		return
	}
	if err == nil {
		c.node.LastDelivery = at
		c.node.SyncError = ""
	} else {
		c.node.SyncError = limitedText("receive: " + err.Error())
	}
	p.incoming[node] = c
}
func (p *presence) deliveryTo(url string, at time.Time, err error) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	c := p.outgoing[url]
	if err == nil {
		c.node.LastDelivery = at
		c.node.SyncError = ""
	} else {
		c.node.SyncError = limitedText("delivery: " + err.Error())
	}
	p.outgoing[url] = c
}
func (p *presence) syncResult(url string, peer Peer, head int64, err error) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	c := p.outgoing[url]
	c.node.SyncError = limitedError(err)
	if err == nil {
		c.node.SyncKnown = true
		c.node.Cursor = peer.Cursor
		c.node.Head = head
		c.node.LastSync = time.Unix(peer.Success, 0)
	}
	p.outgoing[url] = c
}

// snapshot is local authenticated contact history, not a list of open TCP
// sockets or a globally authoritative membership registry. Idle connections
// close normally; periodic heartbeats keep healthy nodes visible.
func (p *presence) snapshot(peers []Peer, now time.Time, ttl time.Duration, liveSource bool) ([]live.NetworkNode, uint64) {
	if p == nil {
		p = newPresence()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	nodes := map[string]contact{}
	for _, peer := range peers {
		c, ok := p.outgoing[peer.URL]
		if !ok {
			c = contact{ttl: ttl, node: live.NetworkNode{Node: peer.Node, Name: peer.Name, Address: peer.URL, Direction: "OUT", Error: peer.Error}}
			if peer.Success > 0 {
				c.node.LastSeen = time.Unix(peer.Success, 0)
			}
			if peer.Node != "" {
				c.node.Role = "full"
			}
		}
		if c.node.Node == "" {
			c.node.Node = peer.Node
		}
		if c.node.Name == "" {
			c.node.Name = peer.Name
		}
		if c.node.Role == "" && c.node.Node != "" {
			c.node.Role = "full"
		}
		if c.node.LastSeen.IsZero() && peer.Success > 0 {
			c.node.LastSeen = time.Unix(peer.Success, 0)
		}
		key := c.node.Node
		if key == "" {
			key = "url:" + peer.URL
		}
		if prev, exists := nodes[key]; exists {
			if prev.node.LastSeen.After(c.node.LastSeen) {
				c = prev
			}
			c.node.Address = min(prev.node.Address, peer.URL)
		}
		nodes[key] = c
	}
	for id, in := range p.incoming {
		if out, ok := nodes[id]; ok {
			out.confirmed = out.confirmed || in.confirmed
			out.node.Direction = "BOTH"
			if in.node.LastSeen.After(out.node.LastSeen) {
				out.node.LastSeen = in.node.LastSeen
			}
			if out.node.Name == "" {
				out.node.Name = in.node.Name
			}
			if out.node.Role == "" {
				out.node.Role = in.node.Role
			}
			if in.node.LastDelivery.After(out.node.LastDelivery) {
				out.node.LastDelivery = in.node.LastDelivery
			}
			if out.node.SyncError == "" {
				out.node.SyncError = in.node.SyncError
			}
			out.ttl = max(out.ttl, in.ttl)
			nodes[id] = out
		} else {
			nodes[id] = in
		}
	}
	result := make([]live.NetworkNode, 0, len(nodes))
	for _, c := range nodes {
		n := c.node
		n.Address = limitedText(n.Address)
		n.Online = liveSource && c.confirmed && !n.LastSeen.IsZero() && now.Sub(n.LastSeen) <= c.ttl
		switch {
		case !liveSource:
			n.State = "STALE"
		case n.Online && (n.Error != "" || n.SyncError != ""):
			n.State = "DEGRADED"
		case n.Online:
			n.State = "ONLINE"
		case !c.confirmed && n.LastAttempt.IsZero():
			n.State = "UNKNOWN"
		default:
			n.State = "OFFLINE"
		}
		result = append(result, n)
	}
	sort.Slice(result, func(i, j int) bool {
		a, b := result[i], result[j]
		if a.Online != b.Online {
			return a.Online
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Node != b.Node {
			return a.Node < b.Node
		}
		return a.Address < b.Address
	})
	return result, p.evictions
}

func (t *transport) probe(ctx context.Context) {
	if !t.cfg.Cluster.Enabled {
		return
	}
	m := t.envelope()
	m.Heartbeat = true
	slots := make(chan struct{}, 4)
	var wg sync.WaitGroup
	for _, peer := range t.list() {
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			wg.Wait()
			return
		}
		wg.Add(1)
		go func(p Peer) {
			defer wg.Done()
			defer func() { <-slots }()
			work, stop := context.WithTimeout(ctx, 5*time.Second)
			defer stop()
			t.request(work, p, "/v3/network/ingest", m)
		}(peer)
	}
	wg.Wait()
}

// StoredNodes is deliberately marked stale: persisted replication cursors do
// not prove that a remote node is online while the local daemon is stopped.
func StoredNodes(ctx context.Context, c config.Config) ([]live.NetworkNode, error) {
	peers, e := ReadPeers(ctx, c)
	if e != nil {
		return nil, e
	}
	known := map[string]bool{}
	for _, p := range peers {
		known[p.URL] = true
	}
	for _, url := range c.Cluster.Peers {
		if !known[url] {
			peers = append(peers, Peer{URL: url})
		}
	}
	nodes, _ := newPresence().snapshot(peers, time.Now(), 15*time.Second, false)
	return nodes, nil
}
