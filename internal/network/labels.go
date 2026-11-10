package network

import (
	"context"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"

	"netmon/internal/config"
	"netmon/internal/identity"
	"netmon/internal/observation"
	"netmon/internal/providers"
)

type serverLabel struct{ name, source string }

// Labeler adds local address-book metadata outside the capture/write path.
// Explicit server labels override interface/cluster address hints.
type Labeler struct {
	providers providers.Loader
	cfg       config.Config
	book      identity.Loader
	mu        sync.Mutex
	refreshed time.Time
	automatic map[netip.Addr]serverLabel
}

func NewLabeler(c config.Config) *Labeler {
	return &Labeler{providers: providers.Loader{Path: c.ProvidersFile}, cfg: c, book: identity.Loader{Path: c.LabelsFile}}
}
func (l *Labeler) refresh() {
	if time.Since(l.refreshed) < 15*time.Second {
		return
	}
	l.refreshed = time.Now()
	automatic := map[netip.Addr]serverLabel{}
	addPeer := func(raw, name string) {
		u, e := url.Parse(raw)
		if e != nil {
			return
		}
		ip, e := netip.ParseAddr(u.Hostname())
		if e != nil || ip.IsUnspecified() {
			return
		}
		if name == "" {
			name = "configured cluster node"
		}
		automatic[ip.Unmap()] = serverLabel{name, "cluster-peer"}
	}
	if l.cfg.Cluster.Enabled {
		for _, raw := range l.cfg.Cluster.Peers {
			addPeer(raw, "")
		}
		if l.cfg.Storage.Mode == "full" {
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			peers, e := ReadPeers(ctx, l.cfg)
			cancel()
			if e == nil {
				for _, peer := range peers {
					addPeer(peer.URL, peer.Name)
				}
			}
		}
	}
	name := l.cfg.Cluster.Name
	if name == "" {
		name, _ = os.Hostname()
	}
	if name == "" {
		name = "this server"
	}
	name = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return '?'
		}
		return r
	}, name)
	if l.cfg.Cluster.Enabled {
		u, e := url.Parse(l.cfg.Cluster.Advertise)
		if e == nil {
			if ip, e := netip.ParseAddr(u.Hostname()); e == nil && !ip.IsUnspecified() {
				automatic[ip.Unmap()] = serverLabel{name, "local-advertise"}
			}
		}
	}
	if iface, e := net.InterfaceByName(l.cfg.Interface); e == nil {
		if addresses, e := iface.Addrs(); e == nil {
			for _, addr := range addresses {
				p, e := netip.ParsePrefix(addr.String())
				if e != nil || p.Addr().IsUnspecified() || p.Addr().IsMulticast() {
					continue
				}
				automatic[p.Addr().Unmap()] = serverLabel{name, "local-interface"}
			}
		}
	}
	l.automatic = automatic
}

// Snapshot freezes annotation metadata for a consistent bulk list/export.
func (l *Labeler) Snapshot() (func(*observation.IP), error) {
	servers, whitelist, e := l.book.Indexes()
	if e != nil {
		return nil, e
	}
	catalog, e := l.providers.Snapshot()
	if e != nil {
		return nil, e
	}
	l.mu.Lock()
	l.refresh()
	automatic := l.automatic
	l.mu.Unlock()
	return func(row *observation.IP) {
		row.ServerName = ""
		row.ServerSource = ""
		row.Whitelisted = false
		row.WhitelistDescription = ""
		row.Providers = nil
		row.ProviderRevision = ""
		row.ProviderDate = ""
		ip, e := netip.ParseAddr(row.IP)
		if e != nil {
			return
		}
		ip = ip.Unmap()
		row.Providers = catalog.Lookup(ip)
		if len(row.Providers) > 0 {
			row.ProviderRevision = catalog.Metadata.Revision
			row.ProviderDate = catalog.Metadata.Generated
		}
		if hint, exists := automatic[ip]; exists {
			row.ServerName = hint.name
			row.ServerSource = hint.source
		}
		if name := servers.Lookup(ip); name != "" {
			row.ServerName = name
			row.ServerSource = "address-book"
		}
		if description := whitelist.Lookup(ip); description != "" {
			row.Whitelisted = true
			row.WhitelistDescription = description
		}
	}, nil
}
func (l *Labeler) Annotate(rows []observation.IP) error {
	annotate, e := l.Snapshot()
	if e != nil {
		return e
	}
	for i := range rows {
		annotate(&rows[i])
	}
	return nil
}
