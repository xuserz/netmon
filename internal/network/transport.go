package network

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"netmon/internal/cluster"
	"netmon/internal/config"
	"netmon/internal/observation"
	"netmon/internal/release"
)

const wireVersion = 4
const maxWire = 2 << 20

type message struct {
	Build             string             `json:"build,omitempty"`
	Update            *release.Offer     `json:"update,omitempty"`
	UpdateStatus      release.Status     `json:"update_status,omitempty"`
	UpdateLease       *UpdateLease       `json:"update_lease,omitempty"`
	Heartbeat         bool               `json:"heartbeat,omitempty"`
	ContactTTLSeconds int64              `json:"contact_ttl_seconds,omitempty"`
	Version           int                `json:"version"`
	Mode              string             `json:"mode"`
	PolicyVersion     string             `json:"policy_version"`
	Policy            observation.Policy `json:"policy"`
	Retention         int64              `json:"retention"`
	Node              string             `json:"node"`
	Name              string             `json:"name"`
	Role              string             `json:"role"`
	Advertise         string             `json:"advertise"`
	Peers             []string           `json:"peers,omitempty"`
	Page
}
type transport struct {
	updates       *updateControl
	presence      *presence
	cfg           config.Config
	node, name    string
	store         *disk
	mu            sync.Mutex
	peers         map[string]Peer
	client        *http.Client
	httpTransport *http.Transport
	server        *http.Server
	slots         chan struct{}
}

func forwardIdentity(c config.Config, key []byte) string {
	name := c.Cluster.Name
	if name == "" {
		name, _ = os.Hostname()
	}
	machine, _ := os.ReadFile("/etc/machine-id")
	mac := hmac.New(sha256.New, key)
	// Preserve existing RAM-only sensor identities after the rename.
	mac.Write([]byte("dnsmon-network-sensor-v1/" + name + "/"))
	mac.Write(machine)
	return hex.EncodeToString(mac.Sum(nil)[:16])
}
func newTransport(c config.Config, node, name string, d *disk) (*transport, error) {
	t := &transport{updates: newUpdateControl(c), presence: newPresence(), cfg: c, node: node, name: name, store: d, peers: map[string]Peer{}, slots: make(chan struct{}, 4)}
	if !c.Cluster.Enabled {
		return t, nil
	}
	key, e := cluster.ReadKey(c.Cluster.KeyFile)
	if e != nil {
		return nil, e
	}
	serverTLS, clientTLS, e := cluster.TransportTLS(key, node)
	if e != nil {
		return nil, e
	}
	t.httpTransport = &http.Transport{TLSClientConfig: clientTLS, MaxResponseHeaderBytes: 8192, MaxIdleConns: 4, MaxIdleConnsPerHost: 1, MaxConnsPerHost: 1, IdleConnTimeout: 2 * time.Second, ResponseHeaderTimeout: 3 * time.Second}
	t.client = &http.Client{Transport: t.httpTransport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if d != nil {
		saved, e := d.Peers(context.Background())
		if e != nil {
			return nil, e
		}
		for _, p := range saved {
			t.peers[p.URL] = p
		}
	}
	for _, raw := range c.Cluster.Peers {
		t.discover(raw)
	}
	if c.Storage.Mode == "full" {
		listener, e := net.Listen("tcp", c.Cluster.Listen)
		if e != nil {
			return nil, e
		}
		t.server = &http.Server{Handler: http.HandlerFunc(t.handle), TLSConfig: serverTLS, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 2 * time.Second, MaxHeaderBytes: 8192, ErrorLog: log.New(io.Discard, "", 0)}
		go func() {
			if e := t.server.Serve(tls.NewListener(cluster.LimitListener(listener, 16), serverTLS)); e != nil && !errors.Is(e, http.ErrServerClosed) {
				log.Printf("network replication listener failed: %v", e)
			}
		}()
	}
	return t, nil
}
func (t *transport) close() {
	if t.server != nil {
		t.server.Close()
	}
	if t.httpTransport != nil {
		t.httpTransport.CloseIdleConnections()
	}
}
func (t *transport) discover(raw string) {
	url, e := config.PeerURL(raw)
	if e != nil {
		return
	}
	self, _ := config.PeerURL(t.cfg.Cluster.Advertise)
	if url == self {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.peers) < config.MaxClusterPeers {
		if _, exists := t.peers[url]; !exists {
			t.peers[url] = Peer{URL: url}
		}
	}
}
func (t *transport) list() []Peer {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]Peer, 0, len(t.peers))
	for _, p := range t.peers {
		out = append(out, p)
	}
	return out
}
func (t *transport) remember(p Peer) { t.mu.Lock(); t.peers[p.URL] = p; t.mu.Unlock() }
func (t *transport) envelope() message {
	m := message{Version: wireVersion, Mode: "network", PolicyVersion: observation.PolicyVersion, Policy: Policy(t.cfg), Retention: int64(t.cfg.Storage.Retention / time.Second), Node: t.node, Name: t.name, Role: t.cfg.Storage.Mode, ContactTTLSeconds: int64(t.contactTTL() / time.Second)}
	m.Build = t.cfg.BuildVersion
	m.UpdateStatus = t.updateStatus()
	if t.cfg.Updates.Propagate {
		m.Update = t.updates.snapshot()
	}
	if t.cfg.Storage.Mode == "full" {
		m.Advertise, _ = config.PeerURL(t.cfg.Cluster.Advertise)
	}
	for _, p := range t.list() {
		if len(m.Peers) < config.MaxClusterPeers {
			m.Peers = append(m.Peers, p.URL)
		}
	}
	if m.Advertise != "" && len(m.Peers) < config.MaxClusterPeers {
		m.Peers = append(m.Peers, m.Advertise)
	}
	return m
}
func (t *transport) validate(m message, control ...bool) error {
	legacy := len(control) > 0 && control[0] && m.Version == 3
	if len(m.UpdateStatus.Blocked) > 128 || observation.InvalidName(m.UpdateStatus.Blocked) || len(m.UpdateStatus.Version) > 128 || len(m.UpdateStatus.Target) > 128 || len(m.UpdateStatus.State) > 32 || len(m.UpdateStatus.Error) > 256 || observation.InvalidName(m.UpdateStatus.Version+m.UpdateStatus.Target+m.UpdateStatus.State+m.UpdateStatus.Error) {
		return errors.New("invalid update status")
	}
	if len(m.Build) > 128 || observation.InvalidName(m.Build) || m.Update != nil && (len(m.Update.Manifest) > release.MaxManifest || len(m.Update.Signature) > 128) {
		return errors.New("invalid peer update metadata")
	}
	if m.UpdateLease != nil {
		l := m.UpdateLease
		if (l.Action != "acquire" && l.Action != "release") || !observation.ValidID(l.Token) || !release.ValidVersion(l.Target) || len(l.Error) > 256 {
			return errors.New("invalid update lease")
		}
	}
	if (m.Version != wireVersion && !legacy) || m.Mode != "network" || m.PolicyVersion != observation.PolicyVersion || m.Policy != Policy(t.cfg) || m.Retention != int64(t.cfg.Storage.Retention/time.Second) {
		return errors.New("network mode, rating policy, or retention differs between nodes")
	}
	if m.ContactTTLSeconds != 0 && (m.ContactTTLSeconds < 15 || m.ContactTTLSeconds > 120) {
		return errors.New("invalid contact lifetime")
	}
	if m.Floor < 0 || m.Floor%60 != 0 || m.Floor > time.Now().Unix()+300 {
		return errors.New("invalid storage floor")
	}
	if !observation.ValidID(m.Node) || len(m.Name) > 128 || observation.InvalidName(m.Name) || (m.Role != "full" && m.Role != "forward") || len(m.Peers) > config.MaxClusterPeers || len(m.Samples)+len(m.Incidents) > 128 {
		return errors.New("invalid network peer message")
	}
	return nil
}
func (t *transport) request(ctx context.Context, p Peer, path string, m message) (response message, err error) {
	started := time.Now()
	defer func() {
		t.presence.recordOutgoing(p.URL, response, time.Now(), time.Since(started), err, t.contactTTL())
	}()
	raw, e := json.Marshal(m)
	if e != nil {
		return response, e
	}
	if len(raw) > maxWire {
		return response, errors.New("network message too large")
	}
	req, e := http.NewRequestWithContext(ctx, "POST", p.URL+path, bytes.NewReader(raw))
	if e != nil {
		return response, e
	}
	req.Header.Set("Content-Type", "application/json")
	result, e := t.client.Do(req)
	if e != nil {
		return response, e
	}
	defer result.Body.Close()
	if result.StatusCode != 200 {
		body, _ := io.ReadAll(io.LimitReader(result.Body, 256))
		return response, fmt.Errorf("peer HTTP %d: %s", result.StatusCode, string(body))
	}
	if e = json.NewDecoder(io.LimitReader(result.Body, maxWire)).Decode(&response); e != nil {
		return response, e
	}
	if e = t.validate(response, m.Heartbeat || path == "/v3/network/update-lease"); e != nil {
		return response, e
	}
	if response.Role != "full" || result.TLS == nil || len(result.TLS.PeerCertificates) == 0 || result.TLS.PeerCertificates[0].Subject.CommonName != response.Node {
		return response, errors.New("peer is not an authenticated storage node")
	}
	for _, url := range response.Peers {
		t.discover(url)
	}
	t.updates.receive(response.Update)
	return response, nil
}
func (t *transport) send(ctx context.Context, items []pending) error {
	if !t.cfg.Cluster.Enabled {
		return errors.New("no storage peers configured")
	}
	peers := t.list()
	var last error = errors.New("no storage peer reachable")
	m := t.envelope()
	for _, p := range items {
		m.Samples = append(m.Samples, *p.sample)
	}
	for _, p := range peers {
		requestCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		reply, e := t.request(requestCtx, p, "/v4/network/ingest", m)
		cancel()
		p.Error = limitedError(e)
		t.presence.deliveryTo(p.URL, time.Now(), e)
		if e == nil {
			p.Node = reply.Node
			p.Name = reply.Name
			p.Success = time.Now().Unix()
			t.remember(p)
			return nil
		}
		t.remember(p)
		last = e
	}
	return last
}
func (t *transport) sync(ctx context.Context) {
	if t.store == nil || !t.cfg.Cluster.Enabled {
		return
	}
	peers := t.list()
	for _, p := range peers {
		if ctx.Err() != nil {
			return
		}
		for round := 0; round < 4; round++ {
			m := t.envelope()
			m.Page.Epoch = p.Epoch
			m.Page.Cursor = p.Cursor
			requestCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			reply, e := t.request(requestCtx, p, "/v4/network/exchange", m)
			cancel()
			if e == nil {
				if !observation.ValidID(reply.Epoch) || reply.Cursor < 0 || reply.Cursor > reply.Head || reply.Epoch == p.Epoch && reply.Cursor < p.Cursor {
					e = errors.New("invalid network cursor")
				}
			}
			if e == nil {
				writeCtx, stop := context.WithTimeout(ctx, 3*time.Second)
				p, e = t.applyPage(writeCtx, p, reply)
				stop()
			}
			if e != nil {
				t.presence.syncResult(p.URL, p, 0, e)
				p.Error = limitedError(e)
				t.remember(p)
				saveCtx, stop := context.WithTimeout(ctx, time.Second)
				t.store.SavePeer(saveCtx, p)
				stop()
				break
			}
			t.presence.syncResult(p.URL, p, reply.Head, nil)
			t.remember(p)
			if reply.Cursor >= reply.Head {
				break
			}
		}
	}
}

// Advance the in-memory peer only after the same cursor is durably committed
// with its observations. An error must leave both cursors replayable.
func (t *transport) applyPage(ctx context.Context, previous Peer, reply message) (Peer, error) {
	next := previous
	next.Node = reply.Node
	next.Name = reply.Name
	next.Epoch = reply.Epoch
	next.Cursor = reply.Cursor
	next.Success = time.Now().Unix()
	next.Error = ""
	if e := t.store.mergePage(ctx, reply.Samples, &next, reply.Floor, reply.Incidents); e != nil {
		return previous, e
	}
	return next, nil
}
func (t *transport) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" || (r.URL.Path != "/v3/network/ingest" && r.URL.Path != "/v4/network/ingest" && r.URL.Path != "/v4/network/exchange" && r.URL.Path != "/v3/network/update-lease") {
		http.NotFound(w, r)
		return
	}
	select {
	case t.slots <- struct{}{}:
		defer func() { <-t.slots }()
	default:
		http.Error(w, "network receiver busy", 503)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	var m message
	if e := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxWire)).Decode(&m); e != nil {
		http.Error(w, "invalid message", 400)
		return
	}
	control := r.URL.Path == "/v3/network/update-lease" || (r.URL.Path == "/v3/network/ingest" && m.Heartbeat)
	if r.URL.Path == "/v3/network/ingest" && !m.Heartbeat {
		http.Error(w, "telemetry requires network protocol v4; upgrade every node", 409)
		return
	}
	if e := t.validate(m, control); e != nil {
		http.Error(w, e.Error(), 409)
		return
	}
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || r.TLS.PeerCertificates[0].Subject.CommonName != m.Node {
		http.Error(w, "peer identity mismatch", 403)
		return
	}
	if m.Node == t.node && r.URL.Path != "/v3/network/update-lease" {
		http.Error(w, "duplicate node identity or self connection", 409)
		return
	}
	if m.Heartbeat && ((r.URL.Path != "/v3/network/ingest" && r.URL.Path != "/v4/network/ingest") || len(m.Samples)+len(m.Incidents) != 0) {
		http.Error(w, "heartbeat must be an empty ingest", 400)
		return
	}
	if r.URL.Path != "/v3/network/update-lease" {
		t.presence.recordIncoming(m, r.RemoteAddr, time.Now(), t.contactTTL())
	}
	t.updates.receive(m.Update)
	if m.Role == "full" {
		t.discover(m.Advertise)
	}
	reply := t.envelope()
	if control {
		reply.Version = m.Version
	}
	if r.URL.Path == "/v3/network/update-lease" {
		coordinator, _ := config.PeerURL(t.cfg.Updates.Coordinator)
		self, _ := config.PeerURL(t.cfg.Cluster.Advertise)
		if coordinator == "" || coordinator != self || m.UpdateLease == nil || len(m.Samples) != 0 {
			http.Error(w, "this node is not the configured update coordinator", 409)
			return
		}
		lease := t.updates.lease(m.Node, *m.UpdateLease, time.Now())
		reply.UpdateLease = &lease
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(reply)
		return
	}
	if m.Heartbeat {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(reply)
		return
	}
	if r.URL.Path == "/v4/network/ingest" {
		if len(m.Incidents) > 0 {
			http.Error(w, "incidents are exchanged by storage replicas", 400)
			return
		}
		for _, s := range m.Samples {
			if s.Node != m.Node {
				http.Error(w, "ingest source differs from certificate", 403)
				return
			}
		}
		if e := t.store.Merge(ctx, m.Samples, nil); e != nil {
			if len(m.Samples) > 0 {
				t.presence.delivery(m.Node, time.Now(), e)
			}
			http.Error(w, limitedError(e), 503)
			return
		}
		if len(m.Samples) > 0 {
			t.presence.delivery(m.Node, time.Now(), nil)
		}
	} else {
		page, e := t.store.Page(ctx, m.Page.Epoch, m.Page.Cursor)
		if e != nil {
			http.Error(w, limitedError(e), 503)
			return
		}
		reply.Page = page
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(reply)
}
func (t *transport) excludePorts() map[uint16]bool {
	ports := map[uint16]bool{}
	if !t.cfg.Cluster.Enabled {
		return ports
	}
	_, port, e := net.SplitHostPort(t.cfg.Cluster.Listen)
	if e == nil {
		n, _ := strconv.Atoi(port)
		if n > 0 {
			ports[uint16(n)] = true
		}
	}
	urls := []string{t.cfg.Cluster.Advertise}
	for _, p := range t.list() {
		urls = append(urls, p.URL)
	}
	for _, raw := range urls {
		url, e := config.PeerURL(raw)
		if e != nil {
			continue
		}
		at := len(url) - 1
		for at >= 0 && url[at] != ':' {
			at--
		}
		n, _ := strconv.Atoi(url[at+1:])
		if n > 0 {
			ports[uint16(n)] = true
		}
	}
	return ports
}
