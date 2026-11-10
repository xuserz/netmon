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
)

const wireVersion = 3
const maxWire = 2 << 20

type message struct {
	Version       int                `json:"version"`
	Mode          string             `json:"mode"`
	PolicyVersion string             `json:"policy_version"`
	Policy        observation.Policy `json:"policy"`
	Retention     int64              `json:"retention"`
	Node          string             `json:"node"`
	Name          string             `json:"name"`
	Role          string             `json:"role"`
	Advertise     string             `json:"advertise"`
	Peers         []string           `json:"peers,omitempty"`
	Page
}
type transport struct {
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
	t := &transport{cfg: c, node: node, name: name, store: d, peers: map[string]Peer{}, slots: make(chan struct{}, 4)}
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
	m := message{Version: wireVersion, Mode: "network", PolicyVersion: observation.PolicyVersion, Policy: Policy(t.cfg), Retention: int64(t.cfg.Storage.Retention / time.Second), Node: t.node, Name: t.name, Role: t.cfg.Storage.Mode}
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
func (t *transport) validate(m message) error {
	if m.Version != wireVersion || m.Mode != "network" || m.PolicyVersion != observation.PolicyVersion || m.Policy != Policy(t.cfg) || m.Retention != int64(t.cfg.Storage.Retention/time.Second) {
		return errors.New("network mode, rating policy, or retention differs between nodes")
	}
	if m.Floor < 0 || m.Floor%60 != 0 || m.Floor > time.Now().Unix()+300 {
		return errors.New("invalid storage floor")
	}
	if !observation.ValidID(m.Node) || len(m.Name) > 128 || observation.InvalidName(m.Name) || (m.Role != "full" && m.Role != "forward") || len(m.Peers) > config.MaxClusterPeers || len(m.Samples) > 128 {
		return errors.New("invalid network peer message")
	}
	return nil
}
func (t *transport) request(ctx context.Context, p Peer, path string, m message) (message, error) {
	var response message
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
	if e = t.validate(response); e != nil {
		return response, e
	}
	if response.Role != "full" || result.TLS == nil || len(result.TLS.PeerCertificates) == 0 || result.TLS.PeerCertificates[0].Subject.CommonName != response.Node {
		return response, errors.New("peer is not an authenticated storage node")
	}
	for _, url := range response.Peers {
		t.discover(url)
	}
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
		m.Samples = append(m.Samples, p.sample)
	}
	for _, p := range peers {
		requestCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		reply, e := t.request(requestCtx, p, "/v3/network/ingest", m)
		cancel()
		p.Error = limitedError(e)
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
			reply, e := t.request(requestCtx, p, "/v3/network/exchange", m)
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
				p.Error = limitedError(e)
				t.remember(p)
				saveCtx, stop := context.WithTimeout(ctx, time.Second)
				t.store.SavePeer(saveCtx, p)
				stop()
				break
			}
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
	if e := t.store.mergePage(ctx, reply.Samples, &next, reply.Floor); e != nil {
		return previous, e
	}
	return next, nil
}
func (t *transport) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" || (r.URL.Path != "/v3/network/ingest" && r.URL.Path != "/v3/network/exchange") {
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
	if e := t.validate(m); e != nil {
		http.Error(w, e.Error(), 409)
		return
	}
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || r.TLS.PeerCertificates[0].Subject.CommonName != m.Node {
		http.Error(w, "peer identity mismatch", 403)
		return
	}
	if m.Node == t.node {
		http.Error(w, "duplicate node identity or self connection", 409)
		return
	}
	if m.Role == "full" {
		t.discover(m.Advertise)
	}
	reply := t.envelope()
	if r.URL.Path == "/v3/network/ingest" {
		for _, s := range m.Samples {
			if s.Node != m.Node {
				http.Error(w, "ingest source differs from certificate", 403)
				return
			}
		}
		if e := t.store.Merge(ctx, m.Samples, nil); e != nil {
			http.Error(w, limitedError(e), 503)
			return
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
