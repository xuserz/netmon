package cluster

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"netmon/internal/config"
	"netmon/internal/store"
)

type Status struct {
	Node          string
	Peers, Online int
	LastSync      time.Time
	Error         string
	CatchingUp    bool
}
type View struct {
	Clients []store.Client
	Totals  store.Totals
	At      time.Time
}
type exchangeRequest struct {
	Version                               int `json:"version"`
	Node, Session, Advertise, Name, Epoch string
	After                                 int64
}
type exchangeResponse struct {
	Head                       int64
	Version                    int `json:"version"`
	Node, Session, Name, Epoch string
	Peers                      []string
	Cursor                     int64
	Components                 []Component
}
type Manager struct {
	cfg           config.Cluster
	state         *state
	source        *store.Store
	node, session string
	advertise     string
	server        *http.Server
	transport     *http.Transport
	client        *http.Client
	cancel        context.CancelFunc
	wg            sync.WaitGroup
	done          sync.Once
	view          atomic.Pointer[View]
	status        atomic.Pointer[Status]
	localBehind   atomic.Bool
	sourceRewound atomic.Bool
	errMu         sync.Mutex
	lastError     string
}

func New(parent context.Context, c config.Config, source *store.Store) (*Manager, error) {
	if e := c.Cluster.Validate(); e != nil {
		return nil, e
	}
	key, e := ReadKey(c.Cluster.KeyFile)
	if e != nil {
		return nil, e
	}
	node, e := source.EnableReplication()
	if e != nil {
		return nil, e
	}
	if !validID(node) {
		return nil, errors.New("invalid persistent cluster node identity")
	}
	s, e := openState(Path(c.Database), node, c.MaxDatabaseMB, c.MaxWALMB)
	if e != nil {
		return nil, e
	}
	ok := false
	defer func() {
		if !ok {
			s.close()
		}
	}()
	reader, e := store.Open(c.Database, false, 0, 0)
	if e != nil {
		return nil, e
	}
	defer func() {
		if !ok {
			reader.Close()
		}
	}()
	serverTLS, clientTLS, e := transportTLS(key, node)
	if e != nil {
		return nil, e
	}
	listener, e := net.Listen("tcp", c.Cluster.Listen)
	if e != nil {
		return nil, e
	}
	cfg := c.Cluster
	if cfg.Name == "" {
		cfg.Name, _ = os.Hostname()
	}
	advertise, _ := config.PeerURL(cfg.Advertise)
	ctx, cancel := context.WithCancel(parent)
	m := &Manager{cfg: cfg, state: s, source: reader, node: node, session: store.RandomID(), advertise: advertise, cancel: cancel}
	m.transport = &http.Transport{TLSClientConfig: clientTLS, MaxResponseHeaderBytes: 8192, MaxIdleConns: 4, MaxIdleConnsPerHost: 1, MaxConnsPerHost: 1, IdleConnTimeout: 2 * time.Second, ResponseHeaderTimeout: 3 * time.Second}
	m.client = &http.Client{Transport: m.transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	m.status.Store(&Status{Node: node, CatchingUp: true})
	m.view.Store(&View{Totals: s.totals, At: time.Now()})
	m.server = &http.Server{Handler: http.HandlerFunc(m.handle), ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 2 * time.Second, MaxHeaderBytes: 4096, TLSConfig: serverTLS, ErrorLog: log.New(io.Discard, "", 0)}
	for _, raw := range cfg.Peers {
		m.discover(ctx, raw)
	}
	ok = true
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		if e := m.server.Serve(tls.NewListener(newLimitedListener(listener, 16), serverTLS)); e != nil && !errors.Is(e, http.ErrServerClosed) {
			m.setError(e)
		}
	}()
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			m.importLocal(ctx)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		ticker := time.NewTicker(cfg.SyncInterval)
		defer ticker.Stop()
		for {
			m.syncPeers(ctx)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			m.publish(ctx)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return m, nil
}
func (m *Manager) Close() {
	m.done.Do(func() {
		m.cancel()
		m.server.Close()
		m.transport.CloseIdleConnections()
		m.wg.Wait()
		m.importLocal(context.Background())
		m.source.Close()
		m.state.close()
	})
}
func (m *Manager) View() View     { v := *m.view.Load(); return v }
func (m *Manager) Status() Status { return *m.status.Load() }
func (m *Manager) setError(e error) {
	m.errMu.Lock()
	defer m.errMu.Unlock()
	if e == nil {
		m.lastError = ""
	} else {
		m.lastError = e.Error()
	}
}
func (m *Manager) discover(ctx context.Context, raw string) {
	url, e := config.PeerURL(raw)
	if e != nil || url == m.advertise {
		return
	}
	if e = m.state.addPeer(ctx, url); e != nil {
		m.setError(e)
	}
}
func (m *Manager) importLocal(parent context.Context) {
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	if m.sourceRewound.Load() {
		m.setError(ErrSourceRewind)
		return
	}
	cursor, e := m.state.sourceCursor(ctx)
	if e != nil {
		m.setError(e)
		return
	}
	var sourceSequence int64
	if e = m.source.DB.QueryRowContext(ctx, "SELECT sequence FROM replica_source WHERE id=1").Scan(&sourceSequence); e != nil {
		m.setError(e)
		return
	}
	if sourceSequence < cursor.Sequence {
		m.sourceRewound.Store(true)
		m.setError(ErrSourceRewind)
		return
	}
	for round := 0; round < 16; round++ {
		page, e := m.source.SourceChanges(ctx, cursor, pageSize)
		if e != nil {
			m.setError(e)
			return
		}
		m.localBehind.Store(len(page.Clients) == pageSize)
		if len(page.Clients) == 0 {
			return
		}
		items := make([]Component, len(page.Clients))
		for i, c := range page.Clients {
			items[i] = Component{Origin: m.node, Name: m.cfg.Name, Client: c}
		}
		if e = m.state.merge(ctx, items, &page.Cursor, nil); e != nil {
			if errors.Is(e, ErrSourceRewind) {
				m.sourceRewound.Store(true)
			}
			m.setError(e)
			return
		}
		m.setError(nil)
		cursor = page.Cursor
		if len(page.Clients) < pageSize {
			return
		}
	}
}
func (m *Manager) syncPeers(ctx context.Context) {
	peers, e := m.state.peers(ctx)
	if e != nil {
		m.setError(e)
		return
	}
	jobs := make(chan Peer)
	var wg sync.WaitGroup
	for i := 0; i < min(4, len(peers)); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				if e := m.pull(ctx, p); e != nil && ctx.Err() == nil {
					m.state.peerError(ctx, p.URL, e)
				}
			}
		}()
	}
	for _, p := range peers {
		select {
		case jobs <- p:
		case <-ctx.Done():
			close(jobs)
			wg.Wait()
			return
		}
	}
	close(jobs)
	wg.Wait()
}
func (m *Manager) pull(parent context.Context, peer Peer) error {
	for round := 0; round < 4; round++ {
		if parent.Err() != nil {
			return parent.Err()
		}
		request := exchangeRequest{Version: 1, Node: m.node, Session: m.session, Advertise: m.advertise, Name: m.cfg.Name, Epoch: peer.Epoch, After: peer.Cursor}
		body, _ := json.Marshal(request)
		ctx, cancel := context.WithTimeout(parent, 5*time.Second)
		req, e := http.NewRequestWithContext(ctx, "POST", peer.URL+"/v1/sync", bytes.NewReader(body))
		if e != nil {
			cancel()
			return e
		}
		req.Header.Set("Content-Type", "application/json")
		response, e := m.client.Do(req)
		if e != nil {
			cancel()
			return e
		}
		var page exchangeResponse
		if response.StatusCode != http.StatusOK {
			response.Body.Close()
			cancel()
			if response.StatusCode == http.StatusConflict {
				return errors.New("duplicate node identity: do not clone netmon databases")
			}
			return fmt.Errorf("peer returned HTTP %d", response.StatusCode)
		}
		e = json.NewDecoder(io.LimitReader(response.Body, 512<<10)).Decode(&page)
		response.Body.Close()
		cancel()
		if e != nil {
			return e
		}
		if page.Version != 1 || !validID(page.Node) || !validID(page.Epoch) || page.Cursor < 0 || page.Head < page.Cursor || len(page.Components) > pageSize || len(page.Peers) > config.MaxClusterPeers || len(page.Name) > 128 {
			return errors.New("invalid cluster response")
		}
		if response.TLS == nil || len(response.TLS.PeerCertificates) == 0 || response.TLS.PeerCertificates[0].Subject.CommonName != page.Node {
			return errors.New("peer identity differs from TLS certificate")
		}
		if page.Node == m.node {
			if page.Session != m.session {
				return errors.New("duplicate node identity: do not clone netmon databases")
			}
			return nil
		}
		if page.Epoch == peer.Epoch && page.Cursor < peer.Cursor {
			return errors.New("peer cursor moved backwards; restore requires a new replica epoch")
		}
		peer.Node, peer.Name, peer.Epoch, peer.Cursor = page.Node, page.Name, page.Epoch, page.Cursor
		peer.Head = page.Head
		mergeCtx, stop := context.WithTimeout(parent, 3*time.Second)
		e = m.state.merge(mergeCtx, page.Components, nil, &peer)
		stop()
		if e != nil {
			return e
		}
		for _, url := range page.Peers {
			m.discover(parent, url)
		}
		if len(page.Components) < pageSize {
			return nil
		}
	}
	return nil
}
func (m *Manager) handle(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/v1/sync" || r.Method != "POST" {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	var request exchangeRequest
	if e := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&request); e != nil {
		http.Error(w, "invalid request", 400)
		return
	}
	if request.Version != 1 || !validID(request.Node) || len(request.Name) > 128 || !validID(request.Session) || request.After < 0 {
		http.Error(w, "invalid peer", 400)
		return
	}
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || r.TLS.PeerCertificates[0].Subject.CommonName != request.Node {
		http.Error(w, "identity mismatch", 403)
		return
	}
	if request.Node == m.node && request.Session != m.session {
		http.Error(w, "duplicate node identity", 409)
		return
	}
	if request.Node != m.node {
		m.discover(ctx, request.Advertise)
	}
	after := request.After
	if request.Epoch != m.state.epoch {
		after = 0
	}
	items, cursor, e := m.state.changes(ctx, after)
	if e != nil {
		http.Error(w, "cannot read changes", 503)
		return
	}
	peers, e := m.state.peers(ctx)
	if e != nil {
		http.Error(w, "cannot read membership", 503)
		return
	}
	urls := []string{m.advertise}
	for _, p := range peers {
		if len(urls) < config.MaxClusterPeers {
			urls = append(urls, p.URL)
		}
	}
	var head int64
	if e = m.state.r.DB.QueryRowContext(ctx, "SELECT sequence FROM cluster_meta WHERE id=1").Scan(&head); e != nil {
		http.Error(w, "cannot read head", 503)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(exchangeResponse{Version: 1, Node: m.node, Session: m.session, Name: m.cfg.Name, Epoch: m.state.epoch, Peers: urls, Cursor: cursor, Head: head, Components: items})
}
func (m *Manager) publish(parent context.Context) {
	ctx, cancel := context.WithTimeout(parent, 500*time.Millisecond)
	defer cancel()
	rows, totals, e := m.state.view(ctx)
	if e == nil {
		m.view.Store(&View{Clients: rows, Totals: totals, At: time.Now()})
	}
	peers, e := m.state.peers(ctx)
	if e != nil {
		return
	}
	status := &Status{Node: m.node, Peers: len(peers), CatchingUp: m.localBehind.Load()}
	for _, p := range peers {
		if p.Cursor < p.Head {
			status.CatchingUp = true
		}
		if p.Error == "" && !p.Success.IsZero() && time.Since(p.Success) < 3*m.cfg.SyncInterval {
			status.Online++
		}
		if p.Success.After(status.LastSync) {
			status.LastSync = p.Success
		}
	}
	m.errMu.Lock()
	status.Error = m.lastError
	m.errMu.Unlock()
	m.status.Store(status)
}

type limitedListener struct {
	net.Listener
	slots chan struct{}
}
type limitedConn struct {
	net.Conn
	slots chan struct{}
	once  sync.Once
}

func newLimitedListener(l net.Listener, n int) *limitedListener {
	return &limitedListener{l, make(chan struct{}, n)}
}
func (l *limitedListener) Accept() (net.Conn, error) {
	for {
		c, e := l.Listener.Accept()
		if e != nil {
			return nil, e
		}
		select {
		case l.slots <- struct{}{}:
			return &limitedConn{Conn: c, slots: l.slots}, nil
		default:
			c.Close()
		}
	}
}
func (c *limitedConn) Close() error { e := c.Conn.Close(); c.once.Do(func() { <-c.slots }); return e }

func ListPeers(ctx context.Context, local string) ([]Peer, error) {
	db, e := store.Open(Path(local), false, 0, 0)
	if e != nil {
		return nil, e
	}
	defer db.Close()
	return (&state{r: db}).peers(ctx)
}

func LimitListener(listener net.Listener, limit int) net.Listener {
	return newLimitedListener(listener, limit)
}
