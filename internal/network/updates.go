package network

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"netmon/internal/cluster"
	"netmon/internal/config"
	"netmon/internal/observation"
	"netmon/internal/release"
)

const UpdateLeaseTTL = 15 * time.Minute
const UpdateStatePath = "/var/lib/netmon-updater/state.json"
const InstalledOfferPath = "/usr/share/netmon/update.json"

type UpdateLease struct {
	Action  string `json:"action"`
	Token   string `json:"token"`
	Target  string `json:"target"`
	Granted bool   `json:"granted,omitempty"`
	Error   string `json:"error,omitempty"`
}
type updateControl struct {
	mu            sync.Mutex
	key           ed25519.PublicKey
	offer         *release.Offer
	version       string
	started       time.Time
	holder, token string
	until         time.Time
}

func newUpdateControl(c config.Config) *updateControl {
	u := &updateControl{started: time.Now()}
	u.key, _ = release.PublicKey(c.Updates.PublicKey)
	if c.Updates.Propagate {
		if o, e := release.ReadOffer(InstalledOfferPath); e == nil {
			if m, e := release.Verify(o, u.key); e == nil && m.Version == c.BuildVersion {
				u.offer = &o
				u.version = m.Version
			}
		}
	}
	return u
}
func (u *updateControl) receive(o *release.Offer) {
	if u == nil || o == nil || len(o.Manifest) > release.MaxManifest || len(o.Signature) != 128 {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	m, e := release.Verify(*o, u.key)
	if e != nil {
		return
	}
	if u.offer == nil || release.Newer(m.Version, u.version) {
		copy := *o
		copy.Manifest = append([]byte(nil), o.Manifest...)
		u.offer = &copy
		u.version = m.Version
	}
}
func (u *updateControl) snapshot() *release.Offer {
	if u == nil {
		return nil
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.offer == nil {
		return nil
	}
	o := *u.offer
	o.Manifest = append([]byte(nil), o.Manifest...)
	return &o
}
func (u *updateControl) lease(node string, req UpdateLease, now time.Time) UpdateLease {
	u.mu.Lock()
	defer u.mu.Unlock()
	reply := req
	reply.Granted = false
	reply.Error = ""
	if req.Action == "release" {
		if u.holder == node && u.token == req.Token {
			u.holder = ""
			u.token = ""
			u.until = time.Time{}
		}
		reply.Granted = true
		return reply
	}
	// A restart must not erase a still-valid grant. Refuse all new grants for
	// one full TTL after startup, including after the coordinator updates itself.
	if now.Before(u.started.Add(UpdateLeaseTTL)) {
		reply.Error = "coordinator startup cooldown"
		return reply
	}
	if now.Before(u.until) && (u.holder != node || u.token != req.Token) {
		reply.Error = "another node is updating"
		return reply
	}
	if u.holder == node && u.token == req.Token && now.Before(u.until) {
		reply.Granted = true
		return reply
	}
	u.holder = node
	u.token = req.Token
	u.until = now.Add(UpdateLeaseTTL)
	reply.Granted = true
	return reply
}
func ReadUpdateStatus() release.Status {
	var s release.Status
	info, e := os.Lstat(UpdateStatePath)
	if e != nil || !info.Mode().IsRegular() || info.Size() > 4096 {
		return s
	}
	f, e := os.Open(UpdateStatePath)
	if e != nil {
		return s
	}
	defer f.Close()
	if json.NewDecoder(io.LimitReader(f, 4096)).Decode(&s) != nil {
		return release.Status{}
	}
	s.Error = limitedText(s.Error)
	s.State = limitedText(s.State)
	if len(s.State) > 32 {
		s.State = s.State[:32]
	}
	if !release.ValidVersion(s.Version) {
		s.Version = ""
	}
	if !release.ValidVersion(s.Target) {
		s.Target = ""
	}
	if !release.ValidVersion(s.Blocked) {
		s.Blocked = ""
	}
	return s
}

func (t *transport) updateStatus() release.Status {
	s := ReadUpdateStatus()
	if s.Version == "" {
		s.Version = t.cfg.BuildVersion
	}
	if offer := t.updates.snapshot(); offer != nil {
		if m, e := release.Parse(offer.Manifest); e == nil && release.Newer(m.Version, t.cfg.BuildVersion) && (s.Target == "" || release.Newer(m.Version, s.Target)) {
			s.Target = m.Version
			s.Error = ""
			s.State = "available"
			if !t.cfg.Updates.Automatic {
				s.State = "opted-out"
			}
		}
	}
	return s
}

// AcquireUpdateLease uses the already-running monitor's authenticated identity.
// The fixed coordinator serializes installation; no peer supplies a command or URL.
func AcquireUpdateLease(ctx context.Context, c config.Config, node, target string) (func(), error) {
	if !observation.ValidID(node) || !release.ValidVersion(target) {
		return nil, errors.New("invalid update lease identity")
	}
	key, e := cluster.ReadKey(c.Cluster.KeyFile)
	if e != nil {
		return nil, e
	}
	_, clientTLS, e := cluster.TransportTLS(key, node)
	if e != nil {
		return nil, e
	}
	tr := &http.Transport{TLSClientConfig: clientTLS, MaxResponseHeaderBytes: 8192}
	deferOnError := true
	defer func() {
		if deferOnError {
			tr.CloseIdleConnections()
		}
	}()
	t := &transport{cfg: c, node: node, name: c.Cluster.Name, presence: newPresence(), peers: map[string]Peer{}, updates: newUpdateControl(c), client: &http.Client{Transport: tr, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	token := make([]byte, 16)
	if _, e = rand.Read(token); e != nil {
		return nil, e
	}
	req := UpdateLease{Action: "acquire", Token: hex.EncodeToString(token), Target: target}
	call := func(ctx context.Context, action string) error {
		req.Action = action
		m := t.envelope()
		m.Version = 3
		m.UpdateLease = &req
		reply, e := t.request(ctx, Peer{URL: c.Updates.Coordinator}, "/v3/network/update-lease", m)
		if e != nil {
			return e
		}
		if reply.UpdateLease == nil || !reply.UpdateLease.Granted || reply.UpdateLease.Token != req.Token {
			return errors.New("update lease refused: " + leaseError(reply.UpdateLease))
		}
		return nil
	}
	if e = call(ctx, "acquire"); e != nil {
		return nil, e
	}
	deferOnError = false
	return func() {
		defer tr.CloseIdleConnections()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = call(ctx, "release")
	}, nil
}
func leaseError(l *UpdateLease) string {
	if l == nil {
		return "coordinator does not support update leases"
	}
	return limitedText(l.Error)
}
