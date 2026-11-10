// Package updater runs outside the unprivileged monitor. Only signed releases
// from the pinned repository can reach the privileged installer.
package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"netmon/internal/config"
	"netmon/internal/live"
	"netmon/internal/network"
	"netmon/internal/release"
)

type Runner struct {
	cfg                           config.Config
	version, arch, base, stateDir string
	client                        *http.Client
	snapshot                      func(context.Context) (live.Response, error)
	acquire                       func(context.Context, string, string) (func(), error)
	install                       func(context.Context, string, string) error
}

func New(c config.Config, version string) *Runner {
	r := &Runner{cfg: c, version: version, arch: runtime.GOARCH, base: "https://github.com/" + release.Repository + "/releases/download/", stateDir: filepath.Dir(network.UpdateStatePath), client: &http.Client{Timeout: 5 * time.Minute, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" || len(via) >= 10 {
			return errors.New("unsafe release redirect")
		}
		return nil
	}}}
	r.snapshot = func(ctx context.Context) (live.Response, error) {
		return live.Fetch(ctx, network.RuntimeBase(c), live.Request{Op: "health"})
	}
	r.acquire = func(ctx context.Context, node, target string) (func(), error) {
		return network.AcquireUpdateLease(ctx, c, node, target)
	}
	r.install = install
	return r
}
func RootFile(path string) error {
	s, e := os.Lstat(path)
	if e != nil {
		return e
	}
	st, ok := s.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || !s.Mode().IsRegular() || s.Mode().Perm()&0022 != 0 {
		return fmt.Errorf("%s must be a root-owned regular file, not writable by group/others", path)
	}
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		d, e := os.Lstat(parent)
		if e != nil {
			return e
		}
		ds, ok := d.Sys().(*syscall.Stat_t)
		if !ok || ds.Uid != 0 || !d.IsDir() || d.Mode().Perm()&0022 != 0 {
			return fmt.Errorf("untrusted update directory %s", parent)
		}
		if parent == "/" {
			break
		}
	}
	return nil
}
func (r *Runner) fetch(ctx context.Context, url, path string, a release.Asset) error {
	req, e := http.NewRequestWithContext(ctx, "GET", url, nil)
	if e != nil {
		return e
	}
	response, e := r.client.Do(req)
	if e != nil {
		return e
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("download HTTP %d", response.StatusCode)
	}
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	hash := sha256.New()
	n, e := io.Copy(io.MultiWriter(f, hash), io.LimitReader(response.Body, a.Size+1))
	if e != nil {
		return e
	}
	if n != a.Size || hex.EncodeToString(hash.Sum(nil)) != a.SHA256 {
		return errors.New("signed release archive size/SHA-256 mismatch")
	}
	return f.Sync()
}
func readyIdentity(version string, s live.Response) error {
	if s.SnapshotAt.IsZero() || time.Since(s.SnapshotAt) > 30*time.Second || time.Until(s.SnapshotAt) > 5*time.Second {
		return errors.New("waiting for a fresh monitor snapshot")
	}
	if !s.Network || s.Source != "live" || s.Health.BuildVersion != version || s.Health.PID < 1 {
		return errors.New("running monitor version/identity is unavailable or differs from installed binary")
	}
	if !release.ValidVersion(version) {
		return errors.New("only CI build versions support automatic updates")
	}
	return nil
}
func Ready(c config.Config, version string, s live.Response) error {
	if e := readyIdentity(version, s); e != nil {
		return e
	}
	if s.Health.QueueBytes != 0 || s.Health.PendingIPs != 0 || s.Health.FlushError != "" || s.Health.ClusterCatchingUp {
		return errors.New("waiting for a drained queue and healthy synchronized storage")
	}
	healthy := false
	for _, n := range s.NetworkNodes {
		if n.Node != s.Health.ClusterNode && n.Role == "full" && n.Online && n.Error == "" && n.SyncError == "" && (c.Storage.Mode == "forward" || n.SyncKnown && n.Cursor >= n.Head) {
			healthy = true
		}
	}
	if !healthy {
		return errors.New("waiting for another online, synchronized full node; a single storage node requires manual update")
	}
	return nil
}
func (r *Runner) state() release.Status {
	var s release.Status
	raw, e := os.ReadFile(filepath.Join(r.stateDir, "state.json"))
	if e == nil && len(raw) < 4096 {
		_ = json.Unmarshal(raw, &s)
	}
	return s
}
func (r *Runner) save(s release.Status) error {
	if e := os.MkdirAll(r.stateDir, 0755); e != nil {
		return e
	}
	// The production state directory is created and owned by systemd/root.
	s.At = time.Now().Unix()
	if s.Version == "" {
		s.Version = r.version
	}
	s.Error = strings.Map(func(ch rune) rune {
		if ch < 32 || ch == 127 {
			return ' '
		}
		return ch
	}, s.Error)
	if len(s.Error) > 256 {
		s.Error = s.Error[:256]
	}
	raw, e := json.Marshal(s)
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(r.stateDir, ".state-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if e = f.Chmod(0644); e != nil {
		return e
	}
	if _, e = f.Write(raw); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = os.Rename(f.Name(), filepath.Join(r.stateDir, "state.json")); e != nil {
		return e
	}
	dir, e := os.Open(r.stateDir)
	if e != nil {
		return e
	}
	defer dir.Close()
	return dir.Sync()
}

// Once is a single timer tick. Transient readiness/network failures wait for the
// next tick. An installer failure blocks that target until explicit retry.
func (r *Runner) Once(ctx context.Context, retry bool) error {
	if !r.cfg.Updates.Automatic {
		return nil
	}
	if e := os.MkdirAll(r.stateDir, 0755); e != nil {
		return e
	}
	previous := r.state()
	status := release.Status{Blocked: previous.Blocked}
	wait := func(e error) error { status.State = "waiting"; status.Error = e.Error(); return r.save(status) }
	current, e := r.snapshot(ctx)
	if e != nil {
		return wait(e)
	}
	if e = readyIdentity(r.version, current); e != nil {
		return wait(e)
	}
	if current.UpdateOffer == nil {
		status.State = "idle"
		return r.save(status)
	}
	key, e := release.PublicKey(r.cfg.Updates.PublicKey)
	if e != nil {
		return wait(e)
	}
	m, e := release.Verify(*current.UpdateOffer, key)
	if e != nil {
		return wait(e)
	}
	if !release.Newer(m.Version, r.version) {
		status.State = "current"
		return r.save(status)
	}
	status.Target = m.Version
	if !m.Automatic || m.Compatibility != release.Compatibility {
		return wait(errors.New("publisher requires a manual update for this release"))
	}
	if previous.Blocked == m.Version && !retry {
		status.State = "blocked"
		status.Error = "previous installation failed; use netmon updates apply --retry"
		return r.save(status)
	}
	status.Blocked = ""
	if e = Ready(r.cfg, r.version, current); e != nil {
		return wait(e)
	}
	name, e := release.AssetName(r.arch)
	if e != nil {
		return wait(e)
	}
	work, e := os.MkdirTemp(r.stateDir, ".download-*")
	if e != nil {
		return wait(e)
	}
	defer os.RemoveAll(work)
	status.State = "downloading"
	if e = r.save(status); e != nil {
		return e
	}
	archive := filepath.Join(work, "release.tar.gz")
	if e = r.fetch(ctx, r.base+m.Version+"/"+name, archive, m.Assets[name]); e != nil {
		return wait(e)
	}
	bundle := filepath.Join(work, "bundle")
	if e = Extract(archive, bundle); e != nil {
		return wait(e)
	}
	if e = os.WriteFile(filepath.Join(bundle, "update.json"), current.UpdateOffer.Manifest, 0644); e != nil {
		return wait(e)
	}
	if e = os.WriteFile(filepath.Join(bundle, "update.json.sig"), []byte(current.UpdateOffer.Signature+"\n"), 0644); e != nil {
		return wait(e)
	}
	// Recheck after download, before taking a short installation lease.
	latest, e := r.snapshot(ctx)
	if e != nil {
		return wait(e)
	}
	if e = Ready(r.cfg, r.version, latest); e != nil {
		return wait(e)
	}
	unlock, e := r.acquire(ctx, latest.Health.ClusterNode, m.Version)
	if e != nil {
		return wait(e)
	}
	defer unlock()
	status.State = "installing"
	status.Blocked = m.Version
	if e = r.save(status); e != nil {
		return e
	}
	installCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if e = r.install(installCtx, bundle, m.Version); e != nil {
		status.State = "failed"
		status.Blocked = m.Version
		status.Error = e.Error()
		if se := r.save(status); se != nil {
			return errors.Join(e, se)
		}
		return e
	}
	status.State = "updated"
	status.Version = m.Version
	status.Blocked = ""
	status.Error = ""
	// save records the helper build separately from the actual installed target.
	return r.save(status)
}
func install(ctx context.Context, bundle, target string) error {
	binary := filepath.Join(bundle, "bin/netmon")
	check := exec.CommandContext(ctx, binary, "version")
	raw, e := check.Output()
	if e != nil {
		return e
	}
	if strings.TrimSpace(string(raw)) != target {
		return errors.New("signed archive contains a different binary version")
	}
	cmd := exec.CommandContext(ctx, "/bin/sh", filepath.Join(bundle, "scripts/install.sh"), binary)
	cmd.Dir = bundle
	cmd.Env = append(os.Environ(), "NETMON_AUTOMATIC_UPDATE=1", "NETMON_INSTALL_LOCK_HELD=1")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM) }
	cmd.WaitDelay = 30 * time.Second
	e = cmd.Run()
	if ctx.Err() != nil && cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	return e
}
