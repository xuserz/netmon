package updater

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"netmon/internal/config"
	"netmon/internal/live"
	"netmon/internal/release"
)

const oldBuild = "build-1-1-aaaaaaaa"
const newBuild = "build-2-1-bbbbbbbb"

func archive(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	for name, body := range entries {
		if e := tw.WriteHeader(&tar.Header{Name: name, Mode: 0755, Size: int64(len(body)), Typeflag: tar.TypeReg}); e != nil {
			t.Fatal(e)
		}
		if _, e := tw.Write([]byte(body)); e != nil {
			t.Fatal(e)
		}
	}
	if e := tw.Close(); e != nil {
		t.Fatal(e)
	}
	if e := gz.Close(); e != nil {
		t.Fatal(e)
	}
	return b.Bytes()
}
func setupRunner(t *testing.T) (*Runner, *live.Response, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	dir := t.TempDir()
	pub, key, _ := ed25519.GenerateKey(nil)
	c := config.Default()
	c.Mode = "network"
	c.Updates.Automatic = true
	c.Updates.PublicKey = filepath.Join(dir, "key")
	if e := os.WriteFile(c.Updates.PublicKey, []byte(hex.EncodeToString(pub)), 0600); e != nil {
		t.Fatal(e)
	}
	packed := archive(t, map[string]string{"bin/netmon": "#!/bin/sh\necho " + newBuild + "\n", "scripts/install.sh": "#!/bin/sh\n[ \"$NETMON_INSTALL_LOCK_HELD\" = 1 ] || exit 4\nprintf installed > \"$NETMON_TEST_UPDATE_MARKER\"\n"})
	sum := sha256.Sum256(packed)
	a := release.Asset{SHA256: hex.EncodeToString(sum[:]), Size: int64(len(packed))}
	m := release.Manifest{Format: 1, Repository: release.Repository, Version: newBuild, Compatibility: release.Compatibility, Automatic: true, Assets: map[string]release.Asset{"netmon_linux_amd64.tar.gz": a, "netmon_linux_arm64.tar.gz": a}}
	raw, _ := json.Marshal(m)
	offer, e := release.Sign(raw, key)
	if e != nil {
		t.Fatal(e)
	}
	response := &live.Response{SnapshotAt: time.Now(), Network: true, Source: "live", UpdateOffer: &offer, Health: live.Health{BuildVersion: oldBuild, PID: 123, ClusterNode: strings.Repeat("a", 32)}, NetworkNodes: []live.NetworkNode{{Role: "full", Online: true, SyncKnown: true, Cursor: 10, Head: 10}}}
	downloads := new(atomic.Int32)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		downloads.Add(1)
		if r.URL.Path != "/"+newBuild+"/netmon_linux_amd64.tar.gz" {
			t.Errorf("untrusted download path %s", r.URL.Path)
		}
		w.Write(packed)
	}))
	t.Cleanup(server.Close)
	runner := New(c, oldBuild)
	runner.stateDir = filepath.Join(dir, "state")
	runner.arch = "amd64"
	runner.base = server.URL + "/"
	runner.client = server.Client()
	runner.snapshot = func(context.Context) (live.Response, error) { return *response, nil }
	leases := new(atomic.Int32)
	runner.acquire = func(context.Context, string, string) (func(), error) { leases.Add(1); return func() {}, nil }
	return runner, response, downloads, leases
}
func TestSignedDownloadRealStagedInstallerAndState(t *testing.T) {
	r, _, downloads, leases := setupRunner(t)
	marker := filepath.Join(t.TempDir(), "marker")
	t.Setenv("NETMON_TEST_UPDATE_MARKER", marker)
	if e := r.Once(context.Background(), false); e != nil {
		t.Fatal(e)
	}
	got, e := os.ReadFile(marker)
	if e != nil || string(got) != "installed" {
		t.Fatal(string(got), e)
	}
	status := r.state()
	if status.State != "updated" || status.Version != newBuild || status.Blocked != "" || downloads.Load() != 1 || leases.Load() != 1 {
		t.Fatal(status, downloads.Load(), leases.Load())
	}
	entries, e := os.ReadDir(r.stateDir)
	if e != nil || len(entries) != 1 {
		t.Fatal(entries, e)
	}
}
func TestFailedInstallerBlocksTargetUntilExplicitRetry(t *testing.T) {
	r, _, downloads, _ := setupRunner(t)
	installs := 0
	r.install = func(context.Context, string, string) error {
		installs++
		return errors.New("startup failed; rolled back")
	}
	if e := r.Once(context.Background(), false); e == nil {
		t.Fatal("failure hidden")
	}
	if r.state().Blocked != newBuild || r.state().State != "failed" {
		t.Fatal(r.state())
	}
	if e := r.Once(context.Background(), false); e != nil {
		t.Fatal(e)
	}
	if installs != 1 || downloads.Load() != 1 || r.state().State != "blocked" {
		t.Fatal(installs, downloads.Load(), r.state())
	}
	r.install = func(context.Context, string, string) error { installs++; return nil }
	if e := r.Once(context.Background(), true); e != nil {
		t.Fatal(e)
	}
	if installs != 2 || r.state().Blocked != "" {
		t.Fatal(installs, r.state())
	}
}
func TestNoInstallationWithoutSignedNewCompatibleOfferHealthyReplicaAndLease(t *testing.T) {
	for _, kind := range []string{"disabled", "tampered", "stale", "self-as-replica", "older", "manual", "incompatible", "queue", "alone", "offline-replica", "sync-gap", "lease-unavailable", "bad-download"} {
		t.Run(kind, func(t *testing.T) {
			r, s, downloads, leases := setupRunner(t)
			installs := 0
			r.install = func(context.Context, string, string) error { installs++; return nil }
			switch kind {
			case "disabled":
				r.cfg.Updates.Automatic = false
			case "tampered":
				s.UpdateOffer.Signature = strings.Repeat("0", 128)
			case "older":
				r.version = "build-3-1-cccccccc"
				s.Health.BuildVersion = r.version
			case "manual", "incompatible":
				pub, key, _ := ed25519.GenerateKey(nil)
				os.WriteFile(r.cfg.Updates.PublicKey, []byte(hex.EncodeToString(pub)), 0600)
				m, _ := release.Parse(s.UpdateOffer.Manifest)
				if kind == "manual" {
					m.Automatic = false
				} else {
					m.Compatibility = "different-schema"
				}
				raw, _ := json.Marshal(m)
				o, _ := release.Sign(raw, key)
				s.UpdateOffer = &o
			case "stale":
				s.SnapshotAt = time.Now().Add(-time.Minute)
			case "self-as-replica":
				s.NetworkNodes[0].Node = s.Health.ClusterNode
			case "queue":
				s.Health.QueueBytes = 10
			case "alone":
				s.NetworkNodes = nil
			case "offline-replica":
				s.NetworkNodes[0].Online = false
			case "sync-gap":
				s.NetworkNodes[0].Cursor = 9
			case "lease-unavailable":
				r.acquire = func(context.Context, string, string) (func(), error) {
					return nil, errors.New("coordinator unavailable")
				}
			case "bad-download":
				r.base += "different/"
			}
			// The HTTP handler rejects unexpected URLs in the separate download test.
			if kind == "bad-download" {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("tampered")) }))
				defer server.Close()
				r.base = server.URL + "/"
				r.client = server.Client()
			}
			if e := r.Once(context.Background(), false); e != nil {
				t.Fatal(e)
			}
			if installs != 0 {
				t.Fatal("unsafe installation")
			}
			if kind != "lease-unavailable" && leases.Load() != 0 {
				t.Fatal("lease acquired before readiness/verification", leases.Load())
			}
			if kind != "lease-unavailable" && kind != "bad-download" && downloads.Load() != 0 {
				t.Fatal("unnecessary download", downloads.Load())
			}
		})
	}
}
func TestExtractionRejectsTraversalLinksAndDuplicatePaths(t *testing.T) {
	for _, kind := range []string{"../escape", "/absolute", "symlink", "duplicate"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			var b bytes.Buffer
			gz := gzip.NewWriter(&b)
			tw := tar.NewWriter(gz)
			h := &tar.Header{Name: kind, Typeflag: tar.TypeReg, Mode: 0600, Size: 1}
			if kind == "symlink" {
				h.Typeflag = tar.TypeSymlink
				h.Linkname = "/etc/passwd"
				h.Size = 0
			}
			tw.WriteHeader(h)
			if h.Size > 0 {
				tw.Write([]byte("x"))
			}
			if kind == "duplicate" {
				tw.WriteHeader(h)
				tw.Write([]byte("y"))
			}
			tw.Close()
			gz.Close()
			file := filepath.Join(dir, "archive.gz")
			os.WriteFile(file, b.Bytes(), 0600)
			if e := Extract(file, filepath.Join(dir, "bundle")); e == nil {
				t.Fatal("unsafe archive accepted")
			}
		})
	}
}
