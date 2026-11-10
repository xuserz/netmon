package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"netmon/internal/release"
)

func TestUpdateKeygenNeverOverwritesAndVerifyRejectsModifiedArchive(t *testing.T) {
	dir := t.TempDir()
	private, public := filepath.Join(dir, "private"), filepath.Join(dir, "public")
	var out, errs bytes.Buffer
	args := []string{"updates", "keygen", "--private", private, "--public", public}
	if e := run(args, &out, &errs); e != nil {
		t.Fatal(e)
	}
	seedText, e := os.ReadFile(private)
	if e != nil {
		t.Fatal(e)
	}
	seed, e := hex.DecodeString(strings.TrimSpace(string(seedText)))
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(out.String(), strings.TrimSpace(string(seedText))) {
		t.Fatal("private material logged")
	}
	info, e := os.Stat(private)
	if e != nil || info.Mode().Perm() != 0600 {
		t.Fatal(info, e)
	}
	if e := run(args, &out, &errs); e == nil {
		t.Fatal("key overwritten")
	}
	pub, e := release.PublicKey(public)
	if e != nil {
		t.Fatal(e)
	}
	key := ed25519.NewKeyFromSeed(seed)
	if !pub.Equal(key.Public()) {
		t.Fatal("key mismatch")
	}
	m := release.Manifest{Format: 1, Repository: release.Repository, Version: "build-2-1-aaaaaaaa", Compatibility: release.Compatibility, Automatic: true, Assets: map[string]release.Asset{"netmon_linux_amd64.tar.gz": {SHA256: strings.Repeat("a", 64), Size: 3}, "netmon_linux_arm64.tar.gz": {SHA256: strings.Repeat("b", 64), Size: 3}}}
	raw, _ := json.Marshal(m)
	offer, e := release.Sign(raw, key)
	if e != nil {
		t.Fatal(e)
	}
	manifest := filepath.Join(dir, "update.json")
	os.WriteFile(manifest, offer.Manifest, 0600)
	os.WriteFile(manifest+".sig", []byte(offer.Signature), 0600)
	verify := []string{"updates", "verify", "--manifest", manifest, "--key", public, "--version", m.Version}
	if e := run(verify, &out, &errs); e != nil {
		t.Fatal(e)
	}
	archive := filepath.Join(dir, "netmon_linux_amd64.tar.gz")
	os.WriteFile(archive, []byte("bad"), 0600)
	if e := run(append(verify, "--archive", archive), &out, &errs); e == nil {
		t.Fatal("modified archive verified")
	}
}
func TestUpdateHelpAndDisabledApplicationNeedNoStatistics(t *testing.T) {
	var out, errs bytes.Buffer
	if e := run([]string{"--config", "/missing/unused", "updates", "--help"}, &out, &errs); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(out.String(), "Usage: netmon updates") {
		t.Fatal(out.String())
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(path, []byte("mode: network\nupdates:\n  automatic: false\n"), 0600)
	if os.Geteuid() == 0 {
		if e := run([]string{"--config", path, "updates", "apply"}, &out, &errs); e != nil {
			t.Fatal(e)
		}
	}
}
