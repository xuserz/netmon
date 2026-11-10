package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"netmon/internal/release"
)

func TestSignerUsesBuiltArchiveBytesAndPinnedPublicKey(t *testing.T) {
	dir := t.TempDir()
	public, key, _ := ed25519.GenerateKey(nil)
	pub := filepath.Join(dir, "key.pub")
	os.WriteFile(pub, []byte(hex.EncodeToString(public)), 0600)
	for _, arch := range []string{"amd64", "arm64"} {
		name, _ := release.AssetName(arch)
		os.WriteFile(filepath.Join(dir, name), []byte("test artifact "+arch), 0600)
	}
	policy := filepath.Join(dir, "policy.json")
	os.WriteFile(policy, []byte(`{"automatic":true,"compatibility":"network-v4-details-v2"}`), 0600)
	version := "build-20-1-aaaaaaaa"
	if e := sign(dir, version, pub, policy, hex.EncodeToString(key.Seed())); e != nil {
		t.Fatal(e)
	}
	offer, e := release.ReadOffer(filepath.Join(dir, "update.json"))
	if e != nil {
		t.Fatal(e)
	}
	m, e := release.Verify(offer, public)
	if e != nil || m.Version != version || !m.Automatic {
		t.Fatal(m, e)
	}
	other, _, _ := ed25519.GenerateKey(nil)
	os.WriteFile(pub, []byte(hex.EncodeToString(other)), 0600)
	if e := sign(dir, version, pub, policy, hex.EncodeToString(key.Seed())); e == nil {
		t.Fatal("mismatched secret accepted")
	}
}
