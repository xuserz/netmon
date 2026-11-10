// release-sign is a maintainer/CI tool. It is never installed on a sensor.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"netmon/internal/release"
)

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, "release signing:", e)
		os.Exit(1)
	}
}
func run() error {
	dir := flag.String("dir", "dist", "release asset directory")
	version := flag.String("version", "", "CI tag")
	pub := flag.String("public-key", "packaging/update-public-key", "committed verification key")
	policy := flag.String("policy", "packaging/update-policy.json", "compatibility declaration")
	flag.Parse()
	return sign(*dir, *version, *pub, *policy, os.Getenv("NETMON_UPDATE_SIGNING_KEY"))
}
func sign(dir, version, pub, policy, seedText string) error {
	seed, e := hex.DecodeString(strings.TrimSpace(seedText))
	if e != nil || len(seed) != ed25519.SeedSize {
		return fmt.Errorf("NETMON_UPDATE_SIGNING_KEY must contain the private 32-byte hex seed")
	}
	key := ed25519.NewKeyFromSeed(seed)
	public, e := release.PublicKey(pub)
	if e != nil {
		return e
	}
	if !key.Public().(ed25519.PublicKey).Equal(public) {
		return fmt.Errorf("signing secret does not match committed public key")
	}
	raw, e := os.ReadFile(policy)
	if e != nil {
		return e
	}
	var p struct {
		Automatic     bool   `json:"automatic"`
		Compatibility string `json:"compatibility"`
	}
	if e = json.Unmarshal(raw, &p); e != nil {
		return e
	}
	m := release.Manifest{Format: 1, Repository: release.Repository, Version: version, Compatibility: p.Compatibility, Automatic: p.Automatic, Assets: map[string]release.Asset{}}
	for _, arch := range []string{"amd64", "arm64"} {
		name, _ := release.AssetName(arch)
		f, e := os.Open(filepath.Join(dir, name))
		if e != nil {
			return e
		}
		h := sha256.New()
		n, e := io.Copy(h, io.LimitReader(f, release.MaxArchive+1))
		f.Close()
		if e != nil {
			return e
		}
		m.Assets[name] = release.Asset{SHA256: hex.EncodeToString(h.Sum(nil)), Size: n}
	}
	raw, e = json.Marshal(m)
	if e != nil {
		return e
	}
	o, e := release.Sign(raw, key)
	if e != nil {
		return e
	}
	if e = os.WriteFile(filepath.Join(dir, "update.json"), o.Manifest, 0644); e != nil {
		return e
	}
	return os.WriteFile(filepath.Join(dir, "update.json.sig"), []byte(o.Signature+"\n"), 0644)
}
