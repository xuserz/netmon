// Package release verifies publisher-signed update offers. Peer authentication
// is deliberately separate from permission to publish executable code.
package release

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
)

const Repository = "xuserz/netmon"
const Compatibility = "network-v4-details-v2"
const MaxManifest = 8192
const MaxArchive = 64 << 20
const domain = "netmon-release-v1\n"

type Asset struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}
type Manifest struct {
	Format        int              `json:"format"`
	Repository    string           `json:"repository"`
	Version       string           `json:"version"`
	Compatibility string           `json:"compatibility"`
	Automatic     bool             `json:"automatic"`
	Assets        map[string]Asset `json:"assets"`
}
type Offer struct {
	Manifest  []byte `json:"manifest"`
	Signature string `json:"signature"`
}
type Status struct {
	Blocked string `json:"blocked,omitempty"`
	Version string `json:"version"`
	Target  string `json:"target,omitempty"`
	State   string `json:"state,omitempty"`
	Error   string `json:"error,omitempty"`
	At      int64  `json:"at,omitempty"`
}

var tag = regexp.MustCompile(`^build-([1-9][0-9]{0,17})-([1-9][0-9]{0,17})-([0-9a-f]{8,40})$`)

func Build(s string) (run, attempt uint64, ok bool) {
	m := tag.FindStringSubmatch(s)
	if m == nil {
		return
	}
	run, e := strconv.ParseUint(m[1], 10, 64)
	if e != nil {
		return 0, 0, false
	}
	attempt, e = strconv.ParseUint(m[2], 10, 64)
	return run, attempt, e == nil
}
func Newer(a, b string) bool {
	ar, aa, ok := Build(a)
	br, ba, bok := Build(b)
	return ok && bok && (ar > br || ar == br && aa > ba)
}
func ValidVersion(s string) bool { _, _, ok := Build(s); return ok }
func Parse(raw []byte) (Manifest, error) {
	var m Manifest
	if len(raw) > MaxManifest {
		return m, errors.New("release manifest too large")
	}
	if e := json.Unmarshal(raw, &m); e != nil {
		return m, e
	}
	if m.Format != 1 || m.Repository != Repository || !ValidVersion(m.Version) || len(m.Assets) != 2 || m.Compatibility == "" || len(m.Compatibility) > 64 {
		return m, errors.New("invalid release metadata")
	}
	for _, name := range []string{"netmon_linux_amd64.tar.gz", "netmon_linux_arm64.tar.gz"} {
		a, ok := m.Assets[name]
		hash, e := hex.DecodeString(a.SHA256)
		if !ok || e != nil || len(hash) != sha256.Size || a.SHA256 != strings.ToLower(a.SHA256) || a.Size <= 0 || a.Size > MaxArchive {
			return m, errors.New("invalid release asset")
		}
	}
	return m, nil
}
func Verify(o Offer, key ed25519.PublicKey) (Manifest, error) {
	m, e := Parse(o.Manifest)
	if e != nil {
		return m, e
	}
	sig, e := hex.DecodeString(o.Signature)
	if e != nil || len(sig) != ed25519.SignatureSize || len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, append([]byte(domain), o.Manifest...), sig) {
		return m, errors.New("release signature verification failed")
	}
	return m, nil
}
func Sign(raw []byte, key ed25519.PrivateKey) (Offer, error) {
	if _, e := Parse(raw); e != nil {
		return Offer{}, e
	}
	if len(key) != ed25519.PrivateKeySize {
		return Offer{}, errors.New("invalid signing key")
	}
	return Offer{Manifest: raw, Signature: hex.EncodeToString(ed25519.Sign(key, append([]byte(domain), raw...)))}, nil
}
func PublicKey(path string) (ed25519.PublicKey, error) {
	raw, e := smallFile(path, 512)
	if e != nil {
		return nil, e
	}
	key, e := hex.DecodeString(strings.TrimSpace(string(raw)))
	if e != nil || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("update public key must be 32 hex-encoded bytes")
	}
	return key, nil
}
func ReadOffer(path string) (Offer, error) {
	raw, e := smallFile(path, MaxManifest)
	if e != nil {
		return Offer{}, e
	}
	if len(raw) > MaxManifest {
		return Offer{}, errors.New("release manifest too large")
	}
	sig, e := smallFile(path+".sig", 256)
	if e != nil {
		return Offer{}, e
	}
	if len(sig) > 256 {
		return Offer{}, errors.New("release signature too large")
	}
	return Offer{Manifest: raw, Signature: strings.TrimSpace(string(sig))}, nil
}

func smallFile(path string, limit int64) ([]byte, error) {
	s, e := os.Stat(path)
	if e != nil {
		return nil, e
	}
	if !s.Mode().IsRegular() || s.Size() > limit {
		return nil, errors.New("invalid or oversized release metadata file")
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	raw, e := io.ReadAll(io.LimitReader(f, limit+1))
	if len(raw) > int(limit) {
		return nil, errors.New("release metadata exceeds size limit")
	}
	return raw, e
}
func AssetName(arch string) (string, error) {
	if arch != "amd64" && arch != "arm64" {
		return "", fmt.Errorf("unsupported update architecture %s", arch)
	}
	return "netmon_linux_" + arch + ".tar.gz", nil
}
