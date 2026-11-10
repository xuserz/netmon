package release

import (
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
)

func testManifest() Manifest {
	return Manifest{Format: 1, Repository: Repository, Version: "build-20-1-aaaaaaaa", Compatibility: Compatibility, Automatic: true, Assets: map[string]Asset{"netmon_linux_amd64.tar.gz": {SHA256: strings.Repeat("a", 64), Size: 100}, "netmon_linux_arm64.tar.gz": {SHA256: strings.Repeat("b", 64), Size: 200}}}
}
func TestSignedOfferSurvivesJSONAndRejectsTamperingAndOtherPublisher(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(nil)
	m := testManifest()
	raw, _ := json.MarshalIndent(m, "", "  ")
	o, e := Sign(raw, key)
	if e != nil {
		t.Fatal(e)
	}
	wire, e := json.Marshal(o)
	if e != nil {
		t.Fatal(e)
	}
	var decoded Offer
	if e = json.Unmarshal(wire, &decoded); e != nil {
		t.Fatal(e)
	}
	if got, e := Verify(decoded, pub); e != nil || got.Version != m.Version {
		t.Fatal(got, e)
	}
	other, _, _ := ed25519.GenerateKey(nil)
	if _, e = Verify(o, other); e == nil {
		t.Fatal("another publisher accepted")
	}
	m.Automatic = false
	decoded.Manifest, _ = json.Marshal(m)
	if _, e = Verify(decoded, pub); e == nil {
		t.Fatal("manifest tampering accepted")
	}
	for _, bad := range []func(*Manifest){func(m *Manifest) { m.Repository = "attacker/netmon" }, func(m *Manifest) { m.Version = "../../bad" }, func(m *Manifest) {
		m.Assets["netmon_linux_amd64.tar.gz"] = Asset{SHA256: strings.Repeat("a", 64), Size: MaxArchive + 1}
	}, func(m *Manifest) { delete(m.Assets, "netmon_linux_arm64.tar.gz") }} {
		m := testManifest()
		bad(&m)
		raw, _ := json.Marshal(m)
		if _, e := Sign(raw, key); e == nil {
			t.Fatal("signed invalid metadata")
		}
	}
}
func TestBuildOrderingNeverDowngradesOrInterpretsArbitraryTags(t *testing.T) {
	for _, pair := range [][2]string{{"build-10-1-aaaaaaaa", "build-9-9-bbbbbbbb"}, {"build-10-2-aaaaaaaa", "build-10-1-aaaaaaaa"}} {
		if !Newer(pair[0], pair[1]) || Newer(pair[1], pair[0]) {
			t.Fatal(pair)
		}
	}
	for _, pair := range [][2]string{{"dev", "build-1-1-aaaaaaaa"}, {"build-1-1-aaaaaaaa", "dev"}, {"build-1-1-aaaaaaaa", "build-1-1-bbbbbbbb"}, {"build-01-1-aaaaaaaa", "build-1-1-bbbbbbbb"}} {
		if Newer(pair[0], pair[1]) {
			t.Fatal(pair)
		}
	}
}
