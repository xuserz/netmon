package cluster

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"io"
	"math/big"
	"os"
	"strings"
	"time"
)

func ReadKey(path string) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	data, e := io.ReadAll(io.LimitReader(f, 257))
	if e != nil {
		return nil, e
	}
	if len(data) > 256 {
		return nil, errors.New("cluster key file is too large")
	}
	key, e := base64.RawStdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if e != nil || len(key) != 32 {
		return nil, errors.New("cluster key must be a base64-encoded 32-byte key from netmon cluster keygen")
	}
	return key, nil
}
func GenerateKey() string {
	var b [32]byte
	if _, e := rand.Read(b[:]); e != nil {
		panic(e)
	}
	return base64.RawStdEncoding.EncodeToString(b[:])
}

// A shared secret defines a private cluster CA. Certificates are verified using
// Go's normal chain/usage/name checks, including mutual TLS. The fixed private
// DNS name authenticates cluster membership, not a public DNS hostname.
// Cluster members are fully trusted and can issue certificates for this group.
func transportTLS(key []byte, node string) (server, client *tls.Config, err error) {
	mac := hmac.New(sha256.New, key)
	// These wire identities are stable across the dnsmon -> netmon rename.
	mac.Write([]byte("dnsmon cluster CA v1"))
	rootKey := ed25519.NewKeyFromSeed(mac.Sum(nil))
	from := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	until := time.Date(2120, 1, 1, 0, 0, 0, 0, time.UTC)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "dnsmon private cluster"}, NotBefore: from, NotAfter: until, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	rootDER, e := x509.CreateCertificate(rand.Reader, ca, ca, rootKey.Public(), rootKey)
	if e != nil {
		return nil, nil, e
	}
	root, e := x509.ParseCertificate(rootDER)
	if e != nil {
		return nil, nil, e
	}
	public, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		return nil, nil, e
	}
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		return nil, nil, e
	}
	leaf := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: node}, NotBefore: from, NotAfter: until, DNSNames: []string{"dnsmon.cluster"}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, BasicConstraintsValid: true}
	der, e := x509.CreateCertificate(rand.Reader, leaf, root, public, rootKey)
	if e != nil {
		return nil, nil, e
	}
	cert := tls.Certificate{Certificate: [][]byte{der, rootDER}, PrivateKey: private}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	server = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	client = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, RootCAs: roots, ServerName: "dnsmon.cluster"}
	return server, client, nil
}

// TransportTLS supplies the same authenticated private transport to network-mode nodes.
func TransportTLS(key []byte, node string) (*tls.Config, *tls.Config, error) {
	return transportTLS(key, node)
}
