package config

import (
	"errors"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const MaxClusterPeers = 32

type Cluster struct {
	Enabled      bool          `yaml:"enabled"`
	Listen       string        `yaml:"listen"`
	Advertise    string        `yaml:"advertise"`
	Peers        []string      `yaml:"peers"`
	KeyFile      string        `yaml:"key_file"`
	Name         string        `yaml:"name"`
	SyncInterval time.Duration `yaml:"sync_interval"`
}

func PeerURL(raw string) (string, error) {
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("cluster peer must be an HTTPS origin, e.g. https://192.0.2.1:9845")
	}
	_, port, e := net.SplitHostPort(u.Host)
	n, numberError := strconv.Atoi(port)
	if e != nil || numberError != nil || n < 1 || n > 65535 {
		return "", errors.New("cluster URL requires an explicit port")
	}
	return "https://" + strings.ToLower(u.Host), nil
}
func (c Cluster) Validate() error       { return c.validate(true) }
func (c Cluster) ValidateClient() error { return c.validate(false) }
func (c Cluster) validate(listener bool) error {
	if !c.Enabled {
		return nil
	}
	if listener {
		_, port, e := net.SplitHostPort(c.Listen)
		n, numberError := strconv.Atoi(port)
		if e != nil || numberError != nil || n < 1 || n > 65535 {
			return errors.New("cluster.listen must be host:port")
		}
		if _, e := PeerURL(c.Advertise); e != nil {
			return e
		}
	}
	if !filepath.IsAbs(c.KeyFile) {
		return errors.New("cluster.key_file must be an absolute path")
	}
	if len(c.Peers) > MaxClusterPeers {
		return errors.New("cluster supports at most 32 peers")
	}
	for _, peer := range c.Peers {
		if _, e := PeerURL(peer); e != nil {
			return e
		}
	}
	if len(c.Name) > 128 || strings.IndexFunc(c.Name, unicode.IsControl) >= 0 {
		return errors.New("cluster.name must be at most 128 bytes without controls")
	}
	if c.SyncInterval < time.Second || c.SyncInterval > time.Hour {
		return errors.New("cluster.sync_interval must be 1s..1h")
	}
	return nil
}
