package config

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Interface         string        `yaml:"interface"`
	Destination       string        `yaml:"destination_ip"`
	Port              uint16        `yaml:"port"`
	Database          string        `yaml:"database"`
	FlushInterval     time.Duration `yaml:"flush_interval"`
	MaxPending        int           `yaml:"max_pending_ips"`
	MaxDatabaseMB     int64         `yaml:"max_database_mb"`
	MaxWALMB          int64         `yaml:"max_wal_mb"`
	SocketBufferMB    int           `yaml:"socket_buffer_mb"`
	MaxTCPFlows       int           `yaml:"max_tcp_flows"`
	MaxTCPBytes       int           `yaml:"max_tcp_bytes"`
	MaxFragments      int           `yaml:"max_fragment_sets"`
	MaxFragmentBytes  int           `yaml:"max_fragment_bytes"`
	ReassemblyTimeout time.Duration `yaml:"reassembly_timeout"`
}

func Default() Config {
	return Config{Interface: "eth0", Port: 53, Database: "/var/lib/dnsmon/stats.db", FlushInterval: 30 * time.Second,
		MaxPending: 10000, MaxDatabaseMB: 64, MaxWALMB: 16, SocketBufferMB: 2,
		MaxTCPFlows: 1024, MaxTCPBytes: 8 << 20, MaxFragments: 256, MaxFragmentBytes: 2 << 20, ReassemblyTimeout: 2 * time.Minute}
}

func Load(path string, required bool) (Config, error) {
	c := Default()
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) && !required {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	defer f.Close()
	d := yaml.NewDecoder(f)
	d.KnownFields(true)
	if err = d.Decode(&c); err != nil {
		return c, fmt.Errorf("config: %w", err)
	}
	var extra any
	if err = d.Decode(&extra); err != io.EOF {
		return c, fmt.Errorf("config: expected one YAML document")
	}
	return c, c.Validate()
}

func (c Config) Validate() error {
	if c.Interface == "" || c.Interface == "any" {
		return errors.New("interface must name one ingress interface; 'any' is forbidden (duplicate Docker observations)")
	}
	if c.Port == 0 {
		return errors.New("port must be 1..65535")
	}
	if c.Destination != "" {
		a, e := netip.ParseAddr(c.Destination)
		if e != nil || a.Zone() != "" {
			return errors.New("destination_ip must be a literal IPv4/IPv6 address without a zone")
		}
	}
	if !filepath.IsAbs(c.Database) {
		return errors.New("database must be an absolute path")
	}
	if c.FlushInterval < time.Second || c.FlushInterval > time.Hour {
		return errors.New("flush_interval must be between 1s and 1h")
	}
	if c.MaxPending < 1 || c.MaxPending > 1000000 || c.MaxDatabaseMB < 1 || c.MaxDatabaseMB > 1<<20 || c.MaxWALMB < 1 || c.MaxWALMB > 1024 {
		return errors.New("invalid pending/database/WAL limits")
	}
	if c.SocketBufferMB < 1 || c.SocketBufferMB > 64 || c.MaxTCPFlows < 1 || c.MaxTCPFlows > 100000 || c.MaxTCPBytes < 65537 || c.MaxTCPBytes > 1<<30 || c.MaxFragments < 1 || c.MaxFragments > 10000 || c.MaxFragmentBytes < 65535 || c.MaxFragmentBytes > 1<<30 {
		return errors.New("invalid capture/reassembly limits")
	}
	if c.ReassemblyTimeout < time.Second || c.ReassemblyTimeout > time.Hour {
		return errors.New("reassembly_timeout must be between 1s and 1h")
	}
	return nil
}
