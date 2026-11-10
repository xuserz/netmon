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
	Mode              string        `yaml:"mode"`
	Storage           Storage       `yaml:"storage"`
	Network           Network       `yaml:"network"`
	Cluster           Cluster       `yaml:"cluster"`
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
	TCPIdleTimeout    time.Duration `yaml:"tcp_idle_timeout"`
	MaxActivityIPs    int           `yaml:"max_activity_ips"`
	HotCacheIPs       int           `yaml:"hot_cache_ips"`
	WriteRetryTimeout time.Duration `yaml:"write_retry_timeout"`
}

func Default() Config {
	return Config{Mode: "dns", Storage: Storage{Mode: "full", Retention: 24 * time.Hour, QueueMemoryMB: 8}, Network: Network{Capture: true, RuntimeDirectory: "/run/netmon", Rating: Rating{PacketsPerSecond: 1000, SYNPerSecond: 100, ScanPorts: 8, HalfLife: time.Hour}}, Cluster: Cluster{Listen: "0.0.0.0:9845", SyncInterval: 5 * time.Second}, Interface: "eth0", Port: 53, Database: "/var/lib/netmon/stats.db", FlushInterval: 30 * time.Second,
		MaxPending: 10000, MaxDatabaseMB: 64, MaxWALMB: 16, SocketBufferMB: 2,
		MaxTCPFlows: 1024, MaxTCPBytes: 8 << 20, MaxFragments: 256, MaxFragmentBytes: 2 << 20, ReassemblyTimeout: 2 * time.Minute, TCPIdleTimeout: 10 * time.Minute, HotCacheIPs: 8192, MaxActivityIPs: 10000, WriteRetryTimeout: 30 * time.Second}
}

func Load(path string, required bool) (Config, error) {
	return loadDefaults(path, required, Default())
}

func LoadLegacy(path string) (Config, error) {
	c := Default()
	c.Database = "/var/lib/dnsmon/stats.db"
	c.Network.RuntimeDirectory = "/run/dnsmon"
	return loadDefaults(path, true, c)
}

func loadDefaults(path string, required bool, c Config) (Config, error) {
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
	if c.TCPIdleTimeout < time.Second || c.TCPIdleTimeout > time.Hour {
		return errors.New("tcp_idle_timeout must be between 1s and 1h")
	}
	if c.MaxActivityIPs < 0 || c.MaxActivityIPs > 100000 {
		return errors.New("max_activity_ips must be 0..100000")
	}
	if c.HotCacheIPs < 0 || c.HotCacheIPs > 1000000 {
		return errors.New("hot_cache_ips must be 0..1000000")
	}
	if c.WriteRetryTimeout < time.Second || c.WriteRetryTimeout > 5*time.Minute {
		return errors.New("write_retry_timeout must be 1s..5m")
	}
	return c.validateNetwork()
}
