package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if e := os.WriteFile(path, []byte("interface: ens3\nflush_interval: 10s\ndestination_ip: '2001:db8::53'\n"), 0600); e != nil {
		t.Fatal(e)
	}
	c, e := Load(path, true)
	if e != nil || c.Interface != "ens3" || c.FlushInterval != 10*time.Second {
		t.Fatal(c, e)
	}
	for _, text := range []string{"providers_file: relative/catalog.gz\n", "interface: any\n", "hot_cache_ips: -1\n", "max_activity_ips: -1\n", "write_retry_timeout: 0s\n", "port: 0\n", "unknown_key: true\n", "max_tcp_flows: 0\n", "flush_interval: 0s\n", "destination_ip: 'fe80::1%eth0'\n", "---\ninterface: eth0\n---\nport: 53\n"} {
		os.WriteFile(path, []byte(text), 0600)
		if _, e = Load(path, true); e == nil {
			t.Fatal("accepted", text)
		}
	}
}

func TestClusterConfiguration(t *testing.T) {
	c := Default()
	c.Cluster.Enabled = true
	c.Cluster.Advertise = "https://192.0.2.1:9845"
	c.Cluster.KeyFile = "/etc/netmon/cluster.key"
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
	for _, bad := range []string{"http://192.0.2.1:9845", "https://192.0.2.1", "https://user:pass@192.0.2.1:9845", "https://192.0.2.1:9845/path", "https://192.0.2.1:99999"} {
		c.Cluster.Advertise = bad
		if e := c.Validate(); e == nil {
			t.Fatal("invalid cluster URL accepted", bad)
		}
	}
}
