package config

import (
	"testing"
	"time"
)

func TestNetworkRolesAndBounds(t *testing.T) {
	c := Default()
	c.Mode = "network"
	if e := c.Validate(); e != nil {
		t.Fatal(e)
	}
	c.Storage.Mode = "forward"
	if e := c.Validate(); e == nil {
		t.Fatal("forward without storage peer accepted")
	}
	c.Cluster.Enabled = true
	c.Cluster.KeyFile = "/etc/netmon/cluster.key"
	c.Cluster.Peers = []string{"https://127.0.0.1:9845"}
	c.Cluster.Listen = ""
	c.Cluster.Advertise = ""
	if e := c.Validate(); e != nil {
		t.Fatal("outbound-only forward rejected", e)
	}
	for _, mutate := range []func(*Config){
		func(c *Config) { c.Mode = "dns" },
		func(c *Config) { c.Storage.Mode = "unknown" },
		func(c *Config) { c.Storage.QueueMemoryMB = 0 },
		func(c *Config) { c.Storage.Retention = 30 * time.Minute },
		func(c *Config) { c.Network.Rating.HalfLife = 0 },
		func(c *Config) { c.Network.Rating.ScanPorts = 17 },
		func(c *Config) { c.Network.Ports = []uint16{0} },
		func(c *Config) { c.Network.RuntimeDirectory = "relative" },
	} {
		invalid := c
		mutate(&invalid)
		if e := invalid.Validate(); e == nil {
			t.Fatal("invalid network configuration accepted", invalid)
		}
	}
}
