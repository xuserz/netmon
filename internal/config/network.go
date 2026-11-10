package config

import (
	"errors"
	"path/filepath"
	"time"
)

type Storage struct {
	Mode          string        `yaml:"mode"`
	Retention     time.Duration `yaml:"retention"`
	QueueMemoryMB int           `yaml:"queue_memory_mb"`
}
type Rating struct {
	PacketsPerSecond int64         `yaml:"pps_threshold"`
	SYNPerSecond     int64         `yaml:"syn_pps_threshold"`
	ScanPorts        int           `yaml:"scan_ports_threshold"`
	HalfLife         time.Duration `yaml:"half_life"`
}
type Network struct {
	AnalysisInterval time.Duration `yaml:"analysis_interval"`
	AnalysisBudget   time.Duration `yaml:"analysis_budget"`
	Classify         bool          `yaml:"classify"`
	ExcludeReplies   bool          `yaml:"exclude_replies"`
	MaxTrackedFlows  int           `yaml:"max_tracked_flows"`
	FlowTimeout      time.Duration `yaml:"flow_timeout"`
	DetailTargets    int           `yaml:"detail_targets"`
	Capture          bool          `yaml:"capture"`
	Ports            []uint16      `yaml:"ports"`
	ExcludePorts     []uint16      `yaml:"exclude_ports"`
	RuntimeDirectory string        `yaml:"runtime_directory"`
	Rating           Rating        `yaml:"rating"`
}

func (c Config) validateNetwork() error {
	if c.Mode != "dns" && c.Mode != "network" {
		return errors.New("mode must be dns or network")
	}
	if c.Network.MaxTrackedFlows < 0 || c.Network.MaxTrackedFlows > 1000000 || c.Network.FlowTimeout < time.Second || c.Network.FlowTimeout > time.Hour || c.Network.DetailTargets < 1 || c.Network.DetailTargets > 64 {
		return errors.New("invalid network flow/detail budgets")
	}
	if c.Network.AnalysisInterval < time.Second || c.Network.AnalysisInterval > time.Minute || c.Network.AnalysisBudget < 50*time.Millisecond || c.Network.AnalysisBudget > time.Second || c.Network.AnalysisBudget > c.Network.AnalysisInterval/2 {
		return errors.New("invalid analysis interval/budget")
	}
	if c.Network.ExcludeReplies && (!c.Network.Classify || c.Network.MaxTrackedFlows == 0) {
		return errors.New("exclude_replies requires network.classify")
	}
	if c.Mode != "network" {
		if c.Storage.Mode != "full" {
			return errors.New("forward storage mode requires mode: network")
		}
		return c.Cluster.Validate()
	}
	if c.Storage.Mode != "full" && c.Storage.Mode != "forward" {
		return errors.New("storage.mode must be full or forward")
	}
	if c.Storage.Retention != 0 && (c.Storage.Retention < time.Hour || c.Storage.Retention > 30*24*time.Hour) {
		return errors.New("storage.retention must be 0s (capacity only) or 1h..720h")
	}
	if c.Storage.QueueMemoryMB < 1 || c.Storage.QueueMemoryMB > 256 {
		return errors.New("storage.queue_memory_mb must be 1..256")
	}
	if !filepath.IsAbs(c.Network.RuntimeDirectory) || len(c.Network.RuntimeDirectory) > 80 {
		return errors.New("network.runtime_directory must be an absolute path up to 80 bytes")
	}
	r := c.Network.Rating
	if r.PacketsPerSecond < 1 || r.PacketsPerSecond > 1000000000 || r.SYNPerSecond < 1 || r.SYNPerSecond > 1000000000 || r.ScanPorts < 2 || r.ScanPorts > 16 || r.HalfLife < time.Minute || r.HalfLife > 7*24*time.Hour {
		return errors.New("invalid rating thresholds/half_life")
	}
	if len(c.Network.Ports) > 64 || len(c.Network.ExcludePorts) > 64 {
		return errors.New("network port lists are limited to 64 ports")
	}
	for _, p := range append(append([]uint16(nil), c.Network.Ports...), c.Network.ExcludePorts...) {
		if p == 0 {
			return errors.New("network ports must be 1..65535")
		}
	}
	if c.Storage.Mode == "forward" {
		if !c.Cluster.Enabled || len(c.Cluster.Peers) == 0 {
			return errors.New("forwarding requires cluster.enabled and at least one storage peer")
		}
		return c.Cluster.ValidateClient()
	}
	return c.Cluster.Validate()
}
