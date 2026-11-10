package config

import (
	"errors"
	"path/filepath"
)

type Updates struct {
	Automatic   bool   `yaml:"automatic"`
	Propagate   bool   `yaml:"propagate"`
	Coordinator string `yaml:"coordinator"`
	PublicKey   string `yaml:"public_key"`
}

func (c Config) validateUpdates() error {
	if !filepath.IsAbs(c.Updates.PublicKey) {
		return errors.New("updates.public_key must be absolute")
	}
	if c.Updates.Coordinator != "" {
		if _, e := PeerURL(c.Updates.Coordinator); e != nil {
			return e
		}
	}
	if c.Updates.Automatic && (c.Mode != "network" || !c.Cluster.Enabled || c.Updates.Coordinator == "") {
		return errors.New("automatic updates require network mode, cluster.enabled and updates.coordinator")
	}
	return nil
}
