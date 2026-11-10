package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"netmon/internal/config"
)

func TestMigrationPreservesImplicitOldDefaultsAndOriginalFile(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "old.yaml")
	original := "interface: ens3\nmax_database_mb: 20480\n"
	if e := os.WriteFile(input, []byte(original), 0600); e != nil {
		t.Fatal(e)
	}
	var out, errs bytes.Buffer
	if e := run([]string{"migrate-config", "--from", input}, &out, &errs); e != nil {
		t.Fatal(e, errs.String())
	}
	generated := filepath.Join(dir, "netmon.yaml")
	if e := os.WriteFile(generated, out.Bytes(), 0600); e != nil {
		t.Fatal(e)
	}
	migrated, e := config.Load(generated, true)
	if e != nil || migrated.Mode != "dns" || migrated.Database != "/var/lib/dnsmon/stats.db" || migrated.Network.RuntimeDirectory != "/run/dnsmon" || migrated.MaxDatabaseMB != 20480 {
		t.Fatal(migrated, e)
	}
	old, e := os.ReadFile(input)
	if e != nil || string(old) != original {
		t.Fatal("original config changed", e)
	}
}

func TestMigrationPreservesCustomPathsClusterAndForwardRole(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "old.yaml")
	text := `mode: network
interface: lo
database: /srv/custom/statistics.db
storage:
  mode: forward
network:
  runtime_directory: /run/custom
cluster:
  enabled: true
  key_file: /etc/dnsmon/cluster.key
  name: existing-node
  peers: [https://192.0.2.1:9845]
`
	if e := os.WriteFile(input, []byte(text), 0600); e != nil {
		t.Fatal(e)
	}
	var out, errs bytes.Buffer
	if e := run([]string{"migrate-config", "--from", input}, &out, &errs); e != nil {
		t.Fatal(e)
	}
	generated := filepath.Join(dir, "new.yaml")
	os.WriteFile(generated, out.Bytes(), 0600)
	got, e := config.Load(generated, true)
	if e != nil || got.Database != "/srv/custom/statistics.db" || got.Network.RuntimeDirectory != "/run/custom" || got.Cluster.KeyFile != "/etc/dnsmon/cluster.key" || got.Storage.Mode != "forward" || got.Cluster.Name != "existing-node" {
		t.Fatal(got, e)
	}
}

func TestMigrationRejectsInvalidConfigBeforeProducingOutput(t *testing.T) {
	input := filepath.Join(t.TempDir(), "old.yaml")
	os.WriteFile(input, []byte("interface: any\n"), 0600)
	var out, errs bytes.Buffer
	if e := run([]string{"migrate-config", "--from", input}, &out, &errs); e == nil || out.Len() != 0 {
		t.Fatal("invalid migration emitted output", out.String(), e)
	}
}
