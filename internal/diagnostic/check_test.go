package diagnostic

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"dnsmon/internal/config"
)

func TestMissingInterfaceExplainsHowToFix(t *testing.T) {
	c := config.Default()
	c.Interface = "missing-dnsmon"
	c.Database = filepath.Join(t.TempDir(), "stats.db")
	found := false
	for _, f := range Checks(c, true) {
		if f.Level == "FAIL" && (strings.Contains(f.Message, "available:") || strings.Contains(f.Message, "cannot inspect")) {
			found = true
		}
	}
	if !found {
		t.Fatal("missing interface was not diagnosed")
	}
	if _, e := os.Stat(c.Database); !os.IsNotExist(e) {
		t.Fatal("read-only check created a database", e)
	}
}
func TestInvalidConfigurationStopsBeforeRuntimeChecks(t *testing.T) {
	c := config.Default()
	c.Port = 0
	findings := Checks(c, true)
	if len(findings) != 1 || findings[0].Level != "FAIL" {
		t.Fatal(findings)
	}
}

func TestServicePermissionPrecedence(t *testing.T) {
	groups := map[uint32]bool{20: true}
	for _, tc := range []struct {
		uid, gid uint32
		mode     os.FileMode
		want     bool
	}{{10, 20, 0700, true}, {10, 20, 0070, false}, {0, 20, 0770, true}, {0, 30, 0770, false}, {0, 30, 0707, true}} {
		if got := modeAllows(tc.uid, tc.gid, tc.mode, 10, groups, 0300); got != tc.want {
			t.Fatal(tc, got)
		}
	}
}
