package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompactHelpDoesNotRequireAnInstalledConfiguration(t *testing.T) {
	var out, errs bytes.Buffer
	e := run([]string{"--config", filepath.Join(t.TempDir(), "missing.yaml"), "compact", "--help"}, &out, &errs)
	if e != nil || !strings.Contains(errs.String(), "-output") {
		t.Fatal(e, out.String(), errs.String())
	}
}
