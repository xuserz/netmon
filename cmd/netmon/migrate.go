package main

import (
	"errors"
	"flag"
	"io"

	"gopkg.in/yaml.v3"
	"netmon/internal/config"
)

// Emit a canonical config with the old implicit paths made explicit. The input
// file, databases and cluster identities are never modified by this command.
func migrateConfig(args []string, out, errOut io.Writer) error {
	fs := flag.NewFlagSet("migrate-config", flag.ContinueOnError)
	fs.SetOutput(errOut)
	from := fs.String("from", "/etc/dnsmon/config.yaml", "existing dnsmon config")
	if e := fs.Parse(args); e != nil {
		if errors.Is(e, flag.ErrHelp) {
			return nil
		}
		return e
	}
	if fs.NArg() != 0 {
		return errors.New("migrate-config takes no positional arguments")
	}
	c, e := config.LoadLegacy(*from)
	if e != nil {
		return e
	}
	encoder := yaml.NewEncoder(out)
	encoder.SetIndent(2)
	defer encoder.Close()
	return encoder.Encode(c)
}
