package main

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"

	"netmon/internal/config"
	"netmon/internal/providers"
)

func providerCommand(args []string, c config.Config, out io.Writer) error {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h" || args[0] == "help") {
		fmt.Fprintln(out, "Usage: netmon providers [lookup IP]\nOffline attribution from providers_file; never grants trust or changes ratings.")
		return nil
	}
	var ip netip.Addr
	if len(args) != 0 {
		if len(args) != 2 || args[0] != "lookup" {
			return errors.New("use netmon providers [lookup IP]")
		}
		var e error
		ip, e = netip.ParseAddr(args[1])
		if e != nil || ip.Zone() != "" {
			return errors.New("lookup requires one IPv4/IPv6 address")
		}
	}
	catalog, e := providers.Load(c.ProvidersFile)
	if e != nil {
		return fmt.Errorf("provider catalog: %w", e)
	}
	fmt.Fprintf(out, "Local catalog: %s\n", c.ProvidersFile)
	if catalog.Entries == 0 {
		fmt.Fprintln(out, "Provider attribution disabled: catalog is empty, missing or unconfigured.")
		return nil
	}
	fmt.Fprintf(out, "Providers: %d; prefixes: %d\nGenerated: %s\nRevision: %s\nSource: %s\nLicense: %s\n", len(catalog.Metadata.Providers), catalog.Entries, catalog.Metadata.Generated, catalog.Metadata.Revision, catalog.Metadata.Repository, catalog.Metadata.License)
	if !ip.IsValid() {
		return nil
	}
	fmt.Fprintf(out, "IP: %s\n", ip.Unmap())
	matches := catalog.Lookup(ip)
	if len(matches) == 0 {
		fmt.Fprintln(out, "No provider match in this snapshot.")
	}
	for _, match := range matches {
		fmt.Fprintf(out, "%s · %s · %s\n", strings.ToUpper(match.Category), match.Name, match.CIDR)
	}
	fmt.Fprintln(out, "Attribution only; TRUSTED requires your whitelist.")
	return nil
}
