package main

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sort"

	"netmon/internal/config"
	"netmon/internal/identity"
	"netmon/internal/network"
)

func labelCommand(kind string, args []string, c config.Config, configPath string, out io.Writer) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	action := args[0]
	if action == "--help" || action == "-h" || action == "help" {
		fmt.Fprintf(out, "Usage: netmon %s list | add IP[/CIDR] \"description\" | remove IP[/CIDR]\nCatalog: %s\n", kind, c.LabelsFile)
		if kind == "whitelist" {
			fmt.Fprintln(out, "  import-dns           Add reviewed public DNS endpoint labels; keep existing descriptions")
		}
		return nil
	}
	if c.LabelsFile == "" {
		return errors.New("labels_file is disabled")
	}
	if action == "list" {
		if len(args) != 1 {
			return errors.New("list takes no positional arguments")
		}
		book, e := identity.Load(c.LabelsFile)
		if e != nil {
			return e
		}
		entries := book.Whitelist
		if kind == "servers" {
			entries = book.Servers
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].IP < entries[j].IP })
		fmt.Fprintf(out, "%-43s %s\n", "IP / CIDR", "DESCRIPTION")
		for _, entry := range entries {
			fmt.Fprintf(out, "%-43s %s\n", entry.IP, entry.Description)
		}
		fmt.Fprintf(out, "Entries: %d\nCatalog: %s\n", len(entries), c.LabelsFile)
		return nil
	}
	if action != "add" && action != "remove" && action != "import-dns" {
		return errors.New("expected list, add, remove or whitelist import-dns")
	}
	if action == "import-dns" && (kind != "whitelist" || len(args) != 1) {
		return errors.New("use netmon whitelist import-dns without extra arguments")
	}
	if action == "add" && len(args) != 3 {
		return errors.New("add requires IP[/CIDR] and a quoted description")
	}
	if action == "remove" && len(args) != 2 {
		return errors.New("remove requires exactly one IP[/CIDR]")
	}
	key := ""
	var e error
	if action != "import-dns" {
		key, e = identity.Normalize(args[1])
		if e != nil {
			return e
		}
	}
	protected := []string{configPath, c.Cluster.KeyFile}
	for _, base := range []string{c.Database, network.DataPath(c.Database), c.Database + ".cluster.db"} {
		for _, suffix := range []string{"", "-wal", "-shm", ".sock", ".lock"} {
			protected = append(protected, base+suffix)
		}
	}
	protected = append(protected, filepath.Join(c.Network.RuntimeDirectory, "monitor.sock"), filepath.Join(c.Network.RuntimeDirectory, "monitor.lock"))
	added := 0
	e = identity.Edit(c.LabelsFile, protected, func(book *identity.Book) error {
		if action == "import-dns" {
			var e error
			added, e = identity.AddPublicDNS(book)
			return e
		}
		entries := &book.Whitelist
		if kind == "servers" {
			entries = &book.Servers
		}
		for i, entry := range *entries {
			if entry.IP != key {
				continue
			}
			if action == "remove" {
				*entries = append((*entries)[:i], (*entries)[i+1:]...)
			} else {
				(*entries)[i].Description = args[2]
			}
			return nil
		}
		if action == "remove" {
			return errors.New("address is not in this list")
		}
		*entries = append(*entries, identity.Entry{IP: key, Description: args[2]})
		return nil
	})
	if e != nil {
		return e
	}
	if action == "import-dns" {
		preset, entries, e := identity.PublicDNS()
		if e != nil {
			return e
		}
		fmt.Fprintf(out, "Public DNS preset: %d providers, %d exact IPs; verified %s\nAdded: %d; kept existing coverage: %d\nCatalog updated: %s\n", len(preset.Providers), len(entries), preset.Verified, added, len(entries)-added, c.LabelsFile)
		return nil
	}
	fmt.Fprintf(out, "%s: %s %s\nCatalog updated: %s\n", kind, action, key, c.LabelsFile)
	return nil
}
