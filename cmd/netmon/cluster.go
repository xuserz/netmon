package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unicode"

	"netmon/internal/cluster"
	"netmon/internal/config"
)

func clusterKeygen(args []string, out, errOut io.Writer) error {
	fs := flag.NewFlagSet("cluster keygen", flag.ContinueOnError)
	fs.SetOutput(errOut)
	path := fs.String("out", "", "new file path (0600); default prints the key")
	if e := fs.Parse(args); e != nil {
		return e
	}
	if fs.NArg() != 0 {
		return errors.New("keygen takes no positional arguments")
	}
	key := cluster.GenerateKey() + "\n"
	if *path == "" {
		_, e := io.WriteString(out, key)
		return e
	}
	f, e := os.OpenFile(*path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	success := false
	defer func() {
		f.Close()
		if !success {
			os.Remove(*path)
		}
	}()
	if _, e = io.WriteString(f, key); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	success = true
	fmt.Fprintln(out, "Cluster key written:", *path)
	return nil
}
func nodes(c config.Config, out io.Writer) error {
	if !c.Cluster.Enabled {
		return errors.New("cluster is disabled; see docs/cluster.md")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	peers, e := cluster.ListPeers(ctx, c.Database)
	if e != nil {
		return e
	}
	fmt.Fprintln(out, "CLUSTER PEERS · last successful exchange; local capture remains independent")
	fmt.Fprintln(out, "ADDRESS                         NAME              NODE                              LAST SUCCESS                 ERROR")
	clean := func(s string) string {
		return strings.Map(func(r rune) rune {
			if unicode.IsControl(r) {
				return ' '
			}
			return r
		}, s)
	}
	for _, p := range peers {
		fmt.Fprintf(out, "%-31s %-17s %-32s %-28s %s\n", clean(p.URL), clean(p.Name), p.Node, timestamp(p.Success), clean(p.Error))
	}
	return nil
}
