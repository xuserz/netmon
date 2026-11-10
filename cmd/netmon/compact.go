package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"netmon/internal/config"
	"netmon/internal/network"
)

func compactCommand(args []string, c config.Config, out, errs io.Writer) error {
	fs := flag.NewFlagSet("compact", flag.ContinueOnError)
	fs.SetOutput(errs)
	output := fs.String("output", "", "new compact network DB path; source is preserved")
	timeout := fs.Duration("timeout", 30*time.Minute, "maintenance deadline (1s..24h)")
	if e := fs.Parse(args); e != nil {
		if errors.Is(e, flag.ErrHelp) {
			return nil
		}
		return e
	}
	if fs.NArg() != 0 || *output == "" {
		return errors.New("use netmon compact --output /path/new.network.db")
	}
	if *timeout < time.Second || *timeout > 24*time.Hour {
		return errors.New("compact --timeout must be 1s..24h")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	r, e := network.Compact(ctx, c, *output)
	if e != nil {
		return e
	}
	fmt.Fprintf(out, "Verified %d observations; converted %d legacy JSON payloads.\nDatabase: %.2f MiB -> %.2f MiB\nCompact copy: %s\nSource retained: %s\nSet database to the compact copy path in the same configuration, then start netmon.\nUse this identity on only one running full node.\n", r.Observations, r.Converted, float64(r.SourceBytes)/(1<<20), float64(r.ResultBytes)/(1<<20), r.Output, network.DataPath(c.Database))
	return nil
}
