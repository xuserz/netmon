package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"netmon/internal/live"
	"netmon/internal/store"
	"netmon/internal/ui"
)

// A stopped or older daemon remains inspectable through a read-only SQLite
// fallback. Cache unchanged snapshots so an idle screen does no database work.
type topFetcher struct {
	storedDB  string
	localOnly bool
	cluster   bool
	db        string
	limit     int
	cached    live.Response
	stamp     string
}

func (f *topFetcher) Fetch(ctx context.Context, sort string) (live.Response, error) {
	if r, e := live.Fetch(ctx, f.db, live.Request{Op: "top", Limit: f.limit, Sort: sort, Local: f.localOnly}); e == nil {
		return r, nil
	}
	if sort != "total" {
		return live.Response{Source: "stored", Sort: sort, Cluster: f.cluster}, nil
	}
	readDB := f.storedDB
	if readDB == "" {
		readDB = f.db
	}
	stamp := ""
	for _, suffix := range []string{"", "-wal"} {
		if st, e := os.Stat(readDB + suffix); e == nil {
			stamp += fmt.Sprintf("%d:%d;", st.ModTime().UnixNano(), st.Size())
		}
	}
	if f.cached.Source != "" && stamp == f.stamp {
		return f.cached, nil
	}
	s, e := store.Open(readDB, false, 0, 0)
	if e != nil {
		return live.Response{}, e
	}
	defer s.Close()
	rows, totals, e := s.StoredView(ctx, f.limit)
	if e != nil {
		return live.Response{}, e
	}
	r := live.Response{Clients: rows, Totals: totals, Source: "stored", Cluster: f.cluster}
	f.cached = r
	f.stamp = stamp
	return r, nil
}
func interactiveTop(out io.Writer, db string, limit int, interval time.Duration, noColor bool, sort string, readDB string, localOnly bool, cluster bool) error {
	file, ok := out.(*os.File)
	if !ok {
		return fmt.Errorf("--watch requires a terminal")
	}
	if limit > 1000 {
		return fmt.Errorf("live top supports at most 1000 rows; use --once or list for larger exports")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	_, noColorEnv := os.LookupEnv("NO_COLOR")
	fetch := &topFetcher{db: db, limit: limit, storedDB: readDB, localOnly: localOnly, cluster: cluster}
	return ui.Run(ctx, ui.Options{In: os.Stdin, Out: file, Interval: interval, Version: version, Sort: sort, Color: !noColor && !noColorEnv}, fetch.Fetch)
}
func terminalOutput(out io.Writer) bool {
	f, ok := out.(*os.File)
	return ok && os.Getenv("TERM") != "dumb" && ui.IsTerminal(f) && ui.IsTerminal(os.Stdin)
}
