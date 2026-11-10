package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"dnsmon/internal/config"
	"dnsmon/internal/monitor"
	"dnsmon/internal/store"
)

var version = "dev"

const usage = `dnsmon — lightweight Linux DNS client counters
Usage: dnsmon [--config /etc/dnsmon/config.yaml] [--db /path/stats.db] COMMAND

  run                  Run the foreground monitor (used by systemd)
  top [-n 20]          Live, colorful terminal dashboard (q quits)
  top --once           Print one committed snapshot; pipes use this automatically
  show IP              One IPv4/IPv6 address
  stats                Global totals
  list                 All clients, ordered by count
  export --csv FILE    Export a consistent snapshot to CSV
  status               Service state and live capture diagnostics
  check [--startup]    Read-only configuration and runtime checks
  version              Print version

Read commands never start a capture. Global flags may also follow COMMAND.
`

func main() {
	if e := run(os.Args[1:], os.Stdout, os.Stderr); e != nil {
		fmt.Fprintln(os.Stderr, "dnsmon:", e)
		os.Exit(1)
	}
}
func run(args []string, out, errOut io.Writer) error {
	path := "/etc/dnsmon/config.yaml"
	dbPath := ""
	explicit := false
	var rest []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--config" || a == "--db":
			if i+1 == len(args) {
				return fmt.Errorf("%s requires a value", a)
			}
			i++
			if a == "--config" {
				path = args[i]
				explicit = true
			} else {
				dbPath = args[i]
			}
		case strings.HasPrefix(a, "--config="):
			path = strings.TrimPrefix(a, "--config=")
			explicit = true
		case strings.HasPrefix(a, "--db="):
			dbPath = strings.TrimPrefix(a, "--db=")
		default:
			rest = append(rest, a)
		}
	}
	if len(rest) == 0 || rest[0] == "help" || rest[0] == "--help" || rest[0] == "-h" {
		fmt.Fprint(out, usage)
		return nil
	}
	command := rest[0]
	rest = rest[1:]
	if command == "version" {
		if len(rest) > 0 {
			return errors.New("version takes no arguments")
		}
		fmt.Fprintln(out, version)
		return nil
	}

	switch command {
	case "run", "top", "show", "stats", "list", "export", "status", "check":
	default:
		return fmt.Errorf("unknown command %q; use dnsmon help", command)
	}
	c, e := config.Load(path, explicit || command == "run" || command == "check")
	if e != nil {
		if command != "status" {
			return e
		}
		fmt.Fprintf(errOut, "Configuration error: %v\n", e)
		c = config.Default()
	}
	if dbPath != "" {
		p, err := filepath.Abs(dbPath)
		if err != nil {
			return err
		}
		c.Database = p
	}
	if command == "status" {
		if len(rest) > 0 {
			return errors.New("status takes no arguments")
		}
		return status(c, out, errOut)
	}
	if command == "check" {
		return check(c, rest, out, errOut)
	}
	if command == "run" {
		if len(rest) > 0 {
			return errors.New("run takes no arguments")
		}
		syscall.Umask(0027)
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		return monitor.Run(ctx, c)
	}
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(errOut)
	limit := 20
	once, watch, noColor := false, false, false
	interval := 2 * time.Second
	csvPath := ""
	if command == "top" {
		fs.IntVar(&limit, "n", 20, "number of clients (up to 1000 in live mode)")
		fs.BoolVar(&once, "once", false, "print one committed SQLite snapshot")
		fs.BoolVar(&watch, "watch", false, "require an interactive live display")
		fs.BoolVar(&noColor, "no-color", false, "disable color")
		fs.DurationVar(&interval, "interval", 2*time.Second, "live refresh interval (250ms..1m)")
	}
	if command == "export" {
		fs.StringVar(&csvPath, "csv", "", "output CSV path")
	}
	if e = fs.Parse(rest); e != nil {
		if errors.Is(e, flag.ErrHelp) {
			return nil
		}
		return e
	}
	if command == "top" && limit < 1 {
		return errors.New("-n must be positive")
	}
	if command == "show" {
		if fs.NArg() != 1 {
			return errors.New("show requires exactly one IP")
		}
	} else if fs.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if command == "export" && csvPath == "" {
		return errors.New("export requires --csv FILE")
	}
	if command == "top" {
		if once && watch {
			return errors.New("--once and --watch are mutually exclusive")
		}
		if interval < 250*time.Millisecond || interval > time.Minute {
			return errors.New("--interval must be 250ms..1m")
		}
		if !once && (watch || terminalOutput(out)) {
			return interactiveTop(out, c.Database, limit, interval, noColor)
		}
	}
	s, e := store.Open(c.Database, false, 0, 0)
	if e != nil {
		return fmt.Errorf("open statistics (has the service initialized the database?): %w", e)
	}
	defer s.Close()
	tx, e := s.DB.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if command == "show" {
		return show(tx, fs.Arg(0), out)
	}
	if command == "export" {
		return export(tx, c.Database, csvPath, out)
	}
	if command == "top" || command == "list" {
		query := "SELECT ip,requests,first_seen,last_seen FROM clients ORDER BY requests DESC,ip ASC"
		var rows *sql.Rows
		if command == "top" {
			rows, e = tx.Query(query+" LIMIT ?", limit)
		} else {
			rows, e = tx.Query(query)
		}
		if e != nil {
			return e
		}
		fmt.Fprintln(out, "DNS MONITOR")
		printHeader(out)
		for rows.Next() {
			c, err := store.Scan(rows)
			if err != nil {
				rows.Close()
				return err
			}
			printClient(out, c)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
	}
	return totals(tx, out)
}
func printHeader(w io.Writer) {
	fmt.Fprintf(w, "%-39s %25s %12s %12s\n", "IP ADDRESS", "REQUESTS", "FIRST SEEN", "LAST SEEN")
}
func printClient(w io.Writer, c store.Client) {
	fmt.Fprintf(w, "%-39s %25s %12s %12s\n", c.IP, commas(strconv.FormatInt(c.Requests, 10)), time.Unix(c.First, 0).Format("02.01.2006"), time.Unix(c.Last, 0).Format("02.01.2006"))
}
func commas(s string) string {
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}
func totals(tx *sql.Tx, w io.Writer) error {
	rows, e := tx.Query("SELECT requests,first_seen,last_seen FROM clients")
	if e != nil {
		return e
	}
	defer rows.Close()
	var n int64
	total := new(big.Int)
	var first, last int64
	for rows.Next() {
		var count, f, l int64
		if e = rows.Scan(&count, &f, &l); e != nil {
			return e
		}
		n++
		total.Add(total, big.NewInt(count))
		if n == 1 || f < first {
			first = f
		}
		if l > last {
			last = l
		}
	}
	if e = rows.Err(); e != nil {
		return e
	}
	fmt.Fprintf(w, "Unique IPs: %s\nTotal requests: %s\n", commas(strconv.FormatInt(n, 10)), commas(total.String()))
	if n > 0 {
		fmt.Fprintf(w, "First seen: %s\nLast seen: %s\n", time.Unix(first, 0).Format(time.RFC3339), time.Unix(last, 0).Format(time.RFC3339))
	}
	return nil
}
