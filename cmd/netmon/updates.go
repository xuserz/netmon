package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"netmon/internal/config"
	"netmon/internal/live"
	"netmon/internal/network"
	"netmon/internal/release"
	"netmon/internal/updater"
)

func updateKeygen(args []string, out, errs io.Writer) error {
	fs := flag.NewFlagSet("updates keygen", flag.ContinueOnError)
	fs.SetOutput(errs)
	private := fs.String("private", "", "new private seed file (keep outside Git)")
	public := fs.String("public", "", "new public key file")
	if e := fs.Parse(args); e != nil {
		if errors.Is(e, flag.ErrHelp) {
			return nil
		}
		return e
	}
	if *private == "" || *public == "" || fs.NArg() != 0 {
		return errors.New("use updates keygen --private FILE --public FILE")
	}
	a, _ := filepath.Abs(*private)
	b, _ := filepath.Abs(*public)
	if a == b {
		return errors.New("private and public paths must differ")
	}
	pub, key, e := ed25519.GenerateKey(nil)
	if e != nil {
		return e
	}
	// Never truncate a key, follow a link, or print private material to a log.
	f, e := os.OpenFile(a, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	_, e = f.WriteString(hex.EncodeToString(key.Seed()) + "\n")
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	p, e := os.OpenFile(b, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if e != nil {
		os.Remove(a)
		return e
	}
	_, e = p.WriteString(hex.EncodeToString(pub) + "\n")
	ce = p.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	fmt.Fprintf(out, "Private signing seed: %s (0600; never commit)\nPublic verification key: %s\nGitHub Actions secret name: NETMON_UPDATE_SIGNING_KEY\n", a, b)
	return nil
}
func updateVerify(args []string, out, errs io.Writer) error {
	fs := flag.NewFlagSet("updates verify", flag.ContinueOnError)
	fs.SetOutput(errs)
	manifest := fs.String("manifest", "", "update.json path (signature at .sig)")
	key := fs.String("key", "/etc/netmon/update-public-key", "trusted public key")
	want := fs.String("version", "", "expected binary/release version")
	archive := fs.String("archive", "", "also verify the selected archive bytes")
	if e := fs.Parse(args); e != nil {
		if errors.Is(e, flag.ErrHelp) {
			return nil
		}
		return e
	}
	if *manifest == "" || *want == "" || fs.NArg() != 0 {
		return errors.New("verify requires --manifest FILE --version TAG [--key FILE]")
	}
	o, e := release.ReadOffer(*manifest)
	if e != nil {
		return e
	}
	k, e := release.PublicKey(*key)
	if e != nil {
		return e
	}
	m, e := release.Verify(o, k)
	if e != nil {
		return e
	}
	if m.Version != *want {
		return errors.New("signed manifest version differs from requested release")
	}
	if *archive != "" {
		a, ok := m.Assets[filepath.Base(*archive)]
		if !ok {
			return errors.New("archive is absent from signed manifest")
		}
		f, e := os.Open(*archive)
		if e != nil {
			return e
		}
		defer f.Close()
		h := sha256.New()
		n, e := io.Copy(h, io.LimitReader(f, release.MaxArchive+1))
		if e != nil {
			return e
		}
		if n != a.Size || hex.EncodeToString(h.Sum(nil)) != a.SHA256 {
			return errors.New("archive differs from signed manifest")
		}
	}
	fmt.Fprintln(out, "Verified publisher signature:", m.Version)
	return nil
}
func updatesCommand(args []string, c config.Config, configPath string, out, errs io.Writer) error {
	if len(args) == 0 {
		args = []string{"status"}
	}
	if len(args) == 1 && (args[0] == "help" || args[0] == "--help" || args[0] == "-h") {
		fmt.Fprintln(out, "Usage: netmon updates status | apply [--retry] | keygen --private FILE --public FILE | verify --manifest FILE --version TAG\nAutomatic application requires root, a signed offer, explicit opt-in and a coordinator lease.")
		return nil
	}
	if args[0] == "status" {
		if len(args) != 1 {
			return errors.New("updates status takes no arguments")
		}
		fmt.Fprintf(out, "Installed build: %s\nAutomatic: %t; propagate: %t\nCoordinator: %s\nPublic key: %s\n", version, c.Updates.Automatic, c.Updates.Propagate, c.Updates.Coordinator, c.Updates.PublicKey)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		s, e := live.Fetch(ctx, network.RuntimeBase(c), live.Request{Op: "health"})
		if e == nil && s.UpdateOffer != nil {
			k, ke := release.PublicKey(c.Updates.PublicKey)
			if ke == nil {
				m, me := release.Verify(*s.UpdateOffer, k)
				if me == nil {
					fmt.Fprintf(out, "Announced release: %s; automatic allowed by publisher: %t\n", m.Version, m.Automatic)
				}
			}
		}
		st := network.ReadUpdateStatus()
		fmt.Fprintf(out, "Last update: %s; target: %s\n", st.State, st.Target)
		if st.Error != "" {
			fmt.Fprintln(out, "Detail:", st.Error)
		}
		if _, e := release.PublicKey(c.Updates.PublicKey); e != nil {
			fmt.Fprintln(out, "Verification key unavailable:", e)
		}
		return nil
	}
	if args[0] != "apply" {
		return errors.New("expected updates status or apply [--retry]")
	}
	retry := len(args) == 2 && args[1] == "--retry"
	if len(args) > 1 && !retry {
		return errors.New("use updates apply [--retry]")
	}
	if os.Geteuid() != 0 {
		return errors.New("updates apply requires root (normally netmon-update.service)")
	}
	if !c.Updates.Automatic {
		fmt.Fprintln(out, "Automatic updates disabled.")
		return nil
	}
	if e := updater.RootFile(configPath); e != nil {
		return e
	}
	if e := updater.RootFile(c.Updates.PublicKey); e != nil {
		return e
	}
	if e := os.MkdirAll(filepath.Dir(network.UpdateStatePath), 0755); e != nil {
		return e
	}
	// Verify directory ownership using a root-created file without trusting a
	// monitor-controlled path. RootFile checks every ancestor as well.
	probe, e := os.CreateTemp(filepath.Dir(network.UpdateStatePath), ".trust-*")
	if e != nil {
		return e
	}
	probe.Close()
	defer os.Remove(probe.Name())
	if e = updater.RootFile(probe.Name()); e != nil {
		return e
	}
	fd, e := syscall.Open("/run/netmon-install.lock", syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if e != nil {
		return e
	}
	defer syscall.Close(fd)
	if e = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		fmt.Fprintln(out, "Another local installer is running; waiting for next timer tick.")
		return nil
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	e = updater.New(c, version).Once(ctx, retry)
	if e == nil {
		st := network.ReadUpdateStatus()
		fmt.Fprintln(out, strings.TrimSpace(st.State+" "+st.Target+" "+st.Error))
	}
	return e
}
