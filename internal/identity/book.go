// Package identity manages explicit IP descriptions. It never changes counters
// or risk scores and performs no external IP ownership lookups.
package identity

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"unicode"
	"unicode/utf8"

	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"
)

const MaxEntries = 10000
const MaxBytes = 4 << 20

type Entry struct {
	IP          string `yaml:"ip"`
	Description string `yaml:"description"`
}
type Book struct {
	Servers   []Entry `yaml:"servers"`
	Whitelist []Entry `yaml:"whitelist"`
}

func Prefix(raw string) (netip.Prefix, error) {
	var p netip.Prefix
	var e error
	if strings.Contains(raw, "/") {
		p, e = netip.ParsePrefix(raw)
	} else {
		var a netip.Addr
		a, e = netip.ParseAddr(raw)
		if e == nil {
			p = netip.PrefixFrom(a, a.BitLen())
		}
	}
	if e != nil || !p.IsValid() || p.Addr().Zone() != "" {
		return p, fmt.Errorf("invalid IP/CIDR %q", raw)
	}
	if p.Addr().Is4In6() {
		if p.Bits() < 96 {
			return p, errors.New("mapped IPv4 prefix must have at least 96 bits")
		}
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	return p.Masked(), nil
}
func Normalize(raw string) (string, error) {
	p, e := Prefix(raw)
	if e != nil {
		return "", e
	}
	if p.Bits() == p.Addr().BitLen() {
		return p.Addr().String(), nil
	}
	return p.String(), nil
}
func Validate(b *Book) error {
	if len(b.Servers)+len(b.Whitelist) > MaxEntries {
		return fmt.Errorf("IP labels are limited to %d entries", MaxEntries)
	}
	for _, entries := range [][]Entry{b.Servers, b.Whitelist} {
		seen := map[string]bool{}
		for i := range entries {
			entry := &entries[i]
			normalized, e := Normalize(entry.IP)
			if e != nil {
				return e
			}
			if seen[normalized] {
				return fmt.Errorf("duplicate IP label %s", normalized)
			}
			seen[normalized] = true
			entry.IP = normalized
			if strings.TrimSpace(entry.Description) == "" || len(entry.Description) > 256 || !utf8.ValidString(entry.Description) || strings.IndexFunc(entry.Description, unicode.IsControl) >= 0 {
				return errors.New("IP description must be 1..256 UTF-8 bytes without control characters")
			}
			entry.Description = strings.TrimSpace(entry.Description)
		}
	}
	return nil
}
func Load(path string) (Book, error) {
	var b Book
	if path == "" {
		return b, nil
	}
	f, e := os.Open(path)
	if errors.Is(e, os.ErrNotExist) {
		return b, nil
	}
	if e != nil {
		return b, e
	}
	defer f.Close()
	data, e := io.ReadAll(io.LimitReader(f, MaxBytes+1))
	if e != nil {
		return b, e
	}
	if len(data) > MaxBytes {
		return b, errors.New("IP labels file exceeds 4 MiB")
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if e = decoder.Decode(&b); e != nil && !errors.Is(e, io.EOF) {
		return b, e
	}
	var extra any
	if e = decoder.Decode(&extra); e != io.EOF {
		return b, errors.New("IP labels require a single YAML document")
	}
	return b, Validate(&b)
}

type Index struct {
	entries map[netip.Prefix]string
	bits    []int
}

func Compile(entries []Entry) Index {
	index := Index{entries: map[netip.Prefix]string{}}
	used := map[int]bool{}
	for _, entry := range entries {
		p, e := Prefix(entry.IP)
		if e != nil {
			continue
		}
		index.entries[p] = entry.Description
		if !used[p.Bits()] {
			index.bits = append(index.bits, p.Bits())
			used[p.Bits()] = true
		}
	}
	sort.Sort(sort.Reverse(sort.IntSlice(index.bits)))
	return index
}
func (i Index) Lookup(ip netip.Addr) string {
	ip = ip.Unmap()
	for _, bits := range i.bits {
		if bits > ip.BitLen() {
			continue
		}
		if value := i.entries[netip.PrefixFrom(ip, bits).Masked()]; value != "" {
			return value
		}
	}
	return ""
}

// Loader recompiles only when the catalog file changes. Invalid edits return an
// error so callers can keep the last displayed snapshot with a visible warning.
type Loader struct {
	Path               string
	mu                 sync.Mutex
	info               os.FileInfo
	loaded             bool
	servers, whitelist Index
}

func (l *Loader) Indexes() (Index, Index, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var info os.FileInfo
	var e error
	if l.Path != "" {
		info, e = os.Stat(l.Path)
	}
	if e != nil && !errors.Is(e, os.ErrNotExist) {
		return Index{}, Index{}, e
	}
	same := l.loaded && ((info == nil && l.info == nil) || (info != nil && l.info != nil && os.SameFile(info, l.info) && info.Size() == l.info.Size() && info.ModTime() == l.info.ModTime()))
	if !same {
		b, e := Load(l.Path)
		if e != nil {
			return Index{}, Index{}, fmt.Errorf("IP labels: %w", e)
		}
		l.servers = Compile(b.Servers)
		l.whitelist = Compile(b.Whitelist)
		l.info = info
		l.loaded = true
	}
	return l.servers, l.whitelist, nil
}

// Edit serializes writers, preserves file owner/group and permissions, and
// atomically replaces a validated catalog. Symlink writes are deliberately refused.
func Edit(path string, protected []string, change func(*Book) error) error {
	if path == "" {
		return errors.New("labels_file is disabled")
	}
	if !filepath.IsAbs(path) {
		return errors.New("labels_file must be absolute")
	}
	for _, suffix := range []string{"", ".lock"} {
		target := path + suffix
		if st, e := os.Lstat(target); e == nil {
			if !st.Mode().IsRegular() {
				return fmt.Errorf("refusing to modify non-regular labels file %s", target)
			}
		} else if !os.IsNotExist(e) {
			return e
		}
		for _, other := range protected {
			if other == "" {
				continue
			}
			a, _ := filepath.Abs(target)
			b, _ := filepath.Abs(other)
			ra := resolvedPath(a)
			rb := resolvedPath(b)
			same := a == b || ra != "" && rb != "" && ra == rb
			if st, e := os.Stat(a); e == nil {
				if os_, e := os.Stat(b); e == nil && os.SameFile(st, os_) {
					same = true
				}
			}
			if same {
				return errors.New("labels file must not overwrite configuration, keys, databases or runtime files")
			}
		}
	}
	fd, e := unix.Open(path+".lock", unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0600)
	if e != nil {
		return e
	}
	defer unix.Close(fd)
	var lockStat unix.Stat_t
	if e = unix.Fstat(fd, &lockStat); e != nil {
		return e
	}
	if lockStat.Mode&unix.S_IFMT != unix.S_IFREG {
		return errors.New("IP labels lock must be a regular file")
	}
	if e = unix.Flock(fd, unix.LOCK_EX); e != nil {
		return e
	}
	defer unix.Flock(fd, unix.LOCK_UN)
	b, e := Load(path)
	if e != nil {
		return e
	}
	if e = change(&b); e != nil {
		return e
	}
	if e = Validate(&b); e != nil {
		return e
	}
	data, e := yaml.Marshal(b)
	if e != nil {
		return e
	}
	if len(data) > MaxBytes {
		return errors.New("IP labels file exceeds 4 MiB")
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".netmon-labels-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	defer f.Close()
	mode := os.FileMode(0640)
	var stat *syscall.Stat_t
	if info, e := os.Stat(path); e == nil {
		mode = info.Mode().Perm()
		stat, _ = info.Sys().(*syscall.Stat_t)
	} else if !os.IsNotExist(e) {
		return e
	}
	if stat != nil {
		if e = f.Chown(int(stat.Uid), int(stat.Gid)); e != nil {
			return e
		}
	} else if info, e := os.Stat(filepath.Dir(path)); e == nil {
		if parent, ok := info.Sys().(*syscall.Stat_t); ok {
			if e = f.Chown(-1, int(parent.Gid)); e != nil {
				return e
			}
		}
	}
	if e = f.Chmod(mode); e != nil {
		return e
	}
	if _, e = f.Write(data); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = os.Rename(f.Name(), path); e != nil {
		return e
	}
	dir, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer dir.Close()
	return dir.Sync()
}

func resolvedPath(path string) string {
	if real, e := filepath.EvalSymlinks(path); e == nil {
		return real
	}
	if parent, e := filepath.EvalSymlinks(filepath.Dir(path)); e == nil {
		return filepath.Join(parent, filepath.Base(path))
	}
	return path
}
