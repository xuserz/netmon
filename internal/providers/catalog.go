// Package providers annotates source IPs using an offline range catalog. A
// provider match is attribution metadata, never an automatic trust decision.
package providers

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

const MaxProviders = 128
const MaxPrefixes = 250000
const maxCompressed = 8 << 20
const maxExpanded = 32 << 20

type Provider struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Category  string   `json:"category"`
	Sources   []string `json:"sources"`
	Generated string   `json:"generated"`
	Prefixes  []string `json:"prefixes,omitempty"`
}
type Metadata struct {
	Format     int        `json:"format"`
	Repository string     `json:"repository"`
	Revision   string     `json:"revision"`
	Generated  string     `json:"generated"`
	License    string     `json:"license"`
	Providers  []Provider `json:"providers"`
}
type Match struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Category string `json:"category"`
	CIDR     string `json:"cidr"`
}
type Catalog struct {
	Metadata Metadata
	Entries  int
	table    map[netip.Prefix][2]uint64
	lengths  []int
}

func validText(s string, limit int) bool {
	return s != "" && len(s) <= limit && utf8.ValidString(s) && strings.IndexFunc(s, unicode.IsControl) < 0
}
func validKind(s string) bool {
	switch s {
	case "cloud", "cdn", "bot", "service", "monitoring", "relay", "vpn", "tor":
		return true
	}
	return false
}
func Load(path string) (*Catalog, error) {
	empty := &Catalog{table: map[netip.Prefix][2]uint64{}}
	if path == "" {
		return empty, nil
	}
	f, e := os.Open(path)
	if errors.Is(e, os.ErrNotExist) {
		return empty, nil
	}
	if e != nil {
		return nil, e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil {
		return nil, e
	}
	if !info.Mode().IsRegular() || info.Size() > maxCompressed {
		return nil, errors.New("provider catalog must be a regular file up to 8 MiB")
	}
	gz, e := gzip.NewReader(io.LimitReader(f, maxCompressed+1))
	if e != nil {
		return nil, e
	}
	defer gz.Close()
	raw, e := io.ReadAll(io.LimitReader(gz, maxExpanded+1))
	if e != nil {
		return nil, e
	}
	if len(raw) > maxExpanded {
		return nil, errors.New("expanded provider catalog exceeds 32 MiB")
	}
	var m Metadata
	if e = json.Unmarshal(raw, &m); e != nil {
		return nil, e
	}
	if m.Format != 1 || len(m.Providers) > MaxProviders || !validText(m.Revision, 128) || !validText(m.Generated, 32) || !validText(m.Repository, 256) || m.License != "CC0-1.0" {
		return nil, errors.New("invalid provider catalog metadata")
	}
	c := &Catalog{Metadata: m, table: map[netip.Prefix][2]uint64{}}
	lengths := map[int]bool{}
	ids := map[string]bool{}
	for i := range c.Metadata.Providers {
		p := &c.Metadata.Providers[i]
		if !validText(p.ID, 64) || ids[p.ID] || !validText(p.Name, 128) || !validKind(p.Category) || len(p.Sources) > 32 || !validText(p.Generated, 32) {
			return nil, errors.New("invalid provider metadata")
		}
		ids[p.ID] = true
		for _, source := range p.Sources {
			if !validText(source, 2048) {
				return nil, errors.New("invalid provider source URL")
			}
		}
		seen := map[netip.Prefix]bool{}
		for _, raw := range p.Prefixes {
			prefix, e := netip.ParsePrefix(raw)
			if e != nil || prefix != prefix.Masked() || prefix.Addr().Zone() != "" || prefix.Addr().Is4In6() || prefix.Bits() == 0 {
				return nil, fmt.Errorf("invalid provider prefix %q", raw)
			}
			if seen[prefix] {
				return nil, fmt.Errorf("duplicate prefix for %s", p.ID)
			}
			seen[prefix] = true
			c.Entries++
			if c.Entries > MaxPrefixes {
				return nil, errors.New("provider prefix limit exceeded")
			}
			mask := c.table[prefix]
			mask[i/64] |= uint64(1) << uint(i%64)
			c.table[prefix] = mask
			lengths[prefix.Bits()] = true
		}
		// Retain only the parsed prefix index and small provider provenance.
		p.Prefixes = nil
	}
	for n := range lengths {
		c.lengths = append(c.lengths, n)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(c.lengths)))
	return c, nil
}
func (c *Catalog) Lookup(ip netip.Addr) []Match {
	if c == nil {
		return nil
	}
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return nil
	}
	var result []Match
	var seen [2]uint64
	for _, n := range c.lengths {
		if n > ip.BitLen() {
			continue
		}
		prefix := netip.PrefixFrom(ip, n).Masked()
		mask, ok := c.table[prefix]
		if !ok {
			continue
		}
		for word := 0; word < 2; word++ {
			remaining := mask[word] &^ seen[word]
			seen[word] |= mask[word]
			for remaining != 0 {
				bit := bits.TrailingZeros64(remaining)
				id := word*64 + bit
				remaining &= remaining - 1
				p := c.Metadata.Providers[id]
				result = append(result, Match{ID: p.ID, Name: p.Name, Category: p.Category, CIDR: prefix.String()})
			}
		}
	}
	return result
}

type Loader struct {
	Path   string
	mu     sync.Mutex
	info   os.FileInfo
	cached *Catalog
}

func (l *Loader) Snapshot() (*Catalog, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	var info os.FileInfo
	var e error
	if l.Path != "" {
		info, e = os.Stat(l.Path)
	}
	if e != nil && !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	same := l.cached != nil && ((info == nil && l.info == nil) || (info != nil && l.info != nil && os.SameFile(info, l.info) && info.Size() == l.info.Size() && info.ModTime() == l.info.ModTime()))
	if same {
		return l.cached, nil
	}
	c, e := Load(l.Path)
	if e != nil {
		return nil, fmt.Errorf("provider catalog: %w", e)
	}
	l.cached = c
	l.info = info
	return c, nil
}
