package identity

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/netip"
)

// The reviewed release snapshot is kept offline: capture never downloads lists.
//
//go:embed data/public-dns.json
var publicDNSData []byte

type DNSProfile struct {
	Name      string   `json:"name"`
	Addresses []string `json:"addresses"`
}
type DNSProvider struct {
	Name     string       `json:"name"`
	Sources  []string     `json:"sources"`
	Profiles []DNSProfile `json:"profiles"`
}
type DNSPreset struct {
	Verified  string        `json:"verified"`
	Providers []DNSProvider `json:"providers"`
}

func PublicDNS() (DNSPreset, []Entry, error) {
	var preset DNSPreset
	if e := json.Unmarshal(publicDNSData, &preset); e != nil {
		return preset, nil, e
	}
	var entries []Entry
	for _, provider := range preset.Providers {
		for _, profile := range provider.Profiles {
			for _, raw := range profile.Addresses {
				ip, e := netip.ParseAddr(raw)
				if e != nil || ip.Zone() != "" || ip.IsPrivate() || ip.IsLoopback() || ip.IsUnspecified() || !ip.IsGlobalUnicast() {
					return preset, nil, fmt.Errorf("invalid public DNS preset IP %q", raw)
				}
				entries = append(entries, Entry{IP: ip.Unmap().String(), Description: provider.Name + " (" + profile.Name + ")"})
			}
		}
	}
	b := Book{Whitelist: entries}
	if e := Validate(&b); e != nil {
		return preset, nil, e
	}
	return preset, b.Whitelist, nil
}

// AddPublicDNS keeps explicit user labels and CIDR coverage authoritative. It
// adds missing endpoints, without changing servers, counters or rating policy.
func AddPublicDNS(book *Book) (added int, err error) {
	_, entries, e := PublicDNS()
	if e != nil {
		return 0, e
	}
	next := Book{Servers: append([]Entry(nil), book.Servers...), Whitelist: append([]Entry(nil), book.Whitelist...)}
	if e = Validate(&next); e != nil {
		return 0, e
	}
	existing := Compile(next.Whitelist)
	for _, entry := range entries {
		if existing.Lookup(netip.MustParseAddr(entry.IP)) != "" {
			continue
		}
		next.Whitelist = append(next.Whitelist, entry)
		added++
	}
	if e = Validate(&next); e != nil {
		return 0, e
	}
	*book = next
	return added, nil
}
