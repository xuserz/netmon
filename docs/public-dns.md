# Public DNS address labels

The release snapshot was checked against the official sources below on **2026-11-10**. It contains 185 exact endpoint IPs from 14 providers, including IPv6 and filtering profiles. It is a maintained selection, not an exhaustive directory of every public resolver.

These labels match **source IPs** in network statistics. A published resolver endpoint may differ from the recursive egress IPs used to query your server. Matching an address does not establish the sender’s identity, and the preset does not include entire provider/cloud networks. NextDNS entries cover its four shared bootstrap endpoints; personalized profiles are not represented by broad network ranges. Mullvad endpoints use encrypted DNS.

## Installation and updates

New installations seed `/etc/netmon/ip-labels.yaml` from the bundled catalog. The installer preserves an existing catalog. After updating the executable, explicitly merge the snapshot with:

```sh
sudo netmon whitelist import-dns
netmon whitelist list
```

The command adds only endpoints not already covered by an existing whitelist entry. Your exact descriptions, CIDR coverage, and own-server entries remain authoritative. Repeating the import adds nothing unless an endpoint was removed or the executable has a newer snapshot. A manually removed preset endpoint is added again if you explicitly import it again. Import uses the same exclusive lock, validation, size limits and atomic replacement as other catalog edits. An invalid/full catalog stays unchanged.

The snapshot is embedded in the executable: import makes no network requests and never opens a statistics database. It also works on forward nodes. `top` reloads the file on its next refresh. No counter, rating, capture rule, firewall rule or database schema changes. Labels stay local to each inspection node.

Update snapshots through reviewed releases rather than background downloads. To change a description or remove an endpoint:

```sh
sudo netmon whitelist add 1.1.1.1 "Cloudflare resolver"
sudo netmon whitelist remove 1.1.1.1
```

## Providers and profiles

### Google Public DNS

Official sources: [source 1](https://developers.google.com/speed/public-dns/docs/using).

| Profile | IPv4 | IPv6 |
| --- | --- | --- |
| standard | `8.8.8.8`, `8.8.4.4` | `2001:4860:4860::8888`, `2001:4860:4860::8844` |

### Cloudflare DNS

Official sources: [source 1](https://developers.cloudflare.com/1.1.1.1/ip-addresses/).

| Profile | IPv4 | IPv6 |
| --- | --- | --- |
| standard | `1.1.1.1`, `1.0.0.1` | `2606:4700:4700::1111`, `2606:4700:4700::1001` |
| malware | `1.1.1.2`, `1.0.0.2` | `2606:4700:4700::1112`, `2606:4700:4700::1002` |
| family | `1.1.1.3`, `1.0.0.3` | `2606:4700:4700::1113`, `2606:4700:4700::1003` |

### Quad9

Official sources: [source 1](https://quad9.net/service/service-addresses-and-features/).

| Profile | IPv4 | IPv6 |
| --- | --- | --- |
| secured | `9.9.9.9`, `149.112.112.112` | `2620:fe::fe`, `2620:fe::9` |
| secured ECS | `9.9.9.11`, `149.112.112.11` | `2620:fe::11`, `2620:fe::fe:11` |
| unfiltered | `9.9.9.10`, `149.112.112.10` | `2620:fe::10`, `2620:fe::fe:10` |

### AdGuard DNS

Official sources: [source 1](https://adguard-dns.io/en/public-dns.html).

| Profile | IPv4 | IPv6 |
| --- | --- | --- |
| default | `94.140.14.14`, `94.140.15.15` | `2a10:50c0::ad1:ff`, `2a10:50c0::ad2:ff` |
| unfiltered | `94.140.14.140`, `94.140.14.141` | `2a10:50c0::1:ff`, `2a10:50c0::2:ff` |
| family | `94.140.14.15`, `94.140.15.16` | `2a10:50c0::bad1:ff`, `2a10:50c0::bad2:ff` |

### OpenDNS

Official sources: [source 1](https://www.opendns.com/setupguide/), [source 2](https://www.cisco.com/c/en/us/td/docs/security/asa/asa923/configuration/firewall/asa-923-firewall-config/access-umbrella.pdf).

| Profile | IPv4 | IPv6 |
| --- | --- | --- |
| standard | `208.67.222.222`, `208.67.220.220` | `2620:119:35::35`, `2620:119:53::53` |
| FamilyShield | `208.67.222.123`, `208.67.220.123` | — |

### Yandex DNS

Official sources: [source 1](https://dns.yandex.ru/).

| Profile | IPv4 | IPv6 |
| --- | --- | --- |
| basic | `77.88.8.8`, `77.88.8.1` | `2a02:6b8::feed:ff`, `2a02:6b8:0:1::feed:ff` |
| safe | `77.88.8.88`, `77.88.8.2` | `2a02:6b8::feed:bad`, `2a02:6b8:0:1::feed:bad` |
| family | `77.88.8.7`, `77.88.8.3` | `2a02:6b8::feed:a11`, `2a02:6b8:0:1::feed:a11` |

### CleanBrowsing

Official sources: [source 1](https://cleanbrowsing.org/filters).

| Profile | IPv4 | IPv6 |
| --- | --- | --- |
| security | `185.228.168.9`, `185.228.169.9` | `2a0d:2a00:1::2`, `2a0d:2a00:2::2` |
| adult | `185.228.168.10`, `185.228.169.11` | `2a0d:2a00:1::1`, `2a0d:2a00:2::1` |
| family | `185.228.168.168`, `185.228.169.168` | `2a0d:2a00:1::`, `2a0d:2a00:2::` |

### Control D

Official sources: [source 1](https://docs.controld.com/docs/free-dns), [source 2](https://docs.controld.com/docs/control-d-ip-ranges).

| Profile | IPv4 | IPv6 |
| --- | --- | --- |
| unfiltered | `76.76.2.0`, `76.76.10.0` | `2606:1a40::`, `2606:1a40:1::` |
| malware | `76.76.2.1`, `76.76.10.1` | `2606:1a40::1`, `2606:1a40:1::1` |
| ads and tracking | `76.76.2.2`, `76.76.10.2` | `2606:1a40::2`, `2606:1a40:1::2` |
| social | `76.76.2.3`, `76.76.10.3` | `2606:1a40::3`, `2606:1a40:1::3` |
| family | `76.76.2.4`, `76.76.10.4` | `2606:1a40::4`, `2606:1a40:1::4` |
| uncensored | `76.76.2.5`, `76.76.10.5` | `2606:1a40::5`, `2606:1a40:1::5` |
| OISD Full | `76.76.2.32`, `76.76.10.32` | `2606:1a40::32`, `2606:1a40:1::32` |
| OISD Basic | `76.76.2.33`, `76.76.10.33` | `2606:1a40::33`, `2606:1a40:1::33` |
| StevenBlack | `76.76.2.35`, `76.76.10.35` | `2606:1a40::35`, `2606:1a40:1::35` |
| 1Hosts Lite | `76.76.2.38`, `76.76.10.38` | `2606:1a40::38`, `2606:1a40:1::38` |
| 1Hosts Pro | `76.76.2.39`, `76.76.10.39` | `2606:1a40::39`, `2606:1a40:1::39` |
| 1Hosts Xtra | `76.76.2.48`, `76.76.10.48` | `2606:1a40::48`, `2606:1a40:1::48` |
| Hagezi Light | `76.76.2.37`, `76.76.10.37` | `2606:1a40::37`, `2606:1a40:1::37` |
| Hagezi Normal | `76.76.2.40`, `76.76.10.40` | `2606:1a40::40`, `2606:1a40:1::40` |
| Hagezi Pro | `76.76.2.41`, `76.76.10.41` | `2606:1a40::41`, `2606:1a40:1::41` |
| Hagezi Pro Plus | `76.76.2.42`, `76.76.10.42` | `2606:1a40::42`, `2606:1a40:1::42` |
| Hagezi Ultimate | `76.76.2.45`, `76.76.10.45` | `2606:1a40::45`, `2606:1a40:1::45` |
| Hagezi TIF | `76.76.2.46`, `76.76.10.46` | `2606:1a40::46`, `2606:1a40:1::46` |
| AdGuard Filter | `76.76.2.44`, `76.76.10.44` | `2606:1a40::44`, `2606:1a40:1::44` |
| free bootstrap | `76.76.2.11`, `76.76.10.11` | `2606:1a40::11`, `2606:1a40:1::11` |
| secure bootstrap | `76.76.2.22`, `76.76.10.22` | `2606:1a40::22`, `2606:1a40:1::22` |

### DNS.SB

Official sources: [source 1](https://dns.sb/).

| Profile | IPv4 | IPv6 |
| --- | --- | --- |
| standard | `185.222.222.222`, `45.11.45.11` | `2a09::`, `2a11::` |

### DNS.WATCH

Official sources: [source 1](https://dns.watch/).

| Profile | IPv4 | IPv6 |
| --- | --- | --- |
| standard | `84.200.69.80`, `84.200.70.40` | `2001:1608:10:25::1c04:b12f`, `2001:1608:10:25::9249:d69b` |

### AliDNS

Official sources: [source 1](https://www.alibabacloud.com/help/en/dns/free-service-disclaimer).

| Profile | IPv4 | IPv6 |
| --- | --- | --- |
| public | `223.5.5.5`, `223.6.6.6` | `2400:3200::1`, `2400:3200:baba::1` |

### Mullvad DNS

Official sources: [source 1](https://mullvad.net/en/help/dns-over-https-and-dns-over-tls).

| Profile | IPv4 | IPv6 |
| --- | --- | --- |
| standard | `194.242.2.2` | `2a07:e340::2` |
| adblock | `194.242.2.3` | `2a07:e340::3` |
| base | `194.242.2.4` | `2a07:e340::4` |
| extended | `194.242.2.5` | `2a07:e340::5` |
| family | `194.242.2.6` | `2a07:e340::6` |
| all | `194.242.2.9` | `2a07:e340::9` |

### NextDNS

Official sources: [source 1](https://github.com/nextdns/nextdns/blob/master/run.go).

| Profile | IPv4 | IPv6 |
| --- | --- | --- |
| anycast bootstrap | `45.90.28.0`, `45.90.30.0` | `2a07:a8c0::`, `2a07:a8c1::` |

### DNSPod

Official sources: [source 1](https://cloud.tencent.com/document/product/302/110786).

| Profile | IPv4 | IPv6 |
| --- | --- | --- |
| public | `119.29.29.29` | `2402:4e00::`, `2402:4e00:1::` |

## Maintaining the snapshot

The reviewed source of truth is [`internal/identity/data/public-dns.json`](../internal/identity/data/public-dns.json). Keep its verification date and provider source links current; update the bundled `ip-labels.yaml` and this table together. Tests reject duplicate/invalid endpoint entries and drift between the embedded snapshot and the fresh-install catalog. Do not add large provider ranges just to label services or infer their ownership.
