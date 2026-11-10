# Offline provider labels

[Back to README](../README.md)

Network views can identify source IP ranges from the local
[rezmoss/cloud-provider-ip-addresses](https://github.com/rezmoss/cloud-provider-ip-addresses)
dataset. No HTTP API, DNS lookup or background download runs during monitoring
or viewing. The catalog ships with release archives and is updated by the
release installer. Go is not required on the server.

The bundled snapshot is dated **2026-11-10**, upstream commit
`98befa4548b486fee5332e92b0a6e1b0ab55f31e`: 67 provider lists and 45,643
provider/CIDR pairs, about 167 KiB compressed. We use each provider's merged
IPv4/IPv6 ranges; region/service duplication is removed while provider overlap
is retained. Provider names, source references and dates remain in the catalog.
The upstream data is CC0-1.0; see [license](../data/providers/LICENSE) and
[manifest with SHA-256](../data/providers/manifest.json).

## What the labels mean

| Tag | Meaning |
| --- | --- |
| `TRUSTED` | Explicit whitelist match in your local address book, including any installed DNS endpoint preset. |
| `SERVER` / `SERVER+WL` | Your own server/node hints, optionally also whitelisted. |
| `CLOUD` | Range listed for a hosting/cloud provider. |
| `CDN` | Range listed for a CDN or edge provider. |
| `BOT` | Range in a crawler/bot provider's published list. |
| `MONITORING` | Range listed for a monitoring service. |
| `SERVICE` | Other service provider ranges. |
| `RELAY`, `VPN`, `TOR` | Relay, VPN or Tor exit lists. |

Categories are netmon display classifications, not upstream reputation scores.
**A provider match never adds the IP to your whitelist, reduces its suspicion
score or removes packets from statistics.** Cloud tenants can send abusive
traffic. Some upstream lists use BGP/ASN announcements rather than official
service-specific ranges. A range match does not authenticate a bot, a service
or the actual sender of a spoofed packet. Unknown IPs remain unclassified.

`top` shows the tag and provider names in its description column. Manual
server/whitelist tags take priority. Narrow terminals abbreviate tags and clip
descriptions; `show` displays all matches with their CIDRs and catalog revision.
For each provider the most specific matching prefix wins; matches from different
providers are all preserved, ordered from most specific range first.

```sh
netmon providers                      # Installed snapshot, date and revision
netmon providers lookup 104.16.1.2    # Lookup even without a statistics database
netmon top
netmon show 104.16.1.2                # Requires observed IP statistics
sudo netmon whitelist add 203.0.113.20 "My uptime monitor"
```

## Configuration and storage

```yaml
providers_file: /usr/share/netmon/providers.json.gz
```

Missing configuration uses that default, including on existing installations.
An empty value (`providers_file: ""`) disables provider labels. A missing file
also leaves IPs unclassified. An invalid file produces an explicit view error;
a running dashboard retains its last successful snapshot and shows the error.
Capture and writes are independent of catalog loading.

The parsed CIDR index is cached in the viewing process and reloaded when the
file changes. Loading and lookups happen outside packet capture. Labels are
current attribution, including when viewing old traffic; historical ownership
is not recorded. No catalog records or per-IP provider rows are written to
SQLite. CSV appends `providers` (JSON array of matches), `provider_revision` and
`provider_date`, frozen for the duration of the export.

Full and forward nodes both support labels. Each server installs its own copy;
catalogs and whitelist decisions are not synchronized through network peers.
The catalog occupies a small static file even on forward nodes. The release
installer replaces its managed file, but preserves your configuration and
address book. A custom `providers_file` is not replaced by the installer.

## Rebuild from a local upstream checkout

The builder reads local files only. To first download a checkout with the
required range/metadata files, without the upstream aggregate JSON:

```sh
git clone --depth 1 --filter=blob:none --no-checkout \
  https://github.com/rezmoss/cloud-provider-ip-addresses.git /tmp/provider-ranges
git -C /tmp/provider-ranges sparse-checkout set --no-cone \
  '/summary.json' '/LICENSE' '/*/*_meta.json' '/*/*_ips_merged.txt'
git -C /tmp/provider-ranges checkout
```

From a netmon source checkout, use Python 3.9+ to build and review the catalog:

```sh
python3 scripts/build-provider-catalog.py \
  --source-dir /tmp/provider-ranges \
  --revision "$(git -C /tmp/provider-ranges rev-parse HEAD)" \
  --output /tmp/providers.json.gz --manifest /tmp/providers-manifest.json
```

Release installations also include the builder at
`/usr/local/libexec/netmon/build-provider-catalog.py`. It uses installed provider
definitions by default. A newly added upstream provider requires a reviewed
name/category in a JSON definitions file passed with `--definitions FILE`;
unknown providers are rejected. Missing files, inconsistent dates/counts and
invalid prefixes abort before replacing the existing output.

Install a reviewed build atomically; open dashboards reload it on refresh:

```sh
sudo install -m 0644 /tmp/providers.json.gz /usr/share/netmon/.providers.next
sudo mv /usr/share/netmon/.providers.next /usr/share/netmon/providers.json.gz
netmon providers
```

For a persistent custom catalog, install it to another absolute path and set
`providers_file` accordingly. No automatic network refresh is scheduled.
