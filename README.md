# netmon

[![CI](https://github.com/xuserz/netmon/actions/workflows/release.yml/badge.svg)](https://github.com/xuserz/netmon/actions/workflows/release.yml)

Lightweight incoming network activity monitoring for Linux, written in Go.

See which IP addresses send traffic to your server, how much they send, and which
show signs of flooding or TCP port scanning. Run a single monitor or combine
multiple servers with encrypted peer-to-peer synchronization.

## Features

- Incoming IPv4/IPv6 packets, IP bytes, TCP SYN, UDP, and ICMP counters per source IP.
- Incoming/reply/unknown classes and bounded port/protocol/node history.
- Built-in cross-node scan detection and replicated incident evidence.
- A **0–100 suspicion score**, with reasons and automatic decay.
- Color terminal dashboard with live refresh, rankings, CPU, RAM, and loss diagnostics.
- **Full nodes** store shared statistics in SQLite and synchronize with other full nodes.
- **Forward nodes** capture and send observations using bounded RAM, without a local statistics database.
- Keep history until the database fills, then remove oldest minute windows first.
- Live database/WAL size, capacity, filesystem free space and write headroom.
- Offline cloud/CDN/bot/provider labels, separate from your explicit TRUSTED whitelist.
- Opt-in signed cluster updates with a coordinator and a separate privileged installer.
- Passive PACKET_MMAP capture before Docker NAT; no firewall changes or automatic blocking.
- Static **amd64/arm64** releases with SQLite included; Go is not required on the server.
- Legacy DNS query accounting remains available through `mode: dns`.

The score is an explainable heuristic, not a probability that an IP is malicious.
High traffic can be legitimate, and UDP/SYN source addresses can be spoofed.
Review the evidence before using exported data in a blocklist.

## Install

Ubuntu/Debian with systemd, Linux 4.20+, `curl`, `tar`, and `sha256sum`:

```sh
curl -fsSL https://github.com/xuserz/netmon/releases/latest/download/install-release.sh | sudo sh
```

As root, use `sh` instead of `sudo sh`. The installer selects your architecture,
checks the SHA-256 checksum, and preserves existing configuration and statistics.
Download bundles directly from [Releases](https://github.com/xuserz/netmon/releases).

## Upgrading from dnsmon

The project is now **netmon**. Fresh installs use `netmon`, `netmon.service`,
`/etc/netmon/config.yaml`, and `/var/lib/netmon`.

The new release installer detects a standard dnsmon installation and migrates
its service automatically. It retains the original config, key, databases,
identities, data paths, and account. Only the active service changes to netmon;
failed startup restores dnsmon. Custom service commands/accounts require manual
migration. See [migration details](docs/operations.md#rename-from-dnsmon).

Use the new download URL above after the first netmon release is published;
older releases contain differently named binaries/archives.

## Quick start

Find the interface carrying incoming client traffic:

```sh
ip -br address
ip route get 1.1.1.1
```

Review `/etc/netmon/config.yaml`; select the interface after `dev`, for example:

```yaml
mode: network
interface: ens3
storage:
  mode: full
  retention: 0s
```

Then start the service:

```sh
sudo netmon check --startup
sudo systemctl enable --now netmon
sudo netmon status
sudo netmon top
```

Fresh installations use network mode. **Existing configurations without `mode`
keep DNS mode.** Add `mode: network` to switch. Network counters use a separate
`stats.db.network.db` database; previous DNS statistics remain intact.

On Docker hosts choose the external ingress interface before DNAT. Only traffic
crossing the selected interface is observed. A packet counter does not confirm
that the server accepted a request or established a connection.

## Commands

For [traffic classes, port history and incident evidence](docs/forensics.md), use
`netmon show IP --since 24h --json` and `netmon incidents --since 168h`.

```sh
netmon top                          # Live color dashboard; q quits
netmon top --sort score             # Suspicion, highest first
netmon top --sort total             # Most incoming packets
netmon top --sort bytes
netmon top --sort syn
netmon top -n 100 --interval 1s
netmon top --once                   # Plain text snapshot
netmon top --no-color
netmon providers                    # Local provider catalog date/revision
netmon providers lookup 104.16.1.2  # Offline range attribution
netmon updates status               # Signed rollout status and configuration
netmon show 192.0.2.10              # Counters, score, reasons
netmon stats                       # Shared saved window on full nodes
netmon stats --local               # Bounded RAM view of this process
netmon list                        # All saved IPs; uses a temporary DB snapshot
netmon export --csv stats.csv
# Stopped full node only: verified compact copy, original retained
netmon compact --output /var/lib/netmon/stats-packed.network.db
netmon nodes                       # Online/offline nodes, roles, links and errors
netmon nodes --watch               # Live node dashboard
netmon nodes --json                # Machine-readable contact state
netmon top --nodes                 # Start top on the node view
netmon status                      # Capture, queue and delivery diagnostics
```

Use `sudo` or an account in the `netmon` group (`dnsmon` on migrated installations). Global `--config FILE` and
`--db FILE` flags work before or after the command. Read commands never start
another capture process.

In the dashboard: arrows or `j/k` scroll, PageUp/PageDown navigate, Space pauses,
`r` refreshes, `c` toggles color, `s` cycles the four rankings, and `n` switches
between IP activity and node connections. `NO_COLOR` is
supported. Full-node views show committed shared data and can lag behind capture;
`--local` and forward-node views show a bounded sample of current-process activity.

Network dashboards show how many known remote nodes are online. The node view
includes full/forward roles, names, addresses, incoming/outgoing links, last
contact, request RTT, synchronization version gap, and connection/storage errors.
Idle authenticated heartbeats keep forward sensors visible without generating
observations or opening a sensor database. Offline full-node reads mark saved
peers **STALE**, rather than claiming they are online. See
[node presence](docs/network.md#node-presence-and-connections) for state meanings
and cache bounds.

New network observations use a compact binary payload, with ID, node, IP and
minute stored once in their existing SQL columns. Minute detail, counters, risk
evidence and indexes remain intact. Current telemetry uses v4; see
[forensic history and migration](docs/forensics.md).
Existing JSON observations are read alongside compact records. Updating the
executable reduces growth of new history; reclaiming existing files is an explicit
maintenance operation. See [lossless database compaction](docs/operations.md#compact-network-history)
for the verified-copy workflow and path switch. Older executables cannot read the
new payload format; keep a backup compatible with the executable you intend to run.

## Own servers and whitelist

In network mode, `top`, `show`, `list`, and CSV display **SERVER**, **WL**, or
**SERVER+WL** beside matching source IPs, with your server/service description.
The selected interface's local addresses and literal-IP cluster endpoints are
recognized as own-server hints; explicit server entries take precedence.

```sh
sudo netmon servers add 192.0.2.10 "DNS node EU"
sudo netmon whitelist add 198.51.100.20 "Uptime Kuma"
sudo netmon whitelist add 2001:db8:1234::/48 "Monitoring network"
netmon servers list
netmon whitelist list
sudo netmon whitelist remove 198.51.100.20
```

New installations include **185 exact IPv4/IPv6 addresses from 14 public DNS
providers**, with provider and filtering-profile descriptions. Existing catalogs
are preserved on upgrade. To merge the bundled selection without overwriting
your entries or CIDR coverage:

```sh
sudo netmon whitelist import-dns
```

See the [DNS catalog and official sources](docs/public-dns.md). Resolver endpoint
IPs can differ from recursive egress IPs; the selection does not cover every
source that a provider might use to query your server.

The address book is `/etc/netmon/ip-labels.yaml` (`labels_file` in config).
Descriptions refresh in a running `top` without restarting capture. Adding an
entry does not create fake traffic rows. Whitelist labels retain all counters
and the observed suspicion score; they do not automatically suppress activity.
A SERVER label alone does not put an address in the whitelist.

Descriptions are local to the machine displaying/exporting statistics. Deploy
the same catalog on other nodes when you want identical labels. There are no
external hosting/GeoIP/WHOIS queries. For NAT, hostname endpoints, or forward
nodes without an advertised address, enter the actual IPs with `servers add`.

See [address-book details](docs/network.md#own-servers-and-whitelist) for matching,
permissions, bounds, and live reload behavior.

## Multiple servers and storage roles

Every **full** node keeps a replica of the shared retained statistics. There is
no primary server or external database. A **forward** node sends its own
observations to a full node and keeps no SQLite database or disk spool.

```yaml
mode: network
storage:
  mode: forward
  queue_memory_mb: 8
cluster:
  enabled: true
  name: edge-1
  key_file: /etc/netmon/cluster.key
  peers: ["https://storage.example.net:9845"]
```

Forward nodes make outbound connections and do not need an advertised listener.
With `retention: 0s`, history has no age limit. As `max_database_mb` is reached,
full nodes remove the oldest closed minute windows first, update totals, and
reuse SQLite pages. The cleanup boundary propagates to all full nodes so stale
replicas cannot restore deleted history. A smaller full node can therefore
shorten the shared history for the cluster. WAL space is additional.

`top` shows DB size/limit, WAL and total file sizes, filesystem free space, and
estimated write headroom before cleanup. On a forward node, it shows **DB
disabled** and a local RAM sample: IPs remain until cache eviction or restart,
not for a fixed retention period. View the full node for saved cluster history.

Use the same secret key, retention, and rating settings across members, including
forward nodes. A full
node can set `network.capture: false` to serve only as storage.

Forwarding waits for a durable acknowledgement from one full node; replication
to additional full nodes follows asynchronously. Retries do not double-count
observations. During outages the RAM queue is bounded: overflow, expiry, process
crashes, or shutdown can lose observations. For local persistence, select `full`.

Follow the [network monitoring and cluster guide](docs/network.md) for complete
configurations, rating rules, failure behavior, and migration instructions.

## Configuration and operations

See [offline provider labels](docs/providers.md) for local range matching,
TRUSTED whitelist behavior and catalog updates without an API.

See [netmon.yaml](netmon.yaml) and the [configuration reference](docs/configuration.md).
After editing the configuration, run `netmon check --startup` and restart the service.
History has no age limit by default; the database cap controls when oldest windows
are removed. Explicit positive retention values still expire observations by age.
For a 20 GiB main-database cap, set `max_database_mb: 20480`; WAL is additional.

Update:

```sh
sudo /usr/local/libexec/netmon/install-release.sh
```

Uninstall the program while retaining configuration and data:

```sh
sudo /usr/local/libexec/netmon/uninstall.sh
```

See [operations](docs/operations.md) for backups and troubleshooting. The installer
preserves existing configuration, so updates do not automatically change modes.

## Development

Source builds require **Go 1.25+**, a C compiler, Make, and Python 3 for integration tests.

```sh
git clone https://github.com/xuserz/netmon.git
cd netmon
make build
make check
python3 -m unittest discover -s scripts/tests -v
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and the [development guide](docs/development.md).
GitHub Actions tests pushes and pull requests; successful default-branch pushes
publish static amd64 and arm64 release bundles.

## Documentation

- [Network mode, suspicion rating, and storage roles](docs/network.md)
- [Configuration and capture scope](docs/configuration.md)
- [Offline provider labels and catalog updates](docs/providers.md)
- [Signed cluster updates and first-time setup](docs/updates.md)
- [Traffic classes, port history and incident evidence](docs/forensics.md)
- [Legacy DNS peer-to-peer clustering](docs/cluster.md)
- [Operations and troubleshooting](docs/operations.md)
- [Development and testing](docs/development.md)
- [Changelog](CHANGELOG.md)

## License

[MIT](LICENSE) © 2026 xuserz. See [third-party notices](THIRD_PARTY_NOTICES.md).
