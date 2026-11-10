# netmon

[![CI](https://github.com/xuserz/netmon/actions/workflows/release.yml/badge.svg)](https://github.com/xuserz/netmon/actions/workflows/release.yml)

Lightweight incoming network activity monitoring for Linux, written in Go.

See which IP addresses send traffic to your server, how much they send, and which
show signs of flooding or TCP port scanning. Run a single monitor or combine
multiple servers with encrypted peer-to-peer synchronization.

## Features

- Incoming IPv4/IPv6 packets, IP bytes, TCP SYN, UDP, and ICMP counters per source IP.
- A **0–100 suspicion score**, with reasons and automatic decay.
- Color terminal dashboard with live refresh, rankings, CPU, RAM, and loss diagnostics.
- **Full nodes** store shared statistics in SQLite and synchronize with other full nodes.
- **Forward nodes** capture and send observations using bounded RAM, without a local statistics database.
- Configurable retention, receive-ring memory, queue capacity, and database limits.
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
  retention: 24h
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

```sh
netmon top                          # Live color dashboard; q quits
netmon top --sort score             # Suspicion, highest first
netmon top --sort total             # Most incoming packets
netmon top --sort bytes
netmon top --sort syn
netmon top -n 100 --interval 1s
netmon top --once                   # Plain text snapshot
netmon top --no-color
netmon show 192.0.2.10              # Counters, score, reasons
netmon stats                       # Shared saved window on full nodes
netmon stats --local               # Bounded RAM view of this process
netmon list                        # All saved IPs; uses a temporary DB snapshot
netmon export --csv stats.csv
netmon nodes                       # Storage peer identities and errors
netmon status                      # Capture, queue and delivery diagnostics
```

Use `sudo` or an account in the `netmon` group (`dnsmon` on migrated installations). Global `--config FILE` and
`--db FILE` flags work before or after the command. Read commands never start
another capture process.

In the dashboard: arrows or `j/k` scroll, PageUp/PageDown navigate, Space pauses,
`r` refreshes, `c` toggles color, and `s` cycles the four rankings. `NO_COLOR` is
supported. Full-node views show committed shared data and can lag behind capture;
`--local` and forward-node views show a bounded sample of current-process activity.

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
Use the same secret key, retention, and rating settings across members. A full
node can set `network.capture: false` to serve only as storage.

Forwarding waits for a durable acknowledgement from one full node; replication
to additional full nodes follows asynchronously. Retries do not double-count
observations. During outages the RAM queue is bounded: overflow, expiry, process
crashes, or shutdown can lose observations. For local persistence, select `full`.

Follow the [network monitoring and cluster guide](docs/network.md) for complete
configurations, rating rules, failure behavior, and migration instructions.

## Configuration and operations

See [netmon.yaml](netmon.yaml) and the [configuration reference](docs/configuration.md).
After editing the configuration, run `netmon check --startup` and restart the service.
The default retained window is 24 hours; database capacity must match your traffic.
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
- [Legacy DNS peer-to-peer clustering](docs/cluster.md)
- [Operations and troubleshooting](docs/operations.md)
- [Development and testing](docs/development.md)
- [Changelog](CHANGELOG.md)

## License

[MIT](LICENSE) © 2026 xuserz. See [third-party notices](THIRD_PARTY_NOTICES.md).
