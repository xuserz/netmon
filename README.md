# dnsmon

[![CI](https://github.com/xuserz/dnsmon/actions/workflows/release.yml/badge.svg)](https://github.com/xuserz/dnsmon/actions/workflows/release.yml)

Lightweight DNS client accounting for Linux.

dnsmon counts incoming DNS queries per client IP and keeps cumulative counters
in SQLite. A background systemd service captures traffic; a terminal dashboard
shows live activity, resource usage, and capture health.

Each client has exactly one database row: **IP address, request count, first seen,
and last seen**. Domain names, individual queries, responses, and packet captures
are never written to disk.

## Features

- UDP and TCP DNS over IPv4 and IPv6.
- TCP stream reassembly, retransmission handling, and bounded IP fragment buffers.
- Color terminal dashboard with live counters, request rate, CPU, memory, and loss diagnostics.
- Batched SQLite writes, WAL readers, and configurable memory and database limits.
- CLI lookup, rankings, totals, CSV export, and startup checks.
- Static Linux binaries for **amd64** and **arm64**, with SQLite included.
- Passive capture on one interface, including the host side of Docker-published DNS.

## Install

The release installer targets **Ubuntu/Debian with systemd**. It requires
Linux 4.20+, `curl`, `tar`, and `sha256sum`. Go and a C compiler are only needed
when [building from source](docs/development.md).

```sh
curl -fsSL https://github.com/xuserz/dnsmon/releases/latest/download/install-release.sh | sudo sh
```

When running as root, use `sh` instead of `sudo sh`.

The installer selects the architecture, verifies the archive's SHA-256 checksum,
and installs the binary, service unit, and configuration. It preserves existing
configuration and statistics. Release files are also available on the
[Releases page](https://github.com/xuserz/dnsmon/releases).

## Quick start

1. Find the interface where client traffic enters the host:

   ```sh
   ip -br address
   ip route get 1.1.1.1
   ```

2. Review `/etc/dnsmon/config.yaml`. The installer attempts to select the interface
   from the default route. Verify it before starting the service:

   ```yaml
   interface: ens3
   destination_ip: ""
   port: 53
   ```

   Use the interface shown after `dev` in the route output. For Docker, select
   the ingress interface and the **published host port**, before DNAT.

3. Check the configuration and start the service:

   ```sh
   sudo dnsmon check --startup
   sudo systemctl enable --now dnsmon
   sudo dnsmon status
   sudo dnsmon top
   ```

Live counters appear as traffic arrives. SQLite is updated every 30 seconds by
default. Only `dnsmon run` starts packet capture; inspection commands never start
an additional monitor.

## Usage

```sh
dnsmon top                         # Interactive live dashboard
dnsmon top -n 100 --interval 1s     # More clients, faster refresh
dnsmon top --once                  # One committed SQLite snapshot
dnsmon top --no-color
dnsmon show 192.0.2.10
dnsmon show 2001:db8::10
dnsmon stats
dnsmon list
dnsmon export --csv stats.csv
dnsmon status
dnsmon check
```

Use `sudo` or an account in the `dnsmon` group to access installed statistics.
Global `--config FILE` and `--db FILE` options can appear before or after the command.

### Live dashboard

| Key | Action |
| --- | --- |
| `q`, `Ctrl+C` | Exit |
| `↑` / `↓`, `j` / `k` | Scroll |
| `PageUp` / `PageDown`, `Home` / `End` | Navigate the client list |
| Space | Pause or resume updates |
| `r` | Refresh |
| `c` | Toggle colors |

The dashboard refreshes every two seconds by default and supports up to 1,000
rows. `NO_COLOR` disables colors. Redirecting `top` to a file or pipe automatically
produces a single plain-text snapshot; `--once` selects that mode explicitly.

`LIVE` includes uncommitted counters from the running service. `STORED` uses
SQLite when the live feed is unavailable. Commands such as `stats`, `show`,
`list`, and `export` read committed data and may lag behind the live dashboard.

## Configuration

The configuration file is `/etc/dnsmon/config.yaml`. See
[dnsmon.yaml](dnsmon.yaml) for defaults and the
[configuration reference](docs/configuration.md) for all options.

After changing it:

```sh
sudo dnsmon check --startup
sudo systemctl restart dnsmon
```

Capture is limited to incoming traffic on one selected interface and port.
DoH, DoT, DNSCrypt, and encrypted DNS payloads are not decoded. For Docker,
multiple interfaces, VLANs, and TCP limitations, see
[capture scope](docs/configuration.md#capture-scope).

## Update and uninstall

Update to the latest published release:

```sh
sudo /usr/local/libexec/dnsmon/install-release.sh
```

The installer preserves configuration and data, restarts an active service, and
restores the previous binary and unit if the updated service fails its startup
health checks. An inactive service is not automatically enabled.

Uninstall the program:

```sh
sudo /usr/local/libexec/dnsmon/uninstall.sh
```

Uninstalling retains the database, configuration, and service account. See
[operations](docs/operations.md) for version selection, backups, and troubleshooting.

## Development

Source builds require **Go 1.25+**, a C compiler, and Make. Python 3 is used for
installer and terminal integration tests.

```sh
git clone https://github.com/xuserz/dnsmon.git
cd dnsmon
make build
make check
python3 -m unittest discover -s scripts/tests -v
```

Changes and pull requests are welcome. Include a description of the problem,
reproduction steps where applicable, and relevant tests. Follow the
[development guide](docs/development.md) for static builds, network integration
tests, and load testing.

GitHub Actions checks pushes and pull requests. Successful pushes to the default
branch publish tested amd64 and arm64 release bundles automatically.

## Documentation

- [Configuration and capture scope](docs/configuration.md)
- [Operations, storage, and troubleshooting](docs/operations.md)
- [Development, testing, and releases](docs/development.md)

## License

The repository does not currently declare a project license.
