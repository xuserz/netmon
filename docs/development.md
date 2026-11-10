# Development

[Back to README](../README.md)

## Requirements

- Linux and Go 1.25+.
- A C compiler and Make; SQLite is compiled through CGO.
- Python 3 for installer, PTY, and paced load tests.
- `musl-tools` for static builds on Ubuntu/Debian.
- `iproute2`, `unshare`, and appropriate namespace/capture privileges for network tests.

Runtime dependencies are limited to `go-sqlite3`, `x/sys/unix`, and `yaml.v3`.
libpcap is not required. `CGO_ENABLED=0` is not supported by this implementation.

## Build

```sh
make build
./bin/dnsmon version
```

Regular builds require a compatible libc on the target system. Build on the same
or an older distribution when distributing a dynamically linked executable.

For a static Linux executable:

```sh
sudo apt install musl-tools
make static VERSION=local
file bin/dnsmon
```

Both build targets accept `VERSION`; the value is embedded in `dnsmon version`.
Release bundles include the binary, configuration, systemd unit, installers, and
README. Package a binary built for the selected architecture with:

```sh
./scripts/package-release.sh amd64 dist
```

## Tests

Run checks and build the executable before running the terminal tests:

```sh
make check
make build
python3 -m unittest discover -s scripts/tests -v
```

Go checks include `go vet` and the race detector. Python tests use temporary
filesystems and pseudo-terminals to exercise installation, rollback, live display,
keyboard controls, resize, suspension, and terminal restoration.

Packet tests cover DNS structure, UDP/TCP IPv4/IPv6, responses, fragmentation,
reassembly, retransmissions, sequence wrap, limits, and expiry. Storage and
monitor tests cover consistent live overlays, saturation, bounded asynchronous
writes, writer failure, shutdown, and SQLite size-limit rollback.

Fuzz the packet and DNS parsers separately:

```sh
go test ./internal/packet -fuzz FuzzFeed -fuzztime 10s
go test ./internal/packet -fuzz FuzzDNS -fuzztime 10s
```

### Network integration

Set `DNSMON_INTEGRATION=1` to enable real packet-socket tests. They require
`CAP_NET_RAW`; bridge tests also require network namespace and link-management
privileges. Without the required permissions, tests report explicit skips.

On systems supporting unprivileged user namespaces, run all tests in an
isolated network namespace:

```sh
unshare --user --map-root-user --net sh -c '
  ip link set lo up
  DNSMON_INTEGRATION=1 go test -race -count=1 ./...
'
```

`TestLivePacketPipeline` checks real UDP/TCP over IPv4/IPv6 through AF_PACKET/BPF
and verifies the resulting database. `TestLiveBridgeIngressCountsOnce` creates
an isolated veth/bridge path and verifies that 100 requests are counted exactly
once with the original source IP. It models bridge traversal without requiring
Docker or changing host firewall rules.

### Load tests

The deterministic in-memory workload exercises the parser, two bounded batches,
and SQLite with one Go processor. It does not measure NIC delivery or packet-socket
system calls:

```sh
go test -v ./internal/monitor -run TestLoad
go test ./internal/monitor -run '^$' -bench BenchmarkPipeline -benchmem
```

For paced traffic to a separate dnsmon process, build the binary and use an
isolated loopback network:

```sh
unshare --user --map-root-user --net sh -c '
  ip link set lo up
  python3 scripts/loadtest.py --rate 5000 --seconds 3
'
```

The script compares sent, observed, and stored counts and reports kernel drops,
process CPU as a percentage of one core, and RSS. Results depend on the host,
traffic mix, number of clients, and storage. They do not establish a fixed CPU
or memory guarantee for another VPS.

## Architecture

| Component | Location |
| --- | --- |
| CLI and command handling | `cmd/dnsmon` |
| AF_PACKET socket and classic BPF filter | `internal/capture` |
| DNS validation, TCP and IP reassembly | `internal/packet` |
| Capture loop and bounded asynchronous writer | `internal/monitor` |
| SQLite storage and live-overlay queries | `internal/store` |
| Read-only Unix diagnostic protocol | `internal/live` |
| Terminal rendering and keyboard handling | `internal/ui` |
| Configuration and startup checks | `internal/config`, `internal/diagnostic` |

Preserve deterministic counting, bounded memory, and the single-row-per-client
storage model when changing the code. Domains and packet contents must not be
persisted. Add regression tests for parser, concurrency, or lifecycle changes.

## Releases

The [GitHub Actions workflow](https://github.com/xuserz/dnsmon/blob/main/.github/workflows/release.yml) runs on pushes,
pull requests, and manual dispatch. It verifies dependencies, runs checks and
integration tests, then builds and tests static binaries on native amd64 and
arm64 runners.

Successful runs on the repository's default branch publish a release marked
`Latest`; other branches and pull requests produce temporary Actions artifacts.
Both architecture bundles must pass before publication. Release versions use
`build-<run>-<attempt>-<commit>` and require no manually created version tag.

Published assets:

- `dnsmon_linux_amd64.tar.gz`
- `dnsmon_linux_arm64.tar.gz`
- `install-release.sh`
- `SHA256SUMS`

Only the publishing job requests `contents: write`, using GitHub's built-in
token. No VPS credentials or SSH deployment are involved.
