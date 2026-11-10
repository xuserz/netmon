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
./bin/netmon version
```

Regular builds require a compatible libc on the target system. Build on the same
or an older distribution when distributing a dynamically linked executable.

For a static Linux executable:

```sh
sudo apt install musl-tools
make static VERSION=local
file bin/netmon
```

Both build targets accept `VERSION`; the value is embedded in `netmon version`.
Release bundles include the binary, configuration, systemd unit, installers, and
README, documentation, MIT License, third-party notices, changelog, and
contribution guide. Package a binary built for the selected architecture with:

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
writes, transient and uncertain commit replay, immutable snapshots under batch
reuse, confirmed-cache eviction, shutdown, migration preservation, and rollback
when a migration reaches the SQLite page limit. Tests also cover SQLite fix
version, export isolation and cleanup, SIGKILL recovery, bounded activity
windows/eviction, and a health heartbeat during a blocked writer.

Identity tests cover IPv4/IPv6/CIDR precedence, mapped addresses, strict catalog
validation, protected paths, atomic edits with preserved permissions, concurrent
writers, reloads, consistent export metadata, and server/whitelist independence.
PTY/process tests exercise adding labels while a dashboard stays open, old
catalog preservation during upgrades, and unchanged counters/risk after labeling.

Network-mode tests additionally cover deterministic score tiers/decay, bounded
queues, old ACKs racing with coalesced updates, eviction without count loss,
retention/replay, capacity eviction/SQLite-full retry, durable replicated cutoffs,
in-place age-expiry migration, storage metrics, transaction rollback, and policy mismatch. Process tests start
RAM-only senders and storage replicas, send non-DNS traffic, interrupt storage,
restart replicas, and verify delivered counters, reasons, CSV, and no sender DB.

Fuzz the packet and DNS parsers separately:

```sh
go test ./internal/observation -fuzz FuzzNetworkDecode -fuzztime 10s
go test ./internal/packet -fuzz FuzzFeed -fuzztime 10s
go test ./internal/packet -fuzz FuzzDNS -fuzztime 10s
go test ./internal/capture -fuzz FuzzRingFrame -fuzztime 10s
```

### Network integration

Set `NETMON_INTEGRATION=1` to enable real packet-socket tests. They require
`CAP_NET_RAW`; bridge tests also require network namespace and link-management
privileges. Without the required permissions, tests report explicit skips.

On systems supporting unprivileged user namespaces, run all tests in an
isolated network namespace:

```sh
unshare --user --map-root-user --net sh -c '
  ip link set lo up
  NETMON_INTEGRATION=1 go test -race -count=1 ./...
  NETMON_INTEGRATION=1 python3 -m unittest discover -s scripts/tests -v
'
```

`TestLivePacketPipeline` checks real UDP/TCP over IPv4/IPv6 through AF_PACKET/BPF/TPACKET_V3
and verifies the resulting database. `TestLiveBridgeIngressCountsOnce` creates
an isolated veth/bridge path and verifies that 100 requests are counted exactly
once with the original source IP. It models bridge traversal without requiring
Docker or changing host firewall rules. Python recovery tests run the actual
binary, kill/restart it after a confirmed flush, and block SQLite while feeding
a burst of packets. They verify live diagnostics, bounded buffers, recovery,
and preservation of confirmed counters. Cluster integration tests run three
real monitors, verify shared and local scopes, discover peers, and restart an
offline member without duplicating its historical contribution. Go tests also
cover transitive/idempotent merge, page boundaries, cursor rollback, TLS key
isolation, and change tracking while cluster networking is disabled.

### Load tests

The deterministic in-memory workload exercises the parser, two bounded batches,
and SQLite with one Go processor. It does not measure NIC delivery or packet-socket
system calls:

```sh
go test -v ./internal/monitor -run TestLoad
go test ./internal/monitor -run '^$' -bench BenchmarkPipeline -benchmem
```

For paced traffic to a separate netmon process, build the binary and use an
isolated loopback network:

```sh
unshare --user --map-root-user --net sh -c '
  ip link set lo up
  python3 scripts/loadtest.py --rate 5000 --seconds 3
  python3 scripts/loadtest.py --rate 5000 --seconds 3 --clients 2000 --live
  python3 scripts/loadtest.py --rate 5000 --seconds 3 --clients 2000 --live --burst-size 500
'
```

The script compares sent, observed, and stored counts and reports kernel drops,
process CPU as a percentage of one core, and RSS. Results depend on the host,
traffic mix, number of clients, and storage. They do not establish a fixed CPU
or memory guarantee for another VPS.

### Reference measurements

On 2026-11-10, a Ryzen 5 5600X Linux host with `GOMAXPROCS=1` observed and
stored all 15,000 UDP queries at 5,000/s from 2,000 source IPs while a client
polled live top at 20 requests/s. Kernel drops were zero; process CPU averaged
about 4–4.7% of one core and sampled RSS was about 18–22 MiB across dynamic
and static builds. This short local
loopback workload is a regression check, not a VPS capacity estimate.

With identical sorted text IPv6 keys and a ranking index, the fresh 100,000-row
layout fixture occupied 13,422,592 bytes with rowid and 9,334,784 bytes without
rowid (30.5% less). A migrated file retains freed pages for reuse; it does not
automatically shrink to the fresh-layout size.

## Architecture

| Component | Location |
| --- | --- |
| CLI and command handling | `cmd/netmon` |
| PACKET_MMAP TPACKET_V3 ring and classic BPF filter | `internal/capture` |
| DNS validation, TCP and IP reassembly | `internal/packet` |
| Capture loop and bounded asynchronous writer | `internal/monitor` |
| Peer replication, TLS, membership, and per-origin merges | `internal/cluster` |
| SQLite storage and live-overlay queries | `internal/store` |
| Read-only Unix diagnostic protocol | `internal/live` |
| Terminal rendering and keyboard handling | `internal/ui` |
| Configuration and startup checks | `internal/config`, `internal/diagnostic` |

Capture updates bounded atomic counter slots under a short mutex. A single
writer snapshots a frozen batch, prepares absolute targets, and retries only
those same targets until acknowledged or failed. A separate publisher copies
atomic slots without the capture mutex and merges them with a read-only WAL
snapshot. It validates the writer revision before publishing an immutable result.
Socket handlers only read that result and bounded health counters.

Operational health runs independently of capture. Parser state crosses to the
health goroutine only as immutable samples; it never reads live Engine maps.
Activity keeps 61 atomic per-second buckets per retained IP; the capture thread
owns its bounded LRU index, and publication reads atomic slots without scanning
a map under the capture mutex. Activity and lifetime snapshots have independent
publication, so a writer retry does not freeze the activity view.

The confirmed-client LRU is bounded by `hot_cache_ips`; it caches only successful
writes. `WITHOUT ROWID` uses the text IP primary key directly. See the upstream
[SQLite design notes](https://www.sqlite.org/withoutrowid.html) and
[kernel packet-ring documentation](https://www.kernel.org/doc/html/latest/networking/packet_mmap.html).
Compare fresh database layouts with:

```sh
go test -v ./internal/store -run TestLayoutFootprint
```

Preserve deterministic counting, bounded memory, and the single-row-per-client
storage model when changing the code. Optional cluster metadata is documented
in the cluster guide; do not add request history. Domains and packet contents must not be
persisted. Add regression tests for parser, concurrency, or lifecycle changes.

## Releases

The [GitHub Actions workflow](https://github.com/xuserz/netmon/blob/main/.github/workflows/release.yml) runs on pushes,
pull requests, and manual dispatch. It verifies dependencies, runs checks and
integration tests, then builds and tests static binaries on native amd64 and
arm64 runners.

Successful runs on the repository's default branch publish a release marked
`Latest`; other branches and pull requests produce temporary Actions artifacts.
Both architecture bundles must pass before publication. Release versions use
`build-<run>-<attempt>-<commit>` and require no manually created version tag.

Published assets:

- `netmon_linux_amd64.tar.gz`
- `netmon_linux_arm64.tar.gz`
- `install-release.sh`
- `SHA256SUMS`

Only the publishing job requests `contents: write`, using GitHub's built-in
token. No VPS credentials or SSH deployment are involved.

### Network-mode process and load tests

Run only inside an isolated network namespace, with the built binary:

```sh
sudo unshare --net sh -c 'ip link set lo up; NETMON_INTEGRATION=1 python3 -m unittest discover -s scripts/tests -p test_network.py -v'
sudo unshare --net sh -c 'ip link set lo up; python3 scripts/loadtest.py --mode network --rate 5000 --seconds 3 --clients 2000 --live --burst-size 250'
```

The network load test uses non-DNS UDP payloads and checks packet counts, unique
IPs, kernel drops, concurrent dashboard snapshots, CPU, and RSS. DNS-mode load
figures do not establish network-mode performance; neither is a VPS capacity
guarantee. Forward nodes can lose unacknowledged RAM; tests deliberately verify
outage/recovery separately from persistent storage replication.

Network payload storage has round-trip, mixed-format replay, malformed/truncated
input, integer-boundary and fuzz coverage. Compaction tests compare canonical
sample/version/priority digests, per-IP views, totals, node identity/epoch and
peer cursors; they check source-file preservation and failed-publication cleanup.
The process test stops the monitor, compacts, switches paths and resumes counters.

Measure the codec independently with:

```sh
go test ./internal/network -run '^$' -bench '^BenchmarkSampleCodec$' -benchmem
```

`TestCompactCopyPreservesHistoryIdentityCursorsAndOriginalFile` logs a storage
comparison for 5000 synthetic node/IP/minute observations. Both baseline and
output are vacuumed; it is a reproducible workload comparison, not a prediction
for another server's traffic. The existing seven indexes are included.
