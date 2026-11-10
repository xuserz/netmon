# Changelog

Changes are recorded here before publication. GitHub release assets use
`build-<run>-<attempt>-<commit>` identifiers; this file does not assign version
tags retroactively.

## Unreleased

### Fixed

- Restore the small SQLite cleanup reserve across bounded batches, and make the
  forced-full recovery regression retain maintenance pages needed by index
  rebalance while explicitly checking that the incoming batch hits SQLITE_FULL.

- Wait for a complete terminal frame containing the requested IP before checking
  trailing columns in PTY tests. Cover one-byte reads so a split risk column
  cannot intermittently fail native static-release CI.

- Continue service migration/update when `reset-failed` reports an unloaded unit;
  retain fatal start/health checks and rollback. Model inactive-unit collection
  in installer tests and show installation success only at the appropriate stage.

- Drain buffered PTY output after the tested process exits, so terminal
  restoration checks do not intermittently fail static-release CI. Add a
  deterministic fragmented-output regression and close test SQLite connections.

### Changed

- Rename dnsmon to netmon: executable, Go module/package paths, config/unit names,
  install paths, documentation, environment variables, and CI/release archives.
- Preserve database formats and authenticated cluster identities across the
  rename; support migration from standard dnsmon installations with config/path
  preservation, service-state transfer, and startup failure rollback.

- Fresh-install configurations now select network activity monitoring on all
  incoming ports. Existing configurations without `mode` retain DNS accounting;
  network counters use a separate database and do not reinterpret DNS totals.

- Update go-sqlite3 to v1.14.53 (SQLite 3.54.1), including the WAL-reset fix.
- Build CSV exports from private incremental backup snapshots with bounded
  deadlines and cleanup, keeping CSV reads off the live WAL.
- Refresh process health and kernel drop counters independently of capture,
  with explicit capture sample age, storage wait time, and oldest pending age.

- Replace per-packet receive calls with a bounded PACKET_MMAP TPACKET_V3 ring.
  Parse UDP directly from mapped packets and use kernel arrival timestamps.
- Prepare absolute counter targets once and safely replay them after transient
  SQLite failures, including uncertain commit acknowledgements. Bound retries
  with `write_retry_timeout`; keep fatal storage failures visible.
- Publish immutable live snapshots at most once per second on demand. Diagnostic
  requests no longer scan pending batches or run SQL; the dashboard marks stale
  snapshots during storage stalls.
- Store clients in a `WITHOUT ROWID` table with an atomic migration for existing
  databases. Retain exactly the same four fields and cumulative statistics.
- Cache a bounded number of confirmed client totals with `hot_cache_ips` to
  avoid repeatedly reading active clients before writing batches.
- Interpret `socket_buffer_mb` as the exact receive-ring allocation; it is no
  longer limited by `net.core.rmem_max`.

### Added

- Built-in INBOUND/REPLY/UNKNOWN header correlation, optional reply exclusion,
  bounded per-IP/node/minute target details, time-range show and JSON output.
- Incremental fixed-window scan/flood detection, replicated incident evidence,
  replay-safe fact IDs, forensic commands, decaying correlation in IP rankings,
  capacity cleanup and compact-copy verification. No external monitoring stack,
  metrics exporter, alerts or notifications.
- Telemetry v4 / detailed compact payload v2; legacy JSON/v1 remains readable.
  Change signed-update compatibility for a manual generation transition while
  retaining v3 heartbeat/update-control discovery.

- Opt-in publisher-signed network-cluster updates: relay release offers over
  authenticated v3 traffic, verify exact archive hashes and Ed25519 signatures,
  stage downloads outside capture, and serialize automatic installs through a
  selected full-node coordinator with restart cooldown. Add root update units,
  version/status diagnostics, explicit retry after failed installation, local
  installer locking, CI signing and compatibility declarations. Preserve opt-out,
  manual-only unsigned releases and pinned host trust keys.

- Offline provider attribution from a pinned CC0 IP-range snapshot: 67 provider
  lists, 45,643 merged provider/CIDR pairs. Show provider/category/range provenance
  in network views and CSV without API calls, capture-path work or SQLite rows.
  Keep cloud/CDN/bot/VPN/Tor attribution independent of TRUSTED manual whitelist
  status and suspicion. Add `providers [lookup IP]`, a local-file-only builder,
  release installation, hot reload, provenance manifest and upstream license.

- Versioned compact network observation payloads with varint counters and relative
  timestamps, reusing SQL identity/IP/minute columns. Preserve every stored sample
  field and all indexes; read legacy JSON and compact rows in the same database.
  Network v3 JSON messages and CSV semantics remain unchanged.
- `compact --output FILE` for stopped full nodes: convert an isolated copy in
  bounded batches, reclaim pages with VACUUM, verify sample/version/priority
  digests and SQLite integrity, and publish without replacing the source.
  Preserve ownership, counters, identities, cursors and cleanup metadata.

- Live node presence in network top, with n to switch to a scrollable node view;
  `nodes --watch`, `nodes --json`, and `top --nodes` on full and forward nodes.
  Show roles, names, authenticated links, last contact, RTT, sync gap and errors.
- Bounded idle heartbeats and incoming sensor discovery outside packet capture,
  without forward-node storage or heartbeat observations/ACKs. Merge node IDs,
  expire lost contacts, retain synchronization failures despite reachability,
  and mark offline saved records STALE instead of online.

- Capacity-based network history with `retention: 0s` by default. Delete oldest
  closed minute windows near the SQLite page cap, adjust totals, and retry full
  transactions without duplicating absolute counters or peer cursors.
- Durable replicated cleanup boundaries (network protocol v3), preventing stale
  nodes and forward queues from restoring capacity-evicted observations. Upgrade
  all members together; a small full node can shorten shared cluster history.
- Preserve existing data and node identities when disabling positive age expiry.
  Other policy changes still require a new database.
- Database/limit, WAL/files size, database-filesystem free space and estimated
  headroom in live/offline network top and status. Forward stays RAM-only.

- Reviewed offline public DNS preset: 185 exact IPv4/IPv6 endpoint labels from
  14 providers, with profile descriptions and official source links. Seed new
  installs and support explicit `whitelist import-dns` merging; preserve user
  descriptions, CIDR coverage and own-server entries, with no rating changes.

- Own-server and whitelist address books with IPv4/IPv6/CIDR descriptions,
  atomic `servers`/`whitelist` CLI editing, and live dashboard reloads.
- SERVER/WL tags and descriptions in network top/show/list/CSV. Local interface
  addresses and literal cluster endpoints provide server hints; explicit entries
  override them. Labels do not suppress counters or alter suspicion scores.
- Bounded local matching outside capture, protected catalog paths, installer
  preservation, concurrency tests, and live/process/export label regressions.

- Per-source incoming packet, byte, TCP/SYN, UDP, and ICMP counters with a
  deterministic 0–100 suspicion score, signal explanations, and time decay.
- Network storage roles: full replicas with retained minute observations, or
  bounded RAM-only forwarding without a local statistics database or spool.
- Authenticated network replication with idempotent observation snapshots,
  durable receive cursors, automatic exclusion of replication TCP ports,
  queue/loss diagnostics, and storage-only receivers.
- Network terminal rankings by suspicion, packets, bytes, and SYN; per-IP risk
  details and consistent CSV export. Configurable retention and rating policy.
- Process regressions for RAM forwarding, replica recovery and DNS isolation;
  counter replay/expiry/eviction, score/decay, queue bounds, and parser tests.

- Optional peer-to-peer clusters: every enabled node stores shared cumulative
  counters and exchanges bounded change pages over mutually authenticated TLS.
- Durable origin IDs and receive cursors, coalesced per-IP source feeds,
  transitive/idempotent counter merges, and seed-based peer discovery.
- `netmon cluster keygen`, `netmon nodes`, shared inspection/export defaults,
  `--local` overrides, and cluster status in the terminal dashboard.
- Three-node network/process regressions covering real capture, restarts,
  disconnected members, pagination, and authentication failures.

- Per-IP activity rankings: `top --sort rate` / `--sort minute`, `s` to cycle,
  and a bounded volatile cache controlled by `max_activity_ips`.
- SIGKILL/restart, writer-stall, packet-burst, activity eviction, and export
  isolation/cancellation regressions, including real-binary network scenarios.

- Regression tests for transaction replay, migration rollback, bounded caching,
  concurrent snapshot publication, and packet-ring metadata validation.
- MIT License, third-party notices, and a short contribution guide, included in
  release archives.

## Existing baseline

The implementation before the changes above includes passive UDP/TCP IPv4/IPv6
accounting, bounded TCP and IP reassembly, cumulative SQLite storage, an
interactive terminal dashboard, CLI inspection and CSV export, systemd
installation, and automatic static amd64/arm64 GitHub releases. No earlier
version numbers are inferred here.
