# Changelog

Changes are recorded here before publication. GitHub release assets use
`build-<run>-<attempt>-<commit>` identifiers; this file does not assign version
tags retroactively.

## Unreleased

### Changed

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
