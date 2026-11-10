# Operations

[Back to README](../README.md)

## Service management

```sh
sudo systemctl enable --now dnsmon
sudo systemctl restart dnsmon
sudo systemctl stop dnsmon
sudo dnsmon status
sudo dnsmon check
sudo journalctl -u dnsmon -b -n 50 --no-pager -o cat
```

The service runs as `dnsmon` with `CAP_NET_RAW`. Its default writable state
directory is `/var/lib/dnsmon`; configuration is in `/etc/dnsmon/config.yaml`.
A custom database directory requires appropriate ownership and systemd
`ReadWritePaths=` configuration.

Read commands require access to the configuration, database, and diagnostic
socket. Use `sudo`, or grant a local user membership in the service group:

```sh
sudo usermod -aG dnsmon "$USER"
```

Log out and back in for group membership to take effect.

## Live and committed data

The dashboard reads bounded, read-only snapshots through `<database>.sock`.
The socket is accessible to its owner and group with mode 0660. Diagnostics are
kept in memory; no diagnostic or request-history tables are created.

`top` in an interactive terminal includes pending RAM counters. `stats`, `show`,
`list`, `export`, and `top --once` read committed SQLite snapshots. With the
default configuration, those commands may trail the live dashboard by about
30 seconds, or longer if storage is slow. A stopped or unavailable daemon makes
the dashboard fall back to `STORED` mode.

`status` reports capture activity, kernel drops, parser diagnostics, last request,
last successful flush, pending work, receive-buffer size, and process memory.
Without a diagnostic response, it prints systemd state and exits with an error.
`check --startup` validates startup settings without requiring a running daemon
or creating a database.

## Persistence

The only application table stores cumulative client statistics:

```sql
CREATE TABLE clients (
    ip TEXT PRIMARY KEY,
    requests INTEGER NOT NULL DEFAULT 0 CHECK(requests >= 0),
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL
);
```

IP addresses are normalized; IPv4-mapped IPv6 addresses become IPv4. Timestamps
are Unix seconds. Table output uses local time; CSV uses UTC RFC3339 timestamps
and the columns `ip,requests,first_seen,last_seen`.

One writer applies batches with SQLite UPSERT. WAL allows concurrent readers,
and `synchronous=FULL` protects committed transactions subject to storage fsync
guarantees. SIGINT/SIGTERM drain pending batches before a normal exit. A crash,
SIGKILL, power loss, or storage failure can lose uncommitted counters from either
in-memory batch. The configured flush interval is not a durability deadline
when storage is blocked.

Per-client counters saturate at `9,223,372,036,854,775,807`; timestamps continue
to update. CLI totals use arbitrary-precision integers. A ranking index speeds
up top queries and adds space/write overhead. New versions create it at startup;
a nearly full existing database may need a higher size limit.

## Storage limits

`max_database_mb` caps main-database pages, including indexes. Database size
primarily follows the number of distinct clients, not the number of requests.

`max_wal_mb` is a separate maintenance threshold. Before the next nonempty write
following an oversized WAL, dnsmon attempts a truncating checkpoint. WAL can
exceed the threshold by one batch. A reader holding a snapshot can prevent the
checkpoint; dnsmon then stops with an explicit error rather than allowing
indefinite WAL growth.

Disk-full errors, configured limits, and unrecoverable writes stop the service.
Committed rows are retained; rows are never silently deleted to free space.
Uncommitted counters may be lost when the failed process exits. WAL, shared
memory, temporary SQLite files, exports, and journald storage are outside the
main-database limit. Leave headroom when setting a filesystem quota.

After resolving an error, reset systemd's restart limit if necessary:

```sh
sudo systemctl reset-failed dnsmon
sudo systemctl restart dnsmon
```

## Backups and export

For a consistent file backup, stop dnsmon before copying the database. For an
online backup, use the SQLite backup API or the SQLite CLI's `.backup` command.
Copying only the main file of an active WAL database is not a consistent backup.

For portable client statistics:

```sh
sudo dnsmon export --csv stats.csv
```

CSV export uses a consistent read snapshot and atomic replacement of the output
file with mode 0600. It does not force pending RAM counters to flush.

## Updates

```sh
sudo /usr/local/libexec/dnsmon/install-release.sh
```

Configuration and statistics are preserved. Active services are restarted after
preflight checks. If startup health checks fail, the installer restores the old
binary and unit. Upgrades briefly interrupt observation; captured TCP state and
IP fragments are not preserved across process restarts.

To select a published tag or another public repository:

```sh
sudo env DNSMON_VERSION=TAG /usr/local/libexec/dnsmon/install-release.sh
sudo env DNSMON_REPOSITORY=owner/repo /usr/local/libexec/dnsmon/install-release.sh
```

The downloader resolves `latest` once, then fetches both archive and checksum
from that same tag. It supports public GitHub Releases. For a private repository,
download the bundle and `SHA256SUMS` through authenticated GitHub access, verify
the checksum, extract the bundle, and run `sudo ./scripts/install.sh` inside it.

When working from a checkout:

```sh
sudo ./scripts/install.sh --release  # Download the latest release
sudo ./scripts/install.sh           # Use bin/dnsmon if present; otherwise download
```

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Service exits or repeatedly restarts | Read `journalctl -u dnsmon`; run `dnsmon check --startup`. |
| Interface not found | Compare `interface` with `ip -br address`; restart after changing it. |
| `AF_PACKET` permission error | Check service capabilities, container restrictions, and VPS packet-socket support. |
| Zero counters | Verify service health, incoming traffic, interface, host-side port, and destination filter. Encrypted DNS is outside capture scope. |
| Live and `stats` totals differ | The dashboard includes uncommitted counters; `stats` reads SQLite. |
| Socket buffer capped | Compare the configured request with `net.core.rmem_max`; Linux reports twice the requested size including overhead. |
| Drops or parser counters increase | Inspect the specific reason, buffer occupancy, disk latency, and CPU usage before changing limits. |
| Release download returns 404 | Verify the repository, published release, and release assets. |

Kernel drop statistics do not include every possible loss before AF_PACKET.
Parser counters distinguish malformed DNS, flow limits, memory limits, missing
TCP framing, and timeouts; they are diagnostic events, not an exact count of
lost DNS messages. Full capture under arbitrary overload is not guaranteed.
