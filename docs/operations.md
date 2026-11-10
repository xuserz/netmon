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
kept in memory; no diagnostic or request-history tables are created. A background
publisher samples pending counters and SQLite at most once per second while
a dashboard is connected. Socket requests read the last immutable result and
current health counters without SQL or a scan of pending IPs.

The publisher checks a commit revision before and after each sample; it discards
a result that overlaps a write instead of delaying capture or the writer. During
retries or a slow sample, the last good result stays visible. `STALE` marks
snapshots older than three seconds; health diagnostics continue to update.

`top` in an interactive terminal includes pending RAM counters. `stats`, `show`,
`list`, `export`, and `top --once` read committed SQLite snapshots. With the
default configuration, those commands may trail the live dashboard by about
30 seconds, or longer if storage is slow. A stopped or unavailable daemon makes
the dashboard fall back to `STORED` mode.

Current-activity views (`top --sort rate` / `--sort minute`) use a separate
bounded RAM cache. Requests/s is the average over the last five completed
seconds; minute counts cover the last 60 completed seconds, excluding the
second in progress. `SHARE` uses the minute count across **all** observed IPs,
including IPs no longer retained by the activity cache. The cache warms up after
restart. Eviction or a contended concurrent sample marks the view incomplete;
these rankings can omit active IPs and are not an exact global top after eviction.
Their header labels totals as **Saved requests**: those are acknowledged durable
counters, while the activity rows include recent uncommitted requests.

`status` reports capture activity, kernel drops, parser diagnostics, last request,
last successful flush, pending work, receive-ring size, kernel-to-reader lag, retry count, and process memory.
A separate goroutine refreshes CPU, RAM, and kernel drops once per second,
even while capture waits for a writer. `Blocked for` and `Oldest pending`
continue to age. Parser/flow statistics are immutable capture samples; their age
is reported separately so a fresh heartbeat does not imply fresh parser state.
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
) WITHOUT ROWID;
```

IP addresses are normalized; IPv4-mapped IPv6 addresses become IPv4. Timestamps
are Unix seconds. Table output uses local time; CSV uses UTC RFC3339 timestamps
and the columns `ip,requests,first_seen,last_seen`.

One writer computes absolute batch targets from confirmed counters, then applies
monotonic SQLite UPSERTs. Acknowledged targets enter a bounded LRU cache. The
same prepared targets can be replayed after an uncertain commit without adding
the batch twice. No new batch is prepared until the previous one is acknowledged.
Do not edit client counters with an external writer while dnsmon is running.

WAL allows concurrent readers,
and `synchronous=FULL` protects committed transactions subject to storage fsync
guarantees. SIGINT/SIGTERM drain pending batches before a normal exit. A crash,
SIGKILL, power loss, or storage failure can lose uncommitted counters from either
in-memory batch. The configured flush interval is not a durability deadline
when storage is blocked.

Per-client counters saturate at `9,223,372,036,854,775,807`; timestamps continue
to update. CLI totals use arbitrary-precision integers. A ranking index speeds
up top queries and adds space/write overhead. New versions create it at startup;
a nearly full existing database may need a higher size limit.

### Existing database migration

On first writable open, legacy rowid tables are copied to a `WITHOUT ROWID`
table inside one transaction; the original four fields and ranking are preserved.
A failed migration rolls back the schema and rows. Before updating a large
database, take a consistent backup and allow temporary space for old and new
tables, their indexes, and WAL, including room within `max_database_mb`. A
20 GiB database already near a 20 GiB cap may require temporarily raising it.

Freed pages remain reusable inside the file; migration does not automatically
shrink the physical database or run `VACUUM`. Existing SQLite readers and the
previous binary can read the new schema. Very large migrations can exceed the
installer startup-health window; arrange a maintenance window and start the
new binary with enough time for migration to finish.

## Storage limits

`max_database_mb` caps main-database pages, including indexes. Database size
primarily follows the number of distinct clients, not the number of requests.

`max_wal_mb` is a separate maintenance threshold. Before the next nonempty write
following an oversized WAL, dnsmon attempts a truncating checkpoint. WAL can
exceed the threshold by one batch. A reader holding a snapshot can prevent the
checkpoint; dnsmon retries within `write_retry_timeout`, then stops with an
explicit error if it remains blocked.

SQLite BUSY/LOCKED, transient I/O/protocol failures, and a blocked checkpoint
receive bounded exponential retries (50 ms up to 1s). Pending batches remain
in memory during retries; health shows the last error and cumulative retry count.
Disk-full errors, configured limits, corruption, and unrecoverable writes stop
the service. Shutdown shortens the remaining retry budget to five seconds;
an already running SQLite call may take longer.
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

CSV export first copies committed SQLite state through the incremental backup
API in steps of 128 pages, without a long-lived source transaction. It then
reads that private copy, so slow CSV formatting does not pin the live WAL.
The completed CSV replaces its destination atomically with mode 0600; errors
leave any existing CSV untouched. It does not flush pending RAM counters.

The temporary `.dnsmon-export-*` directory is created beside the CSV with mode
0700 and removed on success, ordinary failure, or SIGINT/SIGTERM. Allow room
for a database copy, the new CSV, and any existing CSV. Backup checks available
space with a 16 MiB reserve; these checks cannot reserve disk space against
other processes. A SIGKILL can leave a temporary directory; remove that export's
leftovers once the export process is no longer running.

```sh
sudo dnsmon export --csv /mnt/exports/stats.csv --timeout 10m
```

The default deadline is five minutes (`--timeout` accepts 1s..24h). Continuous
writes can restart the incremental backup and eventually reach this deadline;
export fails instead of holding a source snapshot indefinitely. An in-progress
OS I/O call may take longer than the deadline. Other long-lived SQLite readers,
including a slow `list` pipe, can still pin WAL; use isolated CSV export for
bulk consumption.

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
| Receive-ring allocation fails | Lower `socket_buffer_mb` or inspect available memory/container restrictions; changing `net.core.rmem_max` does not enlarge this ring. |
| `STALE` dashboard or writer retries | Inspect retry errors, database locks, disk latency, and WAL checkpoint readers. |
| Drops or parser counters increase | Inspect the specific reason, buffer occupancy, disk latency, and CPU usage before changing limits. |
| Release download returns 404 | Verify the repository, published release, and release assets. |

Kernel drop statistics do not include every possible loss before AF_PACKET.
Parser counters distinguish malformed DNS, flow limits, memory limits, missing
TCP framing, and timeouts; they are diagnostic events, not an exact count of
lost DNS messages. Full capture under arbitrary overload is not guaranteed.
