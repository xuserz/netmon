# Network monitoring

[Back to README](../README.md)

Network mode observes incoming IP traffic on one Linux interface. It counts
packets and IP bytes, including headers, by source address. TCP, SYN without ACK,
UDP, and ICMP counters describe packet types. SYN retransmissions count again;
these counters do not establish successful connections or application requests.
No payload, DNS name, URL, or packet capture is persisted. Stored observations
contain source/node identities, minute windows, counters, bounded SYN destination
port samples, rating evidence, and synchronization metadata.

## Suspicion rating

Each IP has an integer score from 0 to 100. The default policy combines three
signals observed **on the same sensor**, using kernel packet timestamps:

| Signal | First tier | Second tier | Highest tier | Points |
| --- | --- | --- | --- | --- |
| Incoming packets in a wall-clock second | 1,000 | 4,000 | 16,000 | 11 / 23 / 35 |
| TCP SYN without ACK in a second | 100 | 400 | 1,600 | 11 / 23 / 35 |
| Distinct SYN destination ports in a bounded rolling 60s sample | 8 | 16 | 32 | 10 / 20 / 30 |

Points add up to at most 100. Thresholds are configurable under `network.rating`.
Port evidence retains at most 64 ports per cached IP. IPs evicted from the bounded
activity cache lose their rate/scan context; subsequent observations can be
marked `partial`. The score may underestimate activity when capture or cache
limits are exceeded. A second boundary can split a short burst between seconds.

A score decays exponentially: with `half_life: 1h`, 100 becomes 50 after an hour,
25 after two hours, and eventually rounds to zero. The strongest remaining
weighted evidence wins; scores from nodes are not summed or averaged. `show IP`
explains the signal and its observation time. Reasons may remain visible after
the integer score reaches zero, until the associated observation expires.

This is a deterministic triage rule, **not a calibrated probability or proof of
abuse**. Volume alone gives at most 35. NATs, shared proxies, monitoring systems,
and legitimate high-volume clients can score highly. Spoofed UDP/SYN sources can
identify victims rather than senders. A zero score means no threshold signal was
observed, not that an address is safe. There is no automatic blocking or public
submission; review evidence before publishing a feed.

## Own servers and whitelist

Labels describe **source** addresses already present in statistics. SERVER means
an explicitly configured own server/subnet, a local address on the selected
interface, or a literal IP in configured/discovered cluster endpoints. It is
not a hosting-provider classifier and does not prove that the real sender owned
that source address. Automatic node hints show their provenance in `show IP`.
Hostnames are not resolved for identity lookup; add public/NAT/forward-node IPs
explicitly when they are not available from those local hints.

WL marks your whitelist entry. A source can have both SERVER and WL. Counts,
score, reasons, ordering and packet capture stay unchanged for both labels;
whitelisted high-risk traffic remains visible. No firewall rules are modified.

Manage the address book with:

```sh
sudo netmon servers add 192.0.2.10 "DNS node EU"
sudo netmon servers add 2001:db8::10 "DNS node IPv6"
sudo netmon whitelist add 198.51.100.20 "Uptime Kuma"
sudo netmon whitelist add 198.51.100.0/24 "Monitoring subnet"
netmon servers list
netmon whitelist list
sudo netmon whitelist remove 198.51.100.20
sudo netmon servers remove 192.0.2.10
```

`add` updates the description when that normalized address already exists.
Descriptions are required and limited to 256 UTF-8 bytes without controls.
`list`, `add`, `remove`, and `whitelist import-dns` manage only this catalog and never open a statistics
DB, including on forward nodes. Use global `--config FILE` for another catalog;
`--db` is unrelated and rejected for these commands. Inspection features are
currently provided in network mode.

The YAML file defaults to `/etc/netmon/ip-labels.yaml`:

```yaml
servers:
  - ip: 192.0.2.10
    description: DNS node EU
whitelist:
  - ip: 198.51.100.20
    description: Uptime Kuma
  - ip: 2001:db8:1234::/48
    description: Monitoring network
```

Change the absolute `labels_file` path in the main config to use another file.
An empty path disables the manual catalog; local/server endpoint hints remain.
A missing file is an empty catalog, while malformed files fail explicitly.
The installer seeds 185 reviewed public DNS endpoint labels only when the catalog
is absent, preserving user edits and
retaining the appropriate netmon/dnsmon service group on migrated installations.
Uninstall preserves the user's catalog alongside the rest of `/etc/netmon`.

Existing installations can merge the release snapshot with
`sudo netmon whitelist import-dns`. It adds missing literal IPs, keeping your
exact descriptions, existing CIDR coverage and own-server list. No DNS/network
lookup is performed, and no data is added to statistics. See the
[provider/profile list and official sources](public-dns.md), including the
resolver endpoint versus recursive egress distinction. Import is explicit;
upgrades do not silently restore deleted labels.

IPv4, IPv6 and CIDRs are normalized; mapped IPv4 becomes IPv4. Most-specific
prefix wins within each list. SERVER and whitelist matching are independent;
manual server descriptions override automatic hints. There are at most 10,000
entries across both lists, with a 4 MiB file limit. The lookup index and local
address hints are cached. No identity work or file access is added per captured
packet; annotations are applied when a CLI view/export reads statistics.

CLI updates use an exclusive lock and atomic replacement, preserving existing
owner/group and permissions. Run them as root for the installed root-owned config
directory. The CLI refuses writes through symlinks or over config/key/database/
runtime files. You may also edit YAML manually. Keep permission to read the file
for the account running inspection commands. Invalid manual edits leave a running
TUI's last good display with an error; correcting the file restores refresh.

A running `top` reloads catalog edits on its next refresh, without restarting the
monitor or dashboard. Automatic interface/peer hints refresh at most every 15s.
Full `list` and CSV freeze labels for the duration of that export. CSV appends
`server_name,server_source,whitelisted,whitelist_description` to existing columns.
The daemon's raw private Unix snapshots contain capture metrics; the CLI adds
local descriptions. Schema, stored packet counters and replication protocol are
unchanged, so no database migration or rating-policy reset is required.

The catalog is **local configuration**, not replicated telemetry. Full nodes
share counters, while each view uses its own labels. Copy/deploy the same YAML
on other inspection nodes for matching descriptions. Forward nodes still have
no statistics DB or disk spool; their optional user-managed catalog is config.

## A standalone full node

```yaml
mode: network
interface: ens3
database: /var/lib/netmon/stats.db
flush_interval: 5s
max_database_mb: 20480
max_wal_mb: 16
socket_buffer_mb: 4
max_activity_ips: 10000
storage:
  mode: full
  retention: 24h
  queue_memory_mb: 8
network:
  capture: true
  ports: []
  exclude_ports: []
  runtime_directory: /run/netmon
  rating:
    pps_threshold: 1000
    syn_pps_threshold: 100
    scan_ports_threshold: 8
    half_life: 1h
cluster:
  enabled: false
```

An empty `ports` list includes all supported incoming IP protocols. A nonempty
list matches destination ports and excludes packets without a transport port,
including noninitial IP fragments. `exclude_ports` also matches destination
ports. No TCP stream or payload reassembly is needed. Without port filters,
noninitial fragments count as IP packets/bytes with their IP protocol, but cannot
add SYN/port evidence. Capture skips outgoing packets, malformed/truncated IP or
transport headers, unsupported encapsulation, and IPv6 jumbograms. It includes
reply packets arriving on the interface, not only attempts to initiate traffic.

Packet checksums are not validated. Capture cannot see traffic dropped before
AF_PACKET, for example upstream or by an earlier XDP program. It does not enable
promiscuous mode. See [capture scope](configuration.md#capture-scope).

## A cluster of full nodes

Generate a shared key once:

```sh
sudo netmon cluster keygen --out /etc/netmon/cluster.key
sudo chown netmon:netmon /etc/netmon/cluster.key
sudo chmod 640 /etc/netmon/cluster.key
```

Copy it securely to each member at the same path and set the same permissions.
Every holder can authenticate as a cluster member and submit data; use it only
with trusted nodes. TLS 1.3 authenticates both ends using a private CA derived
from the secret; public certificates and an external database are unnecessary.
Expose the dedicated cluster TCP port only where your nodes can reach it.

Add this to the full-node config on server A:

```yaml
cluster:
  enabled: true
  name: storage-a
  listen: "0.0.0.0:9845"
  advertise: "https://storage-a.example.net:9845"
  key_file: /etc/netmon/cluster.key
  peers: ["https://storage-b.example.net:9845"]
  sync_interval: 5s
```

On B use its own name/address and A as a peer. Full nodes discover peer addresses
and keep a durable copy of all observations within retention. They pull updates
without a primary; up to 32 peer addresses are supported. For a storage-only
node set:

```yaml
network:
  capture: false
```

All members must agree on `mode`, retention, and the entire rating policy;
mismatches fail explicitly. Keep clocks synchronized. Certificates bind the
protocol identity to the authenticated peer. A full node's identity and epoch
live in its network database; do not copy a live database to create another node.
See `netmon nodes` for identities, cursors, last exchange, and errors.

**Replication TCP ports are excluded automatically in both directions**, using
configured and discovered peer ports. This prevents synchronization traffic from
creating more observations. Dedicate those ports to netmon: other TCP traffic on
the same port is excluded too. Do not publish replication through a shared
service port such as 443 if monitoring that port matters.

## A RAM-only forward node

```yaml
mode: network
interface: ens3
flush_interval: 5s
max_activity_ips: 10000
storage:
  mode: forward
  retention: 24h
  queue_memory_mb: 8
cluster:
  enabled: true
  name: edge-1
  key_file: /etc/netmon/cluster.key
  peers:
    - "https://storage-a.example.net:9845"
    - "https://storage-b.example.net:9845"
  sync_interval: 5s
```

Rating defaults match the full-node example. Copy any customized rating settings
to forward nodes too. A forward node needs at least one full peer and makes only
outbound HTTPS connections; `listen` and `advertise` are unused. Its identity is
derived from the shared key, node name, and machine ID without writing an identity
file. Give cloned hosts distinct node names/machine IDs.

Forward nodes **never open or create SQLite, WAL, or a disk spool**. They create
only a Unix socket and lock in `/run/netmon` (normally tmpfs); systemd can still
create its empty state directory. Logs follow normal systemd journal settings.
Old databases are not deleted when changing an existing full node to forward.
`database` remains a valid absolute configuration path but is unused for writes.

One full-node durable ACK permits a forward node to forget a queued snapshot.
Additional replicas learn it asynchronously. It does not wait for a quorum; loss
of the only acknowledged storage disk before replication can lose those data.

During an outage, snapshots coalesce in bounded RAM. The queue budget covers
serialized content plus an estimate of per-entry overhead; it is not a process
RSS limit. When full, current entries may be retried later, but eviction/window
rotation can discard unsent increments. `status` and the dashboard expose queue
bytes, rejections, discarded observations, and last successful delivery. A
rejection is not necessarily a lost packet, and a discarded observation can
represent many packets. These diagnostics do not measure exact lost packets.
Expired queued observations are discarded. Shutdown attempts a short drain;
a crash or restart loses all unacknowledged RAM. Use `full` when that tradeoff
is unacceptable.

`top`, `show`, `stats`, and `list` on a forward node display only its bounded
current-process RAM view; there is no durable global history there. Packet totals
cover the process lifetime, while the IP count/list describes cached entries and
per-IP counters reset on cache eviction. `list` is limited by `-n` (maximum 1000)
in this mode. Query a full node for shared history or CSV export.

## Retention, consistency, and capacity

By default, network statistics cover retained minute windows for 24 hours, not
all-time DNS totals. Full nodes coalesce cumulative snapshots per observation ID,
source IP, and minute. Independent source contributions add; repeat delivery and
out-of-order cumulative updates merge by maxima without adding twice. Cache
eviction creates a new disjoint observation ID. This avoids an unbounded event
log on forwarding nodes. Two independent sensors seeing the same physical
packet still count two observations; choose observation boundaries accordingly.

Full nodes expire minute windows in small transactions, normally checked each
minute; backlog can delay cleanup. Counter totals subtract expired windows and
IPs disappear once no observations remain. First/last timestamps and peak PPS
for a continuously retained IP are historical summaries; they are not recomputed
when an older minute expires. Rating evidence is selected from retained windows.
Do not use first-seen as an exact start of the current retention period.

Retention bounds time, not disk volume. Each active source/minute needs an
observation and indexes; rapid cache churn can create more. SQLite stops accepting
new observations at `max_database_mb`, even when unexpired data remain. WAL is
additional. Writers retry while their bounded RAM queue permits; inspect errors
and increase capacity if needed. Removed pages are reused; retention does not
shrink an already allocated database file. Bulk `list`/CSV use temporary private
SQLite snapshots and require extra disk space beside the chosen output/snapshot
directory. Configure capacity based on actual traffic; no setting guarantees a
CPU ceiling or loss-free capture on a small VPS.

Network SQLite uses WAL/FULL durability with atomic counter/cursor transactions.
Counter overflow rejects the entire transaction with an explicit error rather
than wrapping counts. Storage peers track durable change cursors. Synchronization is eventual, so views
can temporarily differ. Outages longer than retention cannot recover expired
windows. Restoring an older database with the same epoch but a cursor below what
peers already consumed is rejected; provision a fresh network database/identity
and let current peers repopulate it instead.

## Migration and policy changes

- Add `mode: network` to an existing configuration and restart. `port: 53` and
  legacy DNS reassembly settings no longer limit network capture. Configure
  `network.ports: [53]` if DNS-port traffic is the intended scope.
- A `database: /var/lib/netmon/stats.db` setting produces
  `/var/lib/netmon/stats.db.network.db`. DNS `stats.db` and `stats.db.cluster.db`
  are preserved. The filename suffix is not added twice.
- Legacy configs without `mode` remain DNS mode; its cluster wire protocol and
  four-column client totals are separate. All communicating members must use
  the same mode. Forward storage is available only in network mode.
- Policy/retention are recorded in each network database. This version requires
  a **new database path on every full node** to change them; old aggregated
  evidence cannot be recalculated as raw traffic. Stop the service, preserve the
  previous database, change the path/settings on all members, and restart. This
  starts a new history rather than silently reinterpreting old scores.
- Changing `storage.mode` to forward stops new local statistics writes. It never
  removes previous databases. Changing back to full reopens the configured
  network database; keep policy/retention consistent.
