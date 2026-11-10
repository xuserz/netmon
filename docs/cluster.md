# Legacy DNS Peer-to-peer clusters

This guide covers `mode: dns`. For incoming traffic monitoring and full/forward
roles, use the [network cluster guide](network.md).


[Back to README](../README.md)

Every enabled node keeps a local capture database and a durable replica of the
cluster's cumulative statistics. There is no primary server. Any node can accept
a new member or display the shared totals. Nodes can learn addresses through an
authenticated seed and then exchange changes directly.

Only IP addresses, cumulative counters, first/last timestamps, and synchronization
metadata are exchanged. Domain names, individual requests, and raw packets are
not stored or transmitted by the replication protocol.

## Set up the first server

Install netmon normally and keep its existing interface/port configuration.
Generate one cluster secret on a trusted machine:

```sh
netmon cluster keygen --out cluster.key
sudo install -o netmon -g netmon -m 0600 cluster.key /etc/netmon/cluster.key
```

The generator creates a new file with mode 0600 and refuses to replace an
existing file. Use this **same key file** on every intended member, transferring
it through your existing secure administration channel. Keep it private: anyone
holding this key can join the cluster and publish statistics.

Add this block to `/etc/netmon/config.yaml` on server A:

```yaml
cluster:
  enabled: true
  name: server-a
  listen: "0.0.0.0:9845"
  advertise: "https://SERVER_A_IP:9845"
  key_file: /etc/netmon/cluster.key
  peers: []
  sync_interval: 5s
```

Replace `SERVER_A_IP` with an address reachable by the other members. Private
network or VPN addresses work. `advertise` is a complete HTTPS origin with an
explicit port; paths, credentials, queries, and plaintext HTTP are rejected.
Allow TCP 9845 between intended members in the existing host/network firewall.

Then validate and restart:

```sh
sudo netmon check --startup
sudo systemctl restart netmon
sudo netmon status
```

## Add another server

Install netmon on server B with its own capture configuration and the same
`cluster.key`. Use a new local database for a new server; do not copy another
member's database or node identity.

```yaml
cluster:
  enabled: true
  name: server-b
  listen: "0.0.0.0:9845"
  advertise: "https://SERVER_B_IP:9845"
  key_file: /etc/netmon/cluster.key
  peers:
    - "https://SERVER_A_IP:9845"
  sync_interval: 5s
```

Restart B after checking its configuration. A learns B's advertised address from
the authenticated exchange, and members gossip their known addresses. C can
join using either A or B. All advertised addresses must be reachable from the
other members. An endpoint hidden behind NAT requires a reachable published
port or a private/VPN route.

Configuration accepts up to 32 peers per node. This implementation is intended
for small clusters; membership and synchronization work are bounded.

## Read statistics

When clustering is enabled, these commands read the local copy of shared totals:

```sh
netmon top
netmon top --once
netmon stats
netmon show 192.0.2.10
netmon list
netmon export --csv cluster.csv
netmon nodes
netmon status
```

Read this server's capture counters instead:

```sh
netmon stats --local
netmon top --local
netmon show 192.0.2.10 --local
netmon export --csv local.csv --local
```

An explicit `--db FILE` reads that exact database rather than automatically
selecting its cluster replica. CSV destinations cannot overwrite either the
local capture database or its replica and sidecar files.

The dashboard labels shared totals **CLUSTER** and **Saved requests**. Those
include only durable replicated counters. CPU, RAM, pending writes, capture
health, and `--sort rate` / `--sort minute` activity views describe the **local**
process; remote live activity is not presented as local traffic. `nodes` reports
peer addresses, names, persistent IDs, last successful exchanges, and errors.

## Synchronization and failures

Each capture database gets a persistent random node ID. For an IP, its shared
counter is the sum of the latest cumulative contributions from distinct node
IDs. Replayed or indirectly relayed contributions merge with `max`; first/last
observations merge with `min`/`max`. A query observed by two different DNS servers
is two server observations, not a globally deduplicated transaction.

Local writes update a compact change feed in the same SQLite transaction as the
client counters. It retains one change position per IP, rather than an event
history. Changes are exchanged in pages of at most 512 components. Receive
positions and the merged counters commit together, so retries and restarts do
not double-count an acknowledged page. Only committed local data is replicated.

The default capture flush interval is 30s, followed by background import and a
peer exchange (5s by default). Data may lag longer during initial synchronization,
slow storage, or network outages. Reducing `flush_interval` also increases write
frequency. Initial synchronization is bounded and can take multiple rounds.
There is no globally atomic snapshot across simultaneously running servers.

If a member is unreachable, capture and local commits continue. Other nodes
retain that member's last known contribution. Exchanges resume from durable
cursors after connectivity returns. A cluster error or a replica reaching its configured size cap
is reported separately from capture health; the local change feed remains the
source for eventual catch-up. Filesystem exhaustion can still affect both
databases when they share a filesystem. Unsaved RAM counters can still be lost on SIGKILL
or power failure, as in standalone mode.

Disabling `cluster.enabled` stops networking and returns commands to local
statistics. Once initialized, the coalesced local change feed continues tracking
commits so enabling the cluster again includes traffic collected in between.

## Storage and identities

For `database: /var/lib/netmon/stats.db`:

- `stats.db` stores local clients plus optional source identity/change metadata.
- `stats.db.cluster.db` stores origin contributions, receive positions, peer
  discovery state, and the materialized shared `clients` table.
- Both files use WAL and the configured database/WAL budgets independently.

The `clients` table still has exactly four fields. Cluster mode adds service
metadata tables and a second database; it needs additional disk space. The
replica retains contributions from every origin on every member, so its storage
can be substantially larger than a single local database. `max_database_mb` is a
per-database limit, not a total filesystem quota. Initializing the local change
feed on an existing large database also needs headroom inside that limit.

Never clone a running member's databases to create another member. Identical
origin IDs would represent both captures as one contribution. Direct connections
with the same node ID but different sessions are rejected as duplicate identities.
Use fresh local databases for new members. Keep identities and replica state
across ordinary restarts.

Do not restore older capture counters into an active identity or manually lower
counters. The merge is monotonic and cannot distinguish a reset from a delayed
old message. For recovery or moving a member, stop capture and preserve the
matching identity/data files; plan historical restores for the whole cluster.
A fresh replica file can rebuild from local state and reachable peers, but data
that existed only on an unreachable/lost node cannot be reconstructed.

## Transport

Nodes use TLS 1.3 with mutual certificate authentication. The 256-bit shared key
defines a private cluster CA; short-lived process keys sign the TLS handshakes.
The private service name `netmon.cluster` is verified against this CA, so public
certificates and public DNS names are not required. Certificate node identities
must match protocol identities. Plaintext HTTP, redirects, foreign cluster keys,
and missing client certificates are rejected.

All members are trusted equally and can issue credentials for this cluster. To
rotate the shared key, distribute the new key to the intended members and restart
them; old-key members cannot reconnect. Capture databases and node IDs stay in
place. The service does not open firewall ports, configure VPNs, or copy keys to
other servers automatically.
