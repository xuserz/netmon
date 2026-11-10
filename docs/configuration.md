# Configuration

[Back to README](../README.md)

The installed configuration is `/etc/netmon/config.yaml`. The source distribution
includes a complete example in [netmon.yaml](../netmon.yaml).

```sh
sudoedit /etc/netmon/config.yaml
sudo netmon check --startup
sudo systemctl restart netmon
```

Unknown keys and invalid values cause startup to fail with an error. Missing
keys use their defaults. Byte budgets and limits named `*_mb` use binary units:
one MiB is 1,048,576 bytes.

## Network mode

Fresh-install [netmon.yaml](../netmon.yaml) selects `mode: network`, a 5s flush,
256 MiB main-database cap, and a 4 MiB receive ring. Omitted keys retain backward
compatible defaults (DNS mode, 30s, 64 MiB, 2 MiB). Explicit settings always win.
See [network monitoring](network.md) for complete full/forward configurations.

| Option | Omitted default | Description |
| --- | --- | --- |
| `labels_file` | `/etc/netmon/ip-labels.yaml` | Local server/whitelist descriptions; absolute path or empty to disable the manual catalog. Network CLI views reload edits automatically. |
| `providers_file` | `/usr/share/netmon/providers.json.gz` | Offline provider range catalog; absolute path or empty to disable. Installed with releases, reloaded by network views; no API calls or automatic trust. See [provider labels](providers.md). |
| `updates.automatic` | `false` | Opt in to signed automatic installation. Requires network cluster mode, a coordinator and an enabled update timer. |
| `updates.propagate` | `true` | Relay verified release offers through cluster traffic, independently of local installation permission. |
| `updates.coordinator` | `""` | One full node's advertised HTTPS URL, identical on participating hosts. Serializes automatic installs; see [updates](updates.md). |
| `updates.public_key` | `/etc/netmon/update-public-key` | Root-owned Ed25519 public key. Never automatically replaced once installed. |
| `mode` | `dns` | `network` for packet activity/rating, `dns` for legacy query accounting. |
| `storage.mode` | `full` | `full` stores shared data; `forward` sends from RAM and opens no statistics DB. Forward requires network mode and at least one cluster peer. |
| `storage.retention` | `0s` | `0s` disables age expiry; optionally 1h..720h. Oldest closed minute windows are removed at database capacity. Every member, including forward, must agree. |
| `storage.queue_memory_mb` | `8` | Estimated queued snapshot/entry budget, 1..256 MiB; process overhead is additional. |
| `network.classify` | `true` | Observe bounded outgoing setup tuples to classify incoming traffic. |
| `network.exclude_replies` | `false` | Omit matched replies from future statistics; UNKNOWN stays counted. |
| `network.max_tracked_flows` | `8192` | Tuple LRU bound, 0..1,000,000. |
| `network.flow_timeout` | `2m` | Idle tuple expiry and UDP uncertainty grace, 1s..1h. |
| `network.detail_targets` | `16` | Protocol/port/class entries per IP/node/minute, 1..64; overflow is explicitly partial. |
| `network.analysis_interval` | `2s` | Built-in full-node incident-analysis interval, 1s..1m. |
| `network.analysis_budget` | `200ms` | Work deadline, 50ms..1s and at most half the interval; not a CPU quota. |
| `network.capture` | `true` | `false` makes a full node a receiver-only replica. |
| `network.ports` | `[]` | Optional destination-port allowlist, at most 64 entries. Empty includes all ports/protocols. |
| `network.exclude_ports` | `[]` | Destination-port exclusions, at most 64. Replication TCP ports are additionally excluded automatically in both directions. |
| `network.runtime_directory` | `/run/netmon` | Absolute Unix socket/lock directory, at most 80 bytes. Custom paths need service write access. |
| `network.rating.pps_threshold` | `1000` | First packet-rate tier, 1..1,000,000,000 packets per wall-clock second. |
| `network.rating.syn_pps_threshold` | `100` | First SYN-rate tier, same numeric range. |
| `network.rating.scan_ports_threshold` | `8` | First distinct-SYN-port tier within a bounded 60s sample, 2..16. |
| `network.rating.half_life` | `1h` | Score decay half-life, 1m..168h. |

In network mode, `database` gains `.network.db` unless already present. Full nodes
retain observations by minute and share the saved window; forward nodes use RAM
only. `max_activity_ips` bounds per-IP rate/port context (a value of 0 retains one
entry in network mode), not the number of IPs allowed in durable storage.
`max_database_mb` caps that network database, and WAL is additional. On a full
queue, capture continues and reports rejected/discarded observations rather than
waiting for disk/network I/O. Near the database size cap, oldest closed minute
windows are removed in bounded transactions; the replicated cleanup boundary
prevents resurrection. WAL and temporary exports remain additional disk usage.
Changing a positive retention to `0s` migrates the existing full-node DB in place,
preserving surviving observations, counters and identities. Other retention or
rating changes still require a fresh network database. See
[capacity and consistency](network.md#retention-consistency-and-capacity).

`port`, `max_pending_ips`, `hot_cache_ips`, `write_retry_timeout`, and all TCP/IP
reassembly settings below belong to DNS mode and do not control network mode.
Network writes retry bounded snapshots until accepted or expired, and show their
last failure through `status`. No disk writes occur on a forward node.

## Common and legacy DNS reference

| Option | Default | Description |
| --- | --- | --- |
| `interface` | `eth0` | One ingress interface. `any` is not supported. A fresh installation attempts to select the default-route interface. |
| `destination_ip` | `""` | One destination IPv4/IPv6 address; empty accepts all destinations on the selected interface. |
| `port` | `53` | Destination port observed before NAT, from 1 to 65535. |
| `database` | `/var/lib/netmon/stats.db` | Absolute SQLite path. Custom locations require ownership and systemd write-access configuration. |
| `flush_interval` | `30s` | Target interval for submitting a batch to SQLite, from 1s to 1h. |
| `max_pending_ips` | `10000` | Maximum distinct IPs per in-memory batch. A new IP beyond this limit triggers early submission. |
| `max_database_mb` | `64` | Hard limit on the main SQLite database in MiB. WAL is separate. |
| `max_wal_mb` | `16` | WAL checkpoint threshold in MiB, not a hard total-disk quota. |
| `socket_buffer_mb` | `2` | Exact PACKET_MMAP TPACKET_V3 receive-ring allocation in MiB, from 1 to 64. `net.core.rmem_max` does not cap this ring. |
| `max_tcp_flows` | `1024` | Maximum active TCP flows. New flows beyond the limit are skipped and reported. |
| `max_tcp_bytes` | `8388608` | Total buffered TCP payload budget in bytes. |
| `max_fragment_sets` | `256` | Maximum incomplete IP datagrams being reassembled. |
| `max_fragment_bytes` | `2097152` | Total buffered IP fragment payload budget in bytes. |
| `reassembly_timeout` | `2m` | Expiry for incomplete TCP messages and IP fragment sets. |
| `tcp_idle_timeout` | `10m` | Idle lifetime of clean, persistent TCP connections. |
| `max_activity_ips` | `10000` | Maximum IPs in the volatile activity LRU cache; 0 disables it, maximum 100,000. This does not limit stored clients. |
| `hot_cache_ips` | `8192` | Maximum confirmed client totals in the writer LRU cache; 0 disables it, maximum 1,000,000. |
| `write_retry_timeout` | `30s` | Retry budget per preparation/apply stage for transient SQLite errors, from 1s to 5m. Shutdown shortens remaining retries to at most 5s plus an already running call. |

Two batches can exist at once: one collecting counters and one being written.
If both fill, capture waits for the writer instead of allocating another batch.
This can cause receive-ring losses during sustained disk stalls. Retries retain
the same prepared absolute targets so replaying an uncertain commit does not
increment counters twice. A retry budget does not provide a persistent queue.

Reassembly budgets cover payload bytes, not total process RAM. Go metadata,
SQLite caches, confirmed-client and activity caches, live snapshots, temporary
copies, and the mapped receive ring add overhead. Raising limits increases possible memory use; it does not reserve CPU
or guarantee loss-free capture.

For example, a 20 GiB main-database limit is:

```yaml
max_database_mb: 20480
```

This is an upper bound, not preallocated disk space. See
[storage limits](operations.md#storage-limits) for WAL and disk-full behavior.

The receive ring uses 1 MiB blocks and a 64 ms block retirement timeout. Capture
borrows packet bytes from mapped blocks; UDP parsing avoids a userspace copy.
TCP and fragment reassembly copy only data they must retain. Allocation failure
is reported at startup; netmon does not silently select a smaller ring.

The activity cache uses 61 per-second counters per retained IP and consumes
several MiB at the default capacity, plus Go metadata and GC overhead. It is
independent of both pending-write batches and the confirmed writer cache.
Evicting an activity entry never removes or changes cumulative SQLite counters.

## Cluster configuration

`cluster.enabled` defaults to `false`. The optional block accepts `name`,
`listen` (default `0.0.0.0:9845`), `advertise`, `key_file`, `peers` (maximum 32),
and `sync_interval` (default `5s`, allowed `1s..1h`). An enabled cluster requires an absolute key-file path. Full nodes need a
reachable advertised HTTPS origin with an explicit port. Network forward nodes
need only outbound peers, with no listener/advertised address. See [cluster setup](cluster.md) for complete examples.

In legacy DNS mode, the database and WAL budgets apply separately to local capture
and the cluster replica. Existing client rows keep their four fields; enabled replication adds
metadata tables and a durable per-origin replica. These budgets are not a total
disk quota.

## Capture scope

### Interface and destination

AF_PACKET capture is bound to one interface. Choose the boundary where the
clients of interest enter the host:

```sh
ip -br address
ip route get 1.1.1.1
```

For example:

```yaml
interface: ens3
destination_ip: ""
port: 53
```

An empty destination matches IPv4 and IPv6 traffic. To restrict capture, use a
single literal address without a hostname, CIDR mask, or IPv6 zone ID.

Outgoing observations are discarded. Capture does not enable promiscuous mode,
change firewall rules, or block clients. Packets are observed before the DNS
server or firewall may reject them; a count does not confirm successful resolution.

### Docker and NAT

For network mode, port allowlists use `network.ports`, not `port`.
For externally published Docker DNS in legacy mode, select the host's external ingress
interface and the published port. With `5353:53/udp`, configure `port: 5353`.
The same setting applies to the host-side TCP port if TCP is published.
`destination_ip` is the destination address before DNAT.

Observing one interface prevents recounting the same packet at an external
interface, bridge, and veth. Traffic from loopback, containers, or other NICs is
only included if it crosses the selected interface. A bridge can be selected
when it is the intended observation boundary; NAT may already have changed IPs.
Clients behind a proxy or external NAT appear under the address visible at that
boundary.

For VLANs, select the VLAN interface, such as `ens3.100`, rather than a tagged
trunk. Tunnels, overlay encapsulation, and VLAN trunk frames are not decoded.
Restart netmon after deleting or recreating its selected interface: the socket
is bound to the interface index.

### Query counting (legacy `mode: dns`)

- **UDP:** one complete, structurally valid DNS request per datagram. A retried
  UDP query is another received request; transaction IDs are not deduplication keys.
- **TCP:** one complete DNS message with a two-byte length prefix. Reassembly
  handles split messages, multiple messages per segment, retransmissions, and
  out-of-order segments. The initial SYN must be observed to establish framing.
- **IPv4/IPv6:** IP fragmentation and common IPv6 extension headers are handled
  within bounded buffers. Exact duplicate fragments are ignored during assembly;
  overlapping fragments are rejected.

Validation checks DNS wire structure, including names, compression pointers,
record boundaries, and EDNS option lengths, without retaining domain strings.
EDNS COOKIE probes, NOTIFY, UPDATE, and DSO wire structure are supported.
RDATA semantics for every record type and packet checksums are not validated.
Responses with QR=1 are excluded.

A TCP connection started before netmon, or evicted after its idle timeout, is
skipped until a new SYN. Guessing the next message boundary could create false
counts. TCP Fast Open data is supported. Completed connections use a separate
bounded retransmission cache; incomplete state is not restored after restart.

Per-flow limits are 128 pending segments and 131,074 buffered payload bytes.
Per-datagram limits are 256 fragments and 65,535 reassembled bytes. IPv6 extension
parsing is bounded. Exceeding a limit is reported through capture diagnostics.

DoH, DoT, DNSCrypt, ESP-encrypted payloads, and IPv6 jumbograms are not decoded.
