# Configuration

[Back to README](../README.md)

The installed configuration is `/etc/dnsmon/config.yaml`. The source distribution
includes a complete example in [dnsmon.yaml](../dnsmon.yaml).

```sh
sudoedit /etc/dnsmon/config.yaml
sudo dnsmon check --startup
sudo systemctl restart dnsmon
```

Unknown keys and invalid values cause startup to fail with an error. Missing
keys use their defaults. Byte budgets and limits named `*_mb` use binary units:
one MiB is 1,048,576 bytes.

## Reference

| Option | Default | Description |
| --- | --- | --- |
| `interface` | `eth0` | One ingress interface. `any` is not supported. A fresh installation attempts to select the default-route interface. |
| `destination_ip` | `""` | One destination IPv4/IPv6 address; empty accepts all destinations on the selected interface. |
| `port` | `53` | Destination port observed before NAT, from 1 to 65535. |
| `database` | `/var/lib/dnsmon/stats.db` | Absolute SQLite path. Custom locations require ownership and systemd write-access configuration. |
| `flush_interval` | `30s` | Target interval for submitting a batch to SQLite, from 1s to 1h. |
| `max_pending_ips` | `10000` | Maximum distinct IPs per in-memory batch. A new IP beyond this limit triggers early submission. |
| `max_database_mb` | `64` | Hard limit on the main SQLite database in MiB. WAL is separate. |
| `max_wal_mb` | `16` | WAL checkpoint threshold in MiB, not a hard total-disk quota. |
| `socket_buffer_mb` | `2` | Requested kernel receive buffer in MiB. `net.core.rmem_max` may cap it. |
| `max_tcp_flows` | `1024` | Maximum active TCP flows. New flows beyond the limit are skipped and reported. |
| `max_tcp_bytes` | `8388608` | Total buffered TCP payload budget in bytes. |
| `max_fragment_sets` | `256` | Maximum incomplete IP datagrams being reassembled. |
| `max_fragment_bytes` | `2097152` | Total buffered IP fragment payload budget in bytes. |
| `reassembly_timeout` | `2m` | Expiry for incomplete TCP messages and IP fragment sets. |
| `tcp_idle_timeout` | `10m` | Idle lifetime of clean, persistent TCP connections. |

Two batches can exist at once: one collecting counters and one being written.
If both fill, capture waits for the writer instead of allocating another batch.
This can cause socket-buffer losses during sustained disk stalls.

Reassembly budgets cover payload bytes, not total process RAM. Go metadata,
SQLite caches, live snapshots, temporary copies, and kernel socket memory add
overhead. Raising limits increases possible memory use; it does not reserve CPU
or guarantee loss-free capture.

For example, a 20 GiB main-database limit is:

```yaml
max_database_mb: 20480
```

This is an upper bound, not preallocated disk space. See
[storage limits](operations.md#storage-limits) for WAL and disk-full behavior.

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

For externally published Docker DNS, select the host's external ingress
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
Restart dnsmon after deleting or recreating its selected interface: the socket
is bound to the interface index.

### Query counting

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

A TCP connection started before dnsmon, or evicted after its idle timeout, is
skipped until a new SYN. Guessing the next message boundary could create false
counts. TCP Fast Open data is supported. Completed connections use a separate
bounded retransmission cache; incomplete state is not restored after restart.

Per-flow limits are 128 pending segments and 131,074 buffered payload bytes.
Per-datagram limits are 256 fragments and 65,535 reassembled bytes. IPv6 extension
parsing is bounded. Exceeding a limit is reported through capture diagnostics.

DoH, DoT, DNSCrypt, ESP-encrypted payloads, and IPv6 jumbograms are not decoded.
