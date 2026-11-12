# Traffic classification and incident history

[Back to README](../README.md)

Everything runs inside netmon. The project explicitly excludes Grafana,
Prometheus and similar external monitoring stacks. There are no metrics servers,
alerts or notification integrations.

## Incoming traffic classes

The selected interface observes outgoing setup headers to correlate returning
traffic. Outgoing packets are **never counted or stored**; the bounded tracker
retains tuples and times, without application payloads. The existing CAP_NET_RAW
permission is sufficient; firewall and conntrack settings are not changed.

| Class | Evidence |
| --- | --- |
| `INBOUND` | Incoming TCP SYN without ACK, subsequent packets of that tracked flow, or incoming ICMP echo request. Closed-port attempts are included. |
| `REPLY` | Matching return tuple after an observed outgoing TCP SYN, UDP datagram or ICMP echo request. |
| `UNKNOWN` | Missing setup, expired/evicted state, fragments, unsupported protocols, unmatched replies or ambiguous UDP traffic. |

This is interface-level correlation, not proof of process ownership,
authentication, application requests or firewall acceptance. Container traffic
can match outgoing flows after host NAT. Select the external interface before
Docker DNAT to retain incoming published destination ports.

An outgoing TCP SYN-ACK never creates a locally initiated flow. UDP has no
handshake: a tuple first observed incoming stays UNKNOWN, and its outgoing server
response cannot turn it into REPLY. Outgoing-first UDP correlation remains
heuristic if capture misses traffic. UDP stays UNKNOWN for one flow timeout after
startup and after cache eviction or reported kernel drops. Fragments stay UNKNOWN.

```yaml
network:
  classify: true
  exclude_replies: false
  max_tracked_flows: 8192
  flow_timeout: 2m
  detail_targets: 16
  analysis_interval: 2s
  analysis_budget: 200ms
```

All three incoming classes remain in totals by default. Matched REPLY traffic
does not contribute to new packet-rate/scan evidence. `exclude_replies: true`
omits matched replies from **future** observations; UNKNOWN remains counted.
This requires classification and a nonzero tuple budget. Restart after changing
these settings; old statistics are not retroactively reclassified or deleted.

`classify: false` keeps ingress-only capture and records UNKNOWN. Flow count is
0..1,000,000 (0 disables storage), idle timeout 1s..1h, target detail limit 1..64.
`status` reports tuple occupancy and evictions. Top descriptions show `[INBOUND]`,
`[REPLY]`, `[UNKNOWN]` or `[MIXED]`, independently of trust/provider labels.
Whitelist entries do not suppress counters, incidents or suspicion.

## Port and node history

```sh
netmon show 198.51.100.20 --since 24h
netmon show 198.51.100.20 --since 168h --json
netmon show 198.51.100.20 --since 2026-11-01T00:00:00Z
netmon show 198.51.100.20 --since all --timeout 30s
```

The summary covers saved IP totals. The detail section separately names its time
range, node IDs/names, protocol/port, class, packets/bytes and SYN counts. Start
times round down to a minute by at most 59 seconds. Full-node queries read committed
observations, so very recent capture may await a flush. Read deadlines are bounded
by `--timeout` (1s..5m). Long read transactions may delay WAL checkpointing.

`detail_targets` bounds distinct **protocol/port/class entries per IP, node and
minute**. Selected entries continue accumulating exact counters. Excess targets
are omitted from the breakdown, while total/class counts remain exact for captured
observations. Partial output includes a count of packets without port detail.
Port 0 denotes no applicable/decoded port, including ICMP and fragments.

Forensic grouping additionally caps displayed groups at 4,096 targets and 512
node identities per IP query, explicitly marking partial coverage. Underlying
observations remain intact. Old data without detail is UNKNOWN and unattributed;
its historic per-port counts cannot be reconstructed from the old SYN-port sample.

On forward nodes, `show` returns the latest published **RAM minute**, marked
partial, without saved time-range history or SQLite. Inspect a full node for
shared history. CSV appends `inbound_packets`, `reply_packets`, `unknown_packets`.

## Correlation and journal

Full nodes incrementally detect these patterns in fixed, non-overlapping
ten-minute UTC epoch windows:

- `port_scan`: a single node sees at least `scan_ports_threshold` distinct SYN
  ports and total SYN count at least twice its distinct-port count.
- `distributed_scan`: at least two nodes see SYNs, their union reaches that port
  threshold, and total SYN count reaches twice the distinct-port count; or at
  least three nodes see SYNs with total SYN count at least twice the node count
  (horizontal scanning of even one port).
- `flood`: eligible packet-rate or SYN-rate evidence reaches four times its
  configured initial rating threshold.

An activity split across a window boundary can be missed; these are not sliding
windows. Retransmissions count. Shared/NAT source IPs and spoofed traffic can
also produce these patterns. The journal is evidence for review, not an
automatically published attacker list.

```sh
netmon incidents
netmon incidents --since 168h --ip 198.51.100.20
netmon incidents --id INCIDENT_ID
netmon incidents --since all --json
```

Records include deterministic IDs, source, kind, times, nodes, ports, severity,
reason and original facts. Facts preserve observation IDs, nodes, minute windows,
eligible packet/SYN counts, rate evidence and SYN ports. No payloads are stored.

A distributed scan raises suspicion even if individual-node intensity is low.
The IP rating is the maximum of decayed intensity and decayed incident severity;
scores are never added or averaged. JSON exposes `intensity_suspicion` and the
incident explaining correlation. The journal preserves original severity while
the live rating decays.

Incidents synchronize between full nodes alongside observations. Facts merge
by original observation ID, preventing duplicate counts on replay or overlapping
evidence. Forward nodes send observations without storing a local journal/spool.

Evidence caps: 512 facts and 64 displayed ports per incident; at most 20,000
observations examined per source/window. Truncation, old observations lacking
detail, capture eviction and cleanup crossing a window mark partial evidence.
If capped merged facts cannot reconstruct a threshold, output states that
limitation instead of claiming complete evidence.

Incidents share the main DB cap. Oldest closed windows and old incidents are
removed first at capacity, with a replicated cutoff preventing resurrection.
`retention: 0s` has no age expiry. Analysis runs outside capture and commits
each window's incident results together with its cursor. Defaults allow at most 128 changed
observations per 2s tick with a 200ms work deadline. This is **not a CPU quota**.
Interval is 1s..1m; budget is 50ms..1s and at most half the interval. Status/top
show backlog/errors; analysis can lag under sustained overload.

## Migration

Telemetry now uses **network v4** and compact payload v2 for detailed samples.
Legacy JSON/v1 samples remain readable. Full-node startup transactionally adds
the journal, analysis cursor and IP/time index, retaining counters, identities,
peer cursors and cleanup boundaries. A newly introduced journal starts at the
existing observation frontier so old history cannot delay live detection; it
does not promise a retrospective incident backfill. The new index needs database headroom.

Signed-update compatibility changes to `network-v4-details-v2`: **manually update
all full and forward nodes once**. Old-generation updaters refuse the incompatible
format. Legacy v3 heartbeat/update-control still announces the release, but v3
telemetry is refused to prevent silent loss of details. Subsequent releases
within the v4 compatibility generation can use automatic rollout normally.

Back up the configuration and a consistent stopped database before migration.
Drain forward-node queues while the old full nodes are still available, then
pause capture during the coordinated generation transition; old sensors cannot
deliver v3 telemetry to upgraded full nodes. Older executables cannot read new v2 payloads; a
cross-generation rollback needs the matching DB backup. `compact` preserves and
verifies detailed samples, incident evidence, IP state and all cursor/metadata
tables in its separate copy. New detail/history consumes additional disk space;
remeasure workload before projecting annual retention from the older format.
