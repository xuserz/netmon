"""Network-mode source, two storage replicas, RAM-only forwarding and risk scores."""
from contextlib import closing
import json
import csv
import os
from pathlib import Path
import signal
import socket
import sqlite3
import struct
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
BINARY = Path(os.environ.get("NETMON_BINARY", ROOT / "bin/netmon"))


@unittest.skipUnless(os.environ.get("NETMON_INTEGRATION") == "1" and BINARY.is_file(),
                     "enable NETMON_INTEGRATION=1 in an isolated network namespace")
class NetworkTests(unittest.TestCase):
    def setUp(self):
        try:
            probe = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM)
            probe.close()
        except PermissionError:
            self.skipTest("CAP_NET_RAW is required")
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.key = self.root / "cluster.key"
        subprocess.run([str(BINARY), "cluster", "keygen", "--out", str(self.key)], check=True, capture_output=True)
        self.nodes = []
        self.addCleanup(self.stop_all)
        self.sink = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sink.bind(("127.0.0.1", 0))
        self.addCleanup(self.sink.close)
        self.port = self.sink.getsockname()[1]

    def reserve(self):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            return sock.getsockname()[1]

    def node(self, name, role, port, peers, capture=False):
        directory = self.root / name
        directory.mkdir()
        runtime = directory / "run"
        database = directory / "statistics-must-not-exist" / "stats.db"
        config = directory / "config.yaml"
        config.write_text(f"mode: network\nlabels_file: {directory / 'labels.yaml'}\ninterface: lo\ndatabase: {database}\nflush_interval: 1s\n"
                          "max_database_mb: 16\nmax_activity_ips: 64\n"
                          f"storage:\n  mode: {role}\n  retention: 0s\n  queue_memory_mb: 1\n"
                          f"network:\n  capture: {str(capture).lower()}\n  runtime_directory: {runtime}\n"
                          f"  ports: [{self.port}]\n"
                          f"cluster:\n  enabled: true\n  name: {name}\n  key_file: {self.key}\n"
                          f"  listen: 127.0.0.1:{port}\n  advertise: https://127.0.0.1:{port}\n"
                          f"  peers: {json.dumps(peers)}\n  sync_interval: 1s\n")
        log = (directory / "monitor.log").open("w+")
        self.addCleanup(log.close)
        node = {"config": config, "runtime": runtime, "database": database,
                "log": log, "process": None, "role": role}
        self.nodes.append(node)
        return node

    def rpc(self, node, op="top", ip=""):
        with socket.socket(socket.AF_UNIX) as conn:
            conn.settimeout(2)
            conn.connect(str(node["runtime"] / "monitor.sock"))
            conn.sendall(json.dumps({"op": op, "sort": "score", "limit": 1000, "ip": ip}).encode() + b"\n")
            with conn.makefile("rb") as file:
                return json.loads(file.readline(2 << 20))

    def wait_for(self, predicate, seconds=15):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            try:
                result = predicate()
                if result:
                    return result
            except (OSError, ValueError, sqlite3.OperationalError):
                pass
            time.sleep(.04)
        logs = []
        for node in self.nodes:
            node["log"].seek(0)
            logs.append(node["log"].read())
        self.fail("network condition timed out\n" + "\n".join(logs))

    def start(self, node):
        check = self.command(node, "check", "--startup")
        self.assertEqual(check.returncode, 0, check.stderr)
        node["process"] = subprocess.Popen([str(BINARY), "--config", str(node["config"]), "run"],
                                           stdout=node["log"], stderr=node["log"])
        self.wait_for(lambda: node["process"].poll() is None and self.rpc(node, "health")["health"]["pid"] == node["process"].pid)

    def stop(self, node):
        process = node["process"]
        if process and process.poll() is None:
            process.terminate()
            try:
                process.wait(12)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

    def stop_all(self):
        for node in self.nodes:
            self.stop(node)

    def total(self, node):
        with closing(sqlite3.connect(str(node["database"]) + ".network.db")) as db:
            return db.execute("SELECT packets FROM net_totals WHERE id=1").fetchone()[0]

    def command(self, node, *args):
        return subprocess.run([str(BINARY), "--config", str(node["config"]), *args],
                              capture_output=True, text=True, timeout=10)

    def test_ram_forwarding_replica_recovery_and_no_legacy_dns_mix(self):
        a_port, b_port, agent_port = self.reserve(), self.reserve(), self.reserve()
        a = self.node("storage-a", "full", a_port, [])
        b = self.node("storage-b", "full", b_port, [f"https://127.0.0.1:{a_port}"])
        agent = self.node("agent", "forward", agent_port, [f"https://127.0.0.1:{a_port}"], capture=True)
        for node in self.nodes:
            self.start(node)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            for _ in range(100):
                client.sendto(b"not a DNS query", ("127.0.0.1", self.port))
        self.wait_for(lambda: self.total(a) == 100 and self.total(b) == 100)
        self.assertTrue(any(not n["last_delivery"].startswith("0001-")
                            for n in self.rpc(agent, "health").get("network_nodes", [])))
        self.assertFalse(agent["database"].parent.exists(), "forwarding wrote a statistics directory")
        self.assertFalse(a["database"].exists(), "network counters were mixed into the DNS database")
        result = self.command(a, "stats")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Packets: 100", result.stdout)
        result = self.command(a, "show", "127.0.0.1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Suspicion: 0/100", result.stdout)
        b["process"].kill()
        b["process"].wait(5)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            for _ in range(50):
                client.sendto(b"still not DNS", ("127.0.0.1", self.port))
        self.wait_for(lambda: self.total(a) == 150)
        self.start(b)
        self.wait_for(lambda: self.total(b) == 150)
        time.sleep(1.1)
        self.assertEqual(self.total(a), 150)
        self.assertFalse(agent["database"].parent.exists())
        exported = self.root / "network.csv"
        result = self.command(a, "export", "--csv", str(exported))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("suspicion", exported.read_text().splitlines()[0])
        self.assertIn("127.0.0.1", exported.read_text())
        self.stop(agent)
        self.assertFalse(agent["database"].parent.exists())
        offline = self.command(agent, "stats")
        self.assertNotEqual(offline.returncode, 0)
        self.assertFalse(agent["database"].parent.exists())

    def test_forward_outage_buffers_in_ram_until_storage_returns(self):
        port = self.reserve()
        storage = self.node("storage", "full", port, [])
        agent = self.node("edge", "forward", self.reserve(), [f"https://127.0.0.1:{port}"], capture=True)
        self.start(agent)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            for _ in range(50):
                client.sendto(b"buffer during outage", ("127.0.0.1", self.port))
        health = self.wait_for(lambda: (h if (h := self.rpc(agent, "health")["health"])["queue_bytes"] > 0 and h.get("flush_error") else False))
        self.assertLessEqual(health["queue_bytes"], health["queue_limit"])
        self.assertFalse(agent["database"].parent.exists())
        self.start(storage)
        self.wait_for(lambda: self.total(storage) == 50)
        self.wait_for(lambda: self.rpc(agent, "health")["health"]["queue_bytes"] == 0)
        result = self.command(agent, "status")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Delivery ACKs:", result.stdout)
        self.stop(agent)
        self.assertFalse(agent["database"].parent.exists())
        offline = self.command(agent, "stats")
        self.assertNotEqual(offline.returncode, 0)
        self.assertFalse(agent["database"].parent.exists())

    def test_score_and_reasons_reach_storage(self):
        port = self.reserve()
        storage = self.node("rated-storage", "full", port, [])
        agent = self.node("rated-edge", "forward", self.reserve(), [f"https://127.0.0.1:{port}"], capture=True)
        for node in self.nodes:
            text = node["config"].read_text().replace("  ports:", "  rating:\n    pps_threshold: 1\n  ports:")
            node["config"].write_text(text)
            self.start(node)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            for _ in range(100):
                client.sendto(b"network rate signal", ("127.0.0.1", self.port))
        self.wait_for(lambda: self.total(storage) == 100)
        result = self.command(storage, "show", "127.0.0.1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Suspicion: 35/100", result.stdout)
        self.assertIn("incoming IP packets/s", result.stdout)

    def test_distributed_scan_port_history_incident_replication_and_restart(self):
        a_port, b_port = self.reserve(), self.reserve()
        targets = set()
        while len(targets) < 8:
            port = self.reserve()
            if port not in (a_port, b_port, self.port):
                targets.add(port)
        targets = sorted(targets)
        a = self.node("scan-a", "full", a_port, [], capture=True)
        b = self.node("scan-b", "full", b_port, [f"https://127.0.0.1:{a_port}"], capture=True)
        for node, ports in ((a, targets[:4]), (b, targets[4:])):
            text = node["config"].read_text().replace(f"  ports: [{self.port}]", f"  ports: {json.dumps(ports)}")
            node["config"].write_text(text)
            self.start(node)
        def scan():
            for port in targets:
                for _ in range(2):
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
                        client.settimeout(.5)
                        client.bind(("127.0.0.2", 0))
                        client.connect_ex(("127.0.0.1", port))
        # Avoid splitting the fixed correlation window at its wall-clock edge.
        if time.time() % 600 > 598:
            time.sleep(2)
        scan()
        self.wait_for(lambda: self.total(a) >= 16 and self.total(b) >= 16)
        def events(node):
            result = self.command(node, "incidents", "--ip", "127.0.0.2", "--json")
            self.assertEqual(result.returncode, 0, result.stderr)
            return json.loads(result.stdout)
        journal = self.wait_for(lambda: (rows if (rows := events(a)) else False))
        incident = next(row for row in journal if row["kind"] == "distributed_scan")
        self.assertEqual(incident["nodes"], 2)
        self.assertEqual(len(incident["ports"]), 8)
        self.assertGreaterEqual(incident["syn"], 16)
        self.wait_for(lambda: any(row["id"] == incident["id"] for row in events(b)))
        result = self.command(a, "show", "127.0.0.2", "--since", "24h", "--json")
        self.assertEqual(result.returncode, 0, result.stderr)
        details = json.loads(result.stdout)
        self.assertEqual(details["summary"]["intensity_suspicion"], 0)
        self.assertGreater(details["summary"]["suspicion"], 0)
        self.assertEqual(len(details["profile"]["nodes"]), 2)
        self.assertEqual(len(details["profile"]["targets"]), 8)
        self.assertGreaterEqual(details["profile"]["traffic"]["inbound"], 16)
        result = self.command(a, "incidents", "--id", incident["id"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Node ", result.stdout)
        self.stop(b)
        offline = events(b)
        self.assertTrue(any(row["id"] == incident["id"] for row in offline))
        self.start(b)
        self.wait_for(lambda: any(row["id"] == incident["id"] for row in events(b)))

    def test_ipv6_udp_and_tcp_syn_are_observed(self):
        node = self.node("ipv6", "full", self.reserve(), [], capture=True)
        self.start(node)
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as udp_sink, socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as tcp_sink:
            udp_sink.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            tcp_sink.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            udp_sink.bind(("::1", self.port))
            tcp_sink.bind(("::1", self.port))
            tcp_sink.listen(1)
            with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as client:
                for _ in range(3):
                    client.sendto(b"IPv6 network activity", ("::1", self.port))
            with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as client:
                client.settimeout(2)
                client.connect(("::1", self.port))
                connection, _ = tcp_sink.accept()
                connection.close()
        def observed():
            with closing(sqlite3.connect(str(node["database"]) + ".network.db")) as db:
                row = db.execute("SELECT udp,syn,tcp FROM net_ips WHERE ip='::1'").fetchone()
                return row and row[0] == 3 and row[1] == 1 and row[2] >= 1
        self.wait_for(observed)
        result = self.command(node, "show", "::1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("::1", result.stdout)

    def test_server_and_whitelist_descriptions_preserve_saved_statistics(self):
        node = self.node("labels", "full", self.reserve(), [], capture=True)
        node["config"].write_text(node["config"].read_text().replace("  ports:", "  rating:\n    pps_threshold: 1\n  ports:"))
        self.start(node)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            for _ in range(100):
                client.sendto(b"labelled activity", ("127.0.0.1", self.port))
        self.wait_for(lambda: self.total(node) == 100)
        for args in [("servers", "add", "127.0.0.1", "DNS node EU"),
                     ("whitelist", "add", "127.0.0.1", "Uptime Kuma")]:
            result = self.command(node, *args)
            self.assertEqual(result.returncode, 0, result.stderr)
        result = self.command(node, "show", "127.0.0.1")
        self.assertEqual(result.returncode, 0, result.stderr)
        for text in ("SERVER+WL", "DNS node EU", "Uptime Kuma", "Suspicion: 35/100"):
            self.assertIn(text, result.stdout)
        # Full top uses a cached snapshot, then applies the current address book.
        self.wait_for(lambda: "Uptime Kuma" in self.command(node, "top", "--once").stdout)
        result = self.command(node, "list", "--snapshot-dir", str(self.root))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Uptime Kuma", result.stdout)
        destination = self.root / "labels.csv"
        result = self.command(node, "export", "--csv", str(destination))
        self.assertEqual(result.returncode, 0, result.stderr)
        with destination.open() as file:
            rows = list(csv.DictReader(file))
        self.assertEqual(rows[0]["server_name"], "DNS node EU")
        self.assertEqual(rows[0]["whitelisted"], "true")
        self.assertEqual(rows[0]["packets"], "100")
        result = self.command(node, "whitelist", "remove", "127.0.0.1")
        self.assertEqual(result.returncode, 0, result.stderr)
        result = self.command(node, "show", "127.0.0.1")
        self.assertNotIn("Uptime Kuma", result.stdout)
        self.assertIn("DNS node EU", result.stdout)
        self.assertEqual(self.total(node), 100)

    def test_capacity_cutoff_propagates_over_tls_and_storage_metrics_are_read_only(self):
        a_port, b_port, agent_port = self.reserve(), self.reserve(), self.reserve()
        a = self.node("storage-a", "full", a_port, [])
        b = self.node("storage-b", "full", b_port, [f"https://127.0.0.1:{a_port}"])
        agent = self.node("agent", "forward", agent_port, [f"https://127.0.0.1:{a_port}"], capture=True)
        for node in self.nodes:
            self.start(node)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.sendto(b"one observation", ("127.0.0.1", self.port))
        self.wait_for(lambda: self.total(a) == 1 and self.total(b) == 1)
        self.wait_for(lambda: self.rpc(a, "health")["health"]["storage"]["database_known"])
        usage = self.rpc(a, "health")["health"]["storage"]
        self.assertGreater(usage["database_bytes"], 0)
        self.assertEqual(usage["limit_bytes"], 16 << 20)
        self.assertGreater(usage["files_bytes"], 0)
        self.assertGreater(usage["disk_available_bytes"], 0)
        self.assertLessEqual(usage["headroom_bytes"], usage["disk_available_bytes"])
        self.assertFalse(self.rpc(agent, "health")["health"]["storage"]["enabled"])
        self.stop(agent)
        self.assertFalse(agent["database"].parent.exists())
        for node in (a, b):
            self.stop(node)
        # Model closed observations without delaying the process test by minutes.
        old_window = int(time.time()) // 60 * 60 - 120
        for node in (a, b):
            with closing(sqlite3.connect(str(node["database"]) + ".network.db")) as db, db:
                rows = db.execute("SELECT id,payload FROM net_observations").fetchall()
                for identity, raw in rows:
                    if raw.startswith(b"{"):
                        payload = json.loads(raw)
                        payload.update(window=old_window, first_seen=old_window, last_seen=old_window)
                        raw = json.dumps(payload).encode()
                    # Compact payload timestamps are offsets from the SQL window.
                    db.execute("UPDATE net_observations SET window=?,payload=? WHERE id=?",
                               (old_window, raw, identity))
                db.execute("UPDATE net_ips SET first=?,last=?", (old_window, old_window))
                if node is a:
                    # This is the durable result of capacity eviction, tested
                    # with actual page limits in the Go storage stress tests.
                    db.execute("UPDATE net_storage SET floor=?", (old_window + 60,))
                    db.execute("UPDATE net_meta SET sequence=sequence+1")
        for node in (a, b):
            self.start(node)
        self.wait_for(lambda: self.total(a) == 0 and self.total(b) == 0)
        for node in (a, b):
            with closing(sqlite3.connect(str(node["database"]) + ".network.db")) as db:
                self.assertEqual(db.execute("SELECT floor FROM net_storage").fetchone()[0], old_window + 60)
                self.assertEqual(db.execute("SELECT count(*) FROM net_observations").fetchone()[0], 0)
        self.stop(b)
        self.start(b)
        time.sleep(1.1)
        self.assertEqual(self.total(b), 0)
        self.stop(a)
        result = self.command(a, "top", "--once")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Database:", result.stdout)
        self.assertIn("Disk available:", result.stdout)
        self.assertIn("Estimated write headroom", result.stdout)

    def test_idle_forward_nodes_are_visible_without_storage_writes_and_expire(self):
        port = self.reserve()
        storage = self.node("storage", "full", port, [])
        agent = self.node("quiet-edge", "forward", self.reserve(), [f"https://127.0.0.1:{port}"])
        self.start(storage)
        self.start(agent)

        def node_snapshot(node, role):
            return next((n for n in self.rpc(node, "health").get("network_nodes", [])
                         if n["role"] == role and n["online"]), None)

        incoming = self.wait_for(lambda: node_snapshot(storage, "forward"))
        outgoing = self.wait_for(lambda: node_snapshot(agent, "full"))
        self.assertEqual(incoming["name"], "quiet-edge")
        self.assertEqual(incoming["direction"], "IN")
        self.assertEqual(outgoing["direction"], "OUT")
        self.assertEqual(incoming["state"], "ONLINE")
        self.assertTrue(incoming["last_delivery"].startswith("0001-"))
        self.assertFalse(agent["database"].parent.exists())
        self.assertEqual(self.rpc(agent, "health")["health"]["delivery_acks"], 0)
        with closing(sqlite3.connect(str(storage["database"]) + ".network.db")) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM net_observations").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT sequence FROM net_meta").fetchone()[0], 0)
        for node in (storage, agent):
            result = self.command(node, "nodes", "--json")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["online"], 1)
            result = self.command(node, "top", "--nodes", "--once")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("ONLINE", result.stdout)
            self.assertIn("Nodes online: 1/1", result.stdout)
        self.stop(agent)
        self.wait_for(lambda: any(n["node"] == incoming["node"] and n["state"] == "OFFLINE"
                                  for n in self.rpc(storage, "health").get("network_nodes", [])), seconds=22)
        self.assertFalse(agent["database"].parent.exists())

    def test_full_nodes_report_sync_positions_and_offline_reads_are_stale(self):
        a_port, b_port = self.reserve(), self.reserve()
        a = self.node("storage-a", "full", a_port, [])
        b = self.node("storage-b", "full", b_port, [f"https://127.0.0.1:{a_port}"])
        self.start(a)
        self.start(b)
        self.wait_for(lambda: any(n["sync_known"] and n["online"] and n["direction"] == "BOTH"
                                  for n in self.rpc(b, "health").get("network_nodes", [])))
        self.stop(b)
        result = self.command(b, "nodes", "--json")
        self.assertEqual(result.returncode, 0, result.stderr)
        saved = json.loads(result.stdout)
        self.assertEqual(saved["source"], "stored")
        self.assertEqual(saved["online"], 0)
        self.assertTrue(saved["nodes"])
        self.assertTrue(all(n["state"] == "STALE" and not n["online"] for n in saved["nodes"]))

    def test_compact_copy_requires_stopped_service_and_resumes_exact_history(self):
        node = self.node("compact-source", "full", self.reserve(), [], capture=True)
        self.start(node)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            for _ in range(100):
                client.sendto(b"compact history", ("127.0.0.1", self.port))
        self.wait_for(lambda: self.total(node) == 100)
        target = self.root / "packed.network.db"
        active = self.command(node, "compact", "--output", str(target))
        self.assertNotEqual(active.returncode, 0)
        self.assertIn("stop the network monitor", active.stderr)
        self.assertFalse(target.exists())
        self.stop(node)
        original_database = str(node["database"]) + ".network.db"
        with closing(sqlite3.connect(original_database)) as db:
            identity = db.execute("SELECT node,epoch,sequence FROM net_meta").fetchone()
        result = self.command(node, "compact", "--output", str(target))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Verified", result.stdout)
        self.assertIn("Source retained:", result.stdout)
        with closing(sqlite3.connect(target)) as db:
            self.assertEqual(db.execute("SELECT node,epoch,sequence FROM net_meta").fetchone(), identity)
            self.assertEqual(db.execute("SELECT packets FROM net_totals").fetchone()[0], 100)
        node["config"].write_text(node["config"].read_text().replace(
            f"database: {node['database']}", f"database: {target}"))
        node["database"] = Path(str(target).removesuffix(".network.db"))
        self.start(node)
        self.assertEqual(self.total(node), 100)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.sendto(b"after compact", ("127.0.0.1", self.port))
        self.wait_for(lambda: self.total(node) == 101)
        with closing(sqlite3.connect(original_database)) as db:
            self.assertEqual(db.execute("SELECT packets FROM net_totals").fetchone()[0], 100)
