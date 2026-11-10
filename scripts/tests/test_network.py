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
                          f"storage:\n  mode: {role}\n  retention: 24h\n  queue_memory_mb: 1\n"
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
