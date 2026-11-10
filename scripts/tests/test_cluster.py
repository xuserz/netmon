"""Three actual DNS monitors exchanging counters over mutually authenticated TLS."""
from contextlib import closing
import json
import os
from pathlib import Path
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
class ClusterTests(unittest.TestCase):
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
        self.assertEqual(self.key.stat().st_mode & 0o777, 0o600)
        self.nodes = []
        self.addCleanup(self.stop_all)
        self.payload = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + b"\0\0\1\0\1"
        cluster_ports = []
        for _ in range(3):
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                cluster_ports.append(listener.getsockname()[1])
        for index in range(3):
            directory = self.root / str(index)
            directory.mkdir()
            sink = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sink.bind(("127.0.0.1", 0))
            self.addCleanup(sink.close)
            db = directory / "stats.db"
            config = directory / "config.yaml"
            peers = "[]" if index == 0 else f'["https://127.0.0.1:{cluster_ports[0]}"]'
            config.write_text(f"interface: lo\nport: {sink.getsockname()[1]}\ndatabase: {db}\n"
                              "flush_interval: 1s\nmax_database_mb: 16\n"
                              f"cluster:\n  enabled: true\n  listen: 127.0.0.1:{cluster_ports[index]}\n"
                              f"  advertise: https://127.0.0.1:{cluster_ports[index]}\n"
                              f"  peers: {peers}\n  key_file: {self.key}\n  name: node-{index}\n  sync_interval: 1s\n")
            log = (directory / "monitor.log").open("w+")
            self.addCleanup(log.close)
            self.nodes.append({"config": config, "db": db, "sink": sink, "log": log, "process": None})
        for node in self.nodes:
            self.start(node)

    def rpc(self, node, local=False):
        with socket.socket(socket.AF_UNIX) as conn:
            conn.settimeout(2)
            conn.connect(str(node["db"]) + ".sock")
            conn.sendall(json.dumps({"op": "top", "limit": 20, "local": local}).encode() + b"\n")
            with conn.makefile("rb") as file:
                return json.loads(file.readline(2 << 20))

    def wait_for(self, predicate, timeout=15):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                if predicate():
                    return
            except (OSError, ValueError, sqlite3.OperationalError):
                pass
            time.sleep(.04)
        output = []
        for node in self.nodes:
            node["log"].seek(0)
            output.append(node["log"].read())
        self.fail("cluster did not converge\n" + "\n".join(output))

    def start(self, node):
        node["process"] = subprocess.Popen([str(BINARY), "--config", str(node["config"]), "run"],
                                           stdout=node["log"], stderr=node["log"])
        self.wait_for(lambda: node["process"].poll() is None and self.rpc(node)["health"]["pid"] == node["process"].pid)

    def stop_all(self):
        for node in self.nodes:
            process = node["process"]
            if process and process.poll() is None:
                process.terminate()
                try:
                    process.wait(10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()

    def send(self, node, count):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            for _ in range(count):
                client.sendto(self.payload, node["sink"].getsockname())

    def total(self, node):
        with closing(sqlite3.connect(str(node["db"]) + ".cluster.db")) as db:
            return db.execute("SELECT coalesce(sum(requests),0) FROM clients").fetchone()[0]

    def command(self, node, *args):
        return subprocess.run([str(BINARY), "--config", str(node["config"]), *args],
                              capture_output=True, text=True, timeout=5, check=True).stdout

    def test_real_capture_shared_totals_local_scope_and_restart(self):
        for index, node in enumerate(self.nodes):
            self.send(node, (index + 1) * 100)
        self.wait_for(lambda: all(self.total(node) == 600 for node in self.nodes))
        for index, node in enumerate(self.nodes):
            self.assertIn("Total requests: 600", self.command(node, "stats"))
            self.assertIn(f"Total requests: {(index + 1) * 100}", self.command(node, "stats", "--local"))
            self.wait_for(lambda n=node: self.rpc(n)["totals"]["requests"] == "600")
            self.assertTrue(self.rpc(node)["cluster"])
            self.assertFalse(self.rpc(node, local=True)["cluster"])
            self.assertIn("https://127.0.0.1:", self.command(node, "nodes"))
        node = self.nodes[2]
        identity = self.rpc(node)["health"]["cluster_node"]
        node["process"].kill()
        node["process"].wait(5)
        self.send(self.nodes[0], 50)
        self.wait_for(lambda: self.total(self.nodes[0]) == 650 and self.total(self.nodes[1]) == 650)
        self.start(node)
        self.wait_for(lambda: self.total(node) == 650)
        self.assertEqual(self.rpc(node)["health"]["cluster_node"], identity)
        time.sleep(1.1)
        self.assertTrue(all(self.total(n) == 650 for n in self.nodes))
