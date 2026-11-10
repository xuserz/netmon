"""Real binary failure tests; enable only inside an isolated network namespace."""
from contextlib import closing
import datetime
import json
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
class RecoveryTests(unittest.TestCase):
    def setUp(self):
        try:
            probe = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM)
            probe.close()
        except PermissionError:
            self.skipTest("CAP_NET_RAW is required")
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = self.root / "stats.db"
        self.config = self.root / "config.yaml"
        self.server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server.bind(("127.0.0.1", 0))
        self.addCleanup(self.server.close)
        self.port = self.server.getsockname()[1]
        self.config.write_text(f"interface: lo\nport: {self.port}\ndatabase: {self.db}\n"
                               "flush_interval: 1s\nmax_pending_ips: 4\nmax_activity_ips: 8\n"
                               "socket_buffer_mb: 4\nmax_database_mb: 16\n")
        self.log = (self.root / "monitor.log").open("w+")
        self.addCleanup(self.log.close)
        self.process = None
        self.addCleanup(self.stop)
        self.payload = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + b"\0\0\1\0\1"

    def rpc(self, op="health", sort="total"):
        with socket.socket(socket.AF_UNIX) as conn:
            conn.settimeout(2)
            conn.connect(str(self.db) + ".sock")
            conn.sendall(json.dumps({"op": op, "limit": 1000, "sort": sort}).encode() + b"\n")
            with conn.makefile("rb") as file:
                return json.loads(file.readline(2 << 20))

    def wait_for(self, predicate, seconds=8):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            try:
                result = predicate()
                if result:
                    return result
            except (OSError, ValueError, sqlite3.OperationalError):
                pass
            time.sleep(.02)
        self.log.seek(0)
        self.fail("condition timed out\n" + self.log.read())

    def start(self):
        self.process = subprocess.Popen([str(BINARY), "--config", str(self.config), "run"],
                                        stdout=self.log, stderr=self.log)
        self.wait_for(lambda: self.process.poll() is None and self.rpc()["health"]["pid"] == self.process.pid)

    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()

    def send(self, count, clients=1):
        sockets = []
        try:
            for index in range(clients):
                conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                conn.bind((f"127.2.0.{index + 1}", 0))
                sockets.append(conn)
            for index in range(count):
                sockets[index % clients].sendto(self.payload, ("127.0.0.1", self.port))
        finally:
            for conn in sockets:
                conn.close()

    def stored(self):
        with closing(sqlite3.connect(self.db)) as db:
            return db.execute("SELECT coalesce(sum(requests),0) FROM clients").fetchone()[0]

    def test_sigkill_restart_preserves_confirmed_counts(self):
        self.start()
        self.assertEqual(self.rpc()["health"]["sqlite_version"], "3.54.1")
        self.send(100)
        self.wait_for(lambda: self.stored() == 100)
        self.send(20)
        self.wait_for(lambda: self.rpc()["health"]["counted_requests"] == 120)
        self.process.kill()
        self.process.wait(5)
        recovered = self.stored()
        self.assertGreaterEqual(recovered, 100)
        self.assertLessEqual(recovered, 120)  # RAM counters may be lost on SIGKILL.
        with closing(sqlite3.connect(self.db)) as db:
            self.assertEqual(db.execute("PRAGMA quick_check").fetchone()[0], "ok")
        self.start()
        self.send(30)
        self.wait_for(lambda: self.stored() == recovered + 30)
        self.stop()
        self.assertEqual(self.process.returncode, 0)

    def test_writer_stall_keeps_health_live_and_recovers_burst(self):
        self.start()
        blocker = sqlite3.connect(self.db)
        self.addCleanup(blocker.close)
        blocker.execute("BEGIN IMMEDIATE")
        self.send(2000, clients=16)
        first = self.wait_for(lambda: (h if (h := self.rpc()["health"])["blocked_for"] else None))
        next_health = self.wait_for(lambda: (h if (h := self.rpc()["health"])["updated"] != first["updated"] else None))
        before = datetime.datetime.fromisoformat(first["updated"])
        after = datetime.datetime.fromisoformat(next_health["updated"])
        self.assertGreater(after, before)
        self.assertLessEqual(next_health["pending_ips"], 8)
        self.assertGreater(next_health["blocked_for"], 0)
        self.assertGreater(next_health["pending_age"], 0)
        self.assertLess(next_health["counted_requests"], 2000)
        blocker.rollback()
        self.wait_for(lambda: self.rpc()["health"]["counted_requests"] == 2000)
        self.wait_for(lambda: self.stored() == 2000)
        self.assertEqual(self.rpc()["health"]["kernel_drops"], 0)
        self.assertLessEqual(self.rpc()["health"]["activity_entries"], 8)
        activity = self.wait_for(lambda: (r if (r := self.rpc("top", "rate")).get("activity") else None))
        self.assertTrue(activity["activity_partial"])
        self.stop()
        self.assertEqual(self.process.returncode, 0)
