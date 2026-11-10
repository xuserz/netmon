"""PTY tests exercise the built executable, terminal restoration and live redraws."""
from contextlib import closing
import datetime
import errno
import json
import socket
import threading
import fcntl
import os
from pathlib import Path
import pty
import select
import signal
import sqlite3
import struct
import subprocess
import sys
import tempfile
import termios
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
BINARY = Path(os.environ.get("NETMON_BINARY", ROOT / "bin/netmon"))


@unittest.skipUnless(BINARY.is_file(), "build bin/netmon first to run terminal integration tests")
class TerminalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.db = Path(self.temp.name) / "stats.db"
        with closing(sqlite3.connect(self.db)) as conn, conn:
            conn.execute("CREATE TABLE clients(ip TEXT PRIMARY KEY,requests INTEGER,first_seen INTEGER,last_seen INTEGER)")
            conn.executemany("INSERT INTO clients VALUES(?,?,?,?)",
                             [(f"192.0.2.{i}", 123456 - i + 1, 1794272400, 1794272400) for i in range(1, 101)])
            conn.execute("CREATE INDEX clients_rank ON clients(requests DESC,ip ASC)")
        self.master, self.slave = pty.openpty()
        self.addCleanup(os.close, self.master)
        self.addCleanup(os.close, self.slave)
        fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack("HHHH", 28, 110, 0, 0))
        self.original = termios.tcgetattr(self.slave)
        self.process = None
        self.data = b""
        self.addCleanup(self.stop)

    def start(self, *args, no_color=False, wait_for=b"192.0.2.1"):
        env = dict(os.environ, TERM="xterm-256color")
        env.pop("NO_COLOR", None)
        if no_color:
            env["NO_COLOR"] = "1"
        self.process = subprocess.Popen([str(BINARY), "--db", str(self.db), "top", "-n", "100", "--interval", "250ms", *args],
                                        stdin=self.slave, stdout=self.slave, stderr=self.slave,
                                        env=env, start_new_session=True)
        self.until(wait_for)

    def until(self, needle, timeout=4):
        deadline = time.monotonic() + timeout
        while needle not in self.data and time.monotonic() < deadline:
            if select.select([self.master], [], [], .05)[0]:
                self.data += os.read(self.master, 65536)
            # poll() can report exit before the terminal's buffered output has
            # been consumed. Stop only once no further PTY data are readable.
            elif self.process and self.process.poll() is not None:
                break
        self.assertIn(needle, self.data, self.data.decode(errors="replace"))

    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(4)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()

    def quit_and_verify_restore(self, use_signal=False):
        if use_signal:
            self.process.send_signal(signal.SIGINT)
        else:
            os.write(self.master, b"q")
        self.process.wait(4)
        self.until(b"\x1b[?1049l")
        self.assertEqual(self.process.returncode, 0, self.data)
        self.assertEqual(termios.tcgetattr(self.slave), self.original)
        self.assertIn(b"\x1b[?25h", self.data)

    def test_colorful_top_redraw_pause_resize_scroll_and_quit(self):
        self.start()
        self.assertIn(b"\x1b[38;5;", self.data)
        self.assertIn(b"123,456", self.data)
        self.data = b""
        os.write(self.master, b" ")
        self.until(b"PAUSED")
        fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack("HHHH", 15, 60, 0, 0))
        self.process.send_signal(signal.SIGWINCH)
        os.write(self.master, b"\x1b[B\x1b[6~")
        self.data = b""
        os.write(self.master, b" ")
        self.until(b"STORED")
        self.quit_and_verify_restore()

    def test_ctrl_c_restores_terminal_and_no_color_is_respected(self):
        self.start(no_color=True)
        self.assertNotIn(b"\x1b[38;5;", self.data)
        self.quit_and_verify_restore(use_signal=True)

    def test_changed_database_appears_without_restarting_top(self):
        self.start()
        with closing(sqlite3.connect(self.db)) as conn, conn:
            conn.execute("UPDATE clients SET requests=987654321 WHERE ip='192.0.2.1'")
        self.until(b"987,654,321")
        self.quit_and_verify_restore()

    def test_pipe_and_once_remain_plain_text(self):
        output = subprocess.check_output([str(BINARY), "--db", str(self.db), "top", "--once", "-n", "3"])
        self.assertNotIn(b"\x1b", output)
        self.assertIn(b"Unique IPs: 100", output)
        self.assertEqual(output.count(b"192.0.2."), 3)

    def live_server(self, slow=False, network=False, storage=None, network_rows=None):
        listener = socket.socket(socket.AF_UNIX)
        try:
            if network:
                directory = Path(self.temp.name) / "run"
                directory.mkdir()
                listener.bind(str(directory / "monitor.sock"))
            else:
                listener.bind(str(self.db) + ".sock")
        except OSError as error:
            listener.close()
            if error.errno == errno.EPERM:
                self.skipTest("sandbox forbids Unix sockets")
            raise
        listener.listen(2)
        listener.settimeout(.1)
        stopped = threading.Event()

        def serve():
            while not stopped.is_set():
                try:
                    conn, _ = listener.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                with conn:
                    conn.settimeout(.3)
                    try:
                        conn.recv(4096)
                        if slow:
                            stopped.wait(3)
                            continue
                        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
                        response = {"source": "live", "health": {"pid": 12345, "interface": "ens3", "port": 53,
                                    "started": now, "updated": now, "counted_requests": 777777,
                                    "pending_requests": 7, "rss_bytes": 15 << 20,"activity_limit":10000},
                                    "totals": {"requests": "777777", "unique_ips": 1},
                                    "activity": [{"ip":"192.0.2.77","rate":123.4,"minute":5678,"share_percent":12.3}],
                                    "clients": [{"ip": "192.0.2.1", "requests": 777777,
                                                 "first_seen": 1794272400, "last_seen": 1794272400}]}
                        if network:
                            response = {"network": True, "source": "live", "snapshot_at": now,
                                "health": {"pid": 12345, "mode": "network", "storage_mode": "forward",
                                           "interface": "ens3", "counted_requests": 777777, "rss_bytes": 15 << 20},
                                "network_totals": {"ips": 1, "packets": 777777, "bytes": 77777700},
                                "network_ips": [{"ip": "192.0.2.77", "packets": 777777,
                                                 "bytes": 77777700, "syn": 12345, "suspicion": 85}]}
                        if network and storage is not None:
                            response["health"]["storage_mode"] = "full"
                            response["health"]["storage"] = storage
                        if network and network_rows is not None:
                            response["network_ips"] = network_rows
                        conn.sendall(json.dumps(response).encode() + b"\n")
                    except OSError:
                        pass
        worker = threading.Thread(target=serve)
        worker.start()

        def cleanup():
            stopped.set()
            listener.close()
            worker.join(4)
        self.addCleanup(cleanup)

    def test_live_counts_come_from_monitor_before_sqlite_flush(self):
        self.live_server()
        self.start()
        self.until(b"777,777")
        self.assertIn(b"LIVE", self.data)
        self.assertIn(b"15.0 MiB", self.data)
        self.quit_and_verify_restore()

    def test_activity_sort_flag_and_keyboard_cycle(self):
        self.live_server()
        self.start("--sort", "rate", wait_for=b"192.0.2.77")
        self.assertIn(b"123.4", self.data)
        self.assertIn(b"5,678", self.data)
        self.assertIn(b"12.3%", self.data)
        self.data = b""
        os.write(self.master, b"s")
        self.until(b"60 complete seconds")
        self.data = b""
        os.write(self.master, b"s")
        self.until(b"total requests")
        self.until(b"192.0.2.1")
        self.quit_and_verify_restore()

    def test_quit_remains_responsive_while_live_request_waits(self):
        self.live_server(slow=True)
        self.start(wait_for=b"Requests")
        started = time.monotonic()
        self.quit_and_verify_restore()
        self.assertLess(time.monotonic() - started, .8)

    def test_suspend_restores_terminal_and_resume_reenters_screen(self):
        self.start()
        self.process.send_signal(signal.SIGTSTP)
        deadline = time.monotonic() + 3
        stopped = False
        while time.monotonic() < deadline:
            pid, status = os.waitpid(self.process.pid, os.WUNTRACED | os.WNOHANG)
            if pid and os.WIFSTOPPED(status):
                stopped = True
                break
            time.sleep(.02)
        try:
            self.assertTrue(stopped, "TUI did not suspend")
            self.assertEqual(termios.tcgetattr(self.slave), self.original)
        finally:
            self.process.send_signal(signal.SIGCONT)
        self.data = b""
        self.until(b"\x1b[?1049h")
        self.quit_and_verify_restore()

    def test_network_forward_rating_color_sort_and_terminal_restore(self):
        self.live_server(network=True)
        config = Path(self.temp.name) / "network.yaml"
        config.write_text(f"mode: network\nstorage:\n  mode: forward\nnetwork:\n  runtime_directory: {Path(self.temp.name) / 'run'}\ncluster:\n  enabled: true\n  key_file: /unused-test-key\n  peers: [https://127.0.0.1:9845]\n")
        self.start("--config", str(config), wait_for=b"192.0.2.77")
        self.assertIn(b"777,777", self.data)
        self.assertIn(b"85", self.data)
        self.assertIn(b"\x1b[38;5;203m", self.data)
        self.until("FORWARD · RAM SAMPLE".encode())
        for kind in (b"total", b"bytes", b"syn", b"score"):
            self.data = b""
            os.write(self.master, b"s")
            self.until(b"sort " + kind)
        self.quit_and_verify_restore()

    def test_exit_sequence_is_read_after_process_exit_and_fragmented_reads(self):
        # A process can exit with several unread chunks still buffered by the PTY.
        # Force small reads so the exit sequence cannot arrive in the first chunk.
        payload = b"final terminal frame\r\n" * 64 + b"\x1b[?25h\x1b[?1049l"
        self.process = subprocess.Popen(
            [sys.executable, "-c", "import os; os.write(1, " + repr(payload) + ")"],
            stdin=self.slave, stdout=self.slave, stderr=self.slave,
            start_new_session=True)
        self.process.wait(4)
        self.assertEqual(self.process.returncode, 0)
        real_read = os.read
        with mock.patch.object(os, "read", side_effect=lambda fd, size: real_read(fd, min(size, 32))):
            self.until(b"\x1b[?1049l")
        self.assertIn(b"\x1b[?25h", self.data)

    def test_network_ip_descriptions_reload_while_top_stays_running(self):
        self.live_server(network=True)
        directory = Path(self.temp.name)
        config = directory / "labels-config.yaml"
        labels = directory / "ip-labels.yaml"
        config.write_text(f"mode: network\nlabels_file: {labels}\nstorage:\n  mode: forward\nnetwork:\n  runtime_directory: {directory / 'run'}\ncluster:\n  enabled: true\n  key_file: /unused-test-key\n  peers: [https://127.0.0.1:9845]\n")
        self.start("--config", str(config), wait_for=b"192.0.2.77")
        pid = self.process.pid
        for kind, description in [("whitelist", "Uptime Kuma"), ("servers", "DNS node EU")]:
            result = subprocess.run([str(BINARY), "--config", str(config), kind, "add", "192.0.2.77", description],
                                    capture_output=True, text=True, timeout=4)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.data = b""
            self.until(description.encode())
        self.until(b"SERVER+WL")
        self.assertIn(b"85", self.data)
        self.assertEqual(self.process.pid, pid)
        result = subprocess.run([str(BINARY), "--config", str(config), "whitelist", "remove", "192.0.2.77"],
                                capture_output=True, text=True, timeout=4)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.quit_and_verify_restore()

    def test_network_storage_space_updates_and_end_reaches_last_ip(self):
        storage = {"enabled": True, "database_known": True, "disk_known": True,
                   "database_bytes": 2 << 20, "limit_bytes": 20 << 30,
                   "wal_bytes": 1 << 20, "files_bytes": 3 << 20,
                   "disk_available_bytes": 30 << 30, "headroom_bytes": 19 << 30}
        rows = [{"ip": f"192.0.2.{i}", "packets": 1000-i} for i in range(1, 101)]
        self.live_server(network=True, storage=storage, network_rows=rows)
        config = Path(self.temp.name) / "network.yaml"
        config.write_text(f"mode: network\nlabels_file: \"\"\nstorage:\n  mode: full\nnetwork:\n  runtime_directory: {Path(self.temp.name) / 'run'}\n")
        self.start("--config", str(config), wait_for=b"192.0.2.1")
        for text in (b"DB 2.0 MiB / 20.0 GiB", b"WAL 1.0 MiB", b"Disk free 30.0 GiB", b"Headroom 19.0 GiB"):
            self.until(text)
        storage["disk_available_bytes"] = 29 << 30
        self.data = b""
        self.until(b"Disk free 29.0 GiB")
        self.data = b""
        os.write(self.master, b"\x1b[F")
        self.until(b"192.0.2.100")
        self.quit_and_verify_restore()
