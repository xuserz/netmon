#!/usr/bin/env python3
"""Paced loopback load test of the real binary. Run in an isolated network namespace."""
import argparse
import json
import os
from pathlib import Path
import signal
import socket
import sqlite3
import struct
import subprocess
import tempfile
import threading
import time


def health(path):
    with socket.socket(socket.AF_UNIX) as conn:
        conn.settimeout(2)
        conn.connect(str(path) + ".sock")
        conn.sendall(b'{"op":"health"}\n')
        with conn.makefile("rb") as file:
            result = json.loads(file.readline(2 << 20))
        if result.get("error"):
            raise RuntimeError(result["error"])
        return result["health"]


def cpu_seconds(pid):
    # Fields 14/15 of proc(5), relative to field 3 after the final ')'.
    values = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return (int(values[11]) + int(values[12])) / os.sysconf("SC_CLK_TCK")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="bin/dnsmon")
    parser.add_argument("--rate", type=int, default=1000)
    parser.add_argument("--seconds", type=int, default=3)
    args = parser.parse_args()
    if not 1 <= args.rate <= 100000 or not 1 <= args.seconds <= 60:
        parser.error("rate must be 1..100000 and seconds 1..60")
    binary = Path(args.binary).resolve()
    with tempfile.TemporaryDirectory(prefix="dnsmon-load-") as temp:
        root = Path(temp)
        database = root / "stats.db"
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(("127.0.0.1", 0))
        server.settimeout(.2)
        port = server.getsockname()[1]
        stopped = threading.Event()

        def drain():
            while not stopped.is_set():
                try:
                    server.recvfrom(65536)
                except socket.timeout:
                    pass
                except OSError:
                    break
        worker = threading.Thread(target=drain)
        worker.start()
        config = root / "config.yaml"
        config.write_text(f"interface: lo\nport: {port}\ndatabase: {database}\nflush_interval: 1s\nmax_database_mb: 16\nmax_wal_mb: 4\nmax_pending_ips: 64\nsocket_buffer_mb: 4\n")
        log = (root / "monitor.log").open("w+")
        process = subprocess.Popen([str(binary), "--config", str(config), "run"],
                                   stdout=log, stderr=log,
                                   env=dict(os.environ, GOMAXPROCS="1"))
        try:
            deadline = time.monotonic() + 10
            while True:
                if process.poll() is not None:
                    log.seek(0)
                    raise RuntimeError("monitor failed to start: " + log.read())
                try:
                    health(database)
                    break
                except (OSError, ValueError):
                    if time.monotonic() > deadline:
                        raise RuntimeError("monitor did not become ready")
                    time.sleep(.02)
            payload = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + b"\0\0\1\0\1"
            expected = args.rate * args.seconds
            cpu_start = cpu_seconds(process.pid)
            started = time.monotonic()
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                batch = max(1, args.rate // 200)
                for index in range(expected):
                    if index % batch == 0:
                        delay = started + index / args.rate - time.monotonic()
                        if delay > 0:
                            time.sleep(delay)
                    client.sendto(payload, ("127.0.0.1", port))
            elapsed = time.monotonic() - started
            cpu = 100 * (cpu_seconds(process.pid) - cpu_start) / max(elapsed, .001)
            deadline = time.monotonic() + 3
            while True:
                metrics = health(database)
                if metrics["counted_requests"] >= expected or time.monotonic() >= deadline:
                    break
                time.sleep(.02)
            process.send_signal(signal.SIGTERM)
            process.wait(10)
            if process.returncode:
                raise RuntimeError("monitor failed during shutdown")
            with sqlite3.connect(database) as db:
                stored = db.execute("SELECT coalesce(sum(requests),0) FROM clients").fetchone()[0]
            report = {"target_requests_per_second": args.rate, "sent": expected,
                      "observed": metrics["counted_requests"], "stored": stored,
                      "kernel_drops": metrics["kernel_drops"],
                      "monitor_cpu_percent_one_core": round(cpu, 2),
                      "monitor_rss_mib": round(metrics["rss_bytes"] / (1 << 20), 2),
                      "elapsed_seconds": round(elapsed, 3)}
            print(json.dumps(report, indent=2))
            if stored != expected or metrics["counted_requests"] != expected or metrics["kernel_drops"]:
                raise RuntimeError("loss/duplicate detected; see the report")
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            stopped.set()
            server.close()
            worker.join(1)
            log.close()


if __name__ == "__main__":
    main()
