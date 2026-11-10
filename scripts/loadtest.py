#!/usr/bin/env python3
"""Paced loopback load test of the real binary. Run in an isolated network namespace."""
from contextlib import closing
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
    parser.add_argument("--mode", choices=("dns", "network"), default="dns")
    parser.add_argument("--binary", default="bin/netmon")
    parser.add_argument("--rate", type=int, default=1000)
    parser.add_argument("--seconds", type=int, default=3)
    parser.add_argument("--clients", type=int, default=1)
    parser.add_argument("--live", action="store_true", help="poll top snapshots while sending")
    parser.add_argument("--burst-size", type=int, default=0, help="packets per paced burst; 0 uses small batches")
    args = parser.parse_args()
    if not 1 <= args.rate <= 100000 or not 1 <= args.seconds <= 60:
        parser.error("rate must be 1..100000 and seconds 1..60")
    if not 1 <= args.clients <= 10000:
        parser.error("clients must be 1..10000")
    if not 0 <= args.burst_size <= args.rate * args.seconds:
        parser.error("burst-size must be 0..total requests")
    binary = Path(args.binary).resolve()
    with tempfile.TemporaryDirectory(prefix="netmon-load-") as temp:
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
        socket_base = database
        stored_database = database
        if args.mode == "network":
            runtime = root / "run"
            socket_base = runtime / "monitor"
            stored_database = Path(str(database) + ".network.db")
            config.write_text(config.read_text() + f"mode: network\nnetwork:\n  runtime_directory: {runtime}\n  ports: [{port}]\n")
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
                    health(socket_base)
                    break
                except (OSError, ValueError):
                    if time.monotonic() > deadline:
                        raise RuntimeError("monitor did not become ready")
                    time.sleep(.02)
            payload = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + b"\0\0\1\0\1"
            if args.mode == "network":
                payload = b"non-DNS incoming network load"
            expected = args.rate * args.seconds
            cpu_start = cpu_seconds(process.pid)
            started = time.monotonic()
            clients = []
            for index in range(args.clients):
                client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                client.bind((f"127.{1 + index // 65536}.{index // 256 % 256}.{index % 256}", 0))
                clients.append(client)
            live_results = {"responses": 0, "max_requests": 0, "activity_responses": 0}
            def poll_top():
                while not stopped.wait(.05):
                    try:
                        with socket.socket(socket.AF_UNIX) as conn:
                            conn.settimeout(2)
                            conn.connect(str(socket_base) + ".sock")
                            conn.sendall(json.dumps({"op":"top","limit":1000,"sort":("score" if args.mode == "network" else "rate") if live_results["responses"] % 2 else "total"}).encode() + b"\n")
                            with conn.makefile("rb") as file:
                                result = json.loads(file.readline(2 << 20))
                            if not result.get("error"):
                                live_results["responses"] += 1
                                if result.get("network_ips") if args.mode == "network" else result.get("activity"):
                                    live_results["activity_responses"] += 1
                                live_results["max_requests"] = max(live_results["max_requests"], int(result["network_totals"]["packets"] if args.mode == "network" else result["totals"]["requests"]))
                    except (OSError, ValueError):
                        pass
            viewer = threading.Thread(target=poll_top)
            if args.live:
                viewer.start()
            try:
                batch = args.burst_size or max(1, args.rate // 200)
                for index in range(expected):
                    if index % batch == 0:
                        delay = started + index / args.rate - time.monotonic()
                        if delay > 0:
                            time.sleep(delay)
                    clients[index % len(clients)].sendto(payload, ("127.0.0.1", port))
            finally:
                for client in clients:
                    client.close()
            elapsed = time.monotonic() - started
            cpu = 100 * (cpu_seconds(process.pid) - cpu_start) / max(elapsed, .001)
            deadline = time.monotonic() + 3
            while True:
                metrics = health(socket_base)
                if metrics["counted_requests"] >= expected or time.monotonic() >= deadline:
                    break
                time.sleep(.02)
            process.send_signal(signal.SIGTERM)
            process.wait(10)
            if process.returncode:
                raise RuntimeError("monitor failed during shutdown")
            with closing(sqlite3.connect(stored_database)) as db:
                if args.mode == "network":
                    unique, stored = db.execute("SELECT ips,packets FROM net_totals WHERE id=1").fetchone()
                else:
                    unique = db.execute("SELECT count(*) FROM clients").fetchone()[0]
                    stored = db.execute("SELECT coalesce(sum(requests),0) FROM clients").fetchone()[0]
            report = {"mode": args.mode, "target_packets_or_dns_queries_per_second": args.rate, "sent": expected,
                      "observed": metrics["counted_requests"], "stored": stored,
                      "unique_clients": unique, "concurrent_live_view": args.live,
                      "burst_size": args.burst_size,
                      "activity_responses": live_results["activity_responses"],
                      "live_responses": live_results["responses"],
                      "max_live_count": live_results["max_requests"],
                      "kernel_drops": metrics["kernel_drops"],
                      "monitor_cpu_percent_one_core": round(cpu, 2),
                      "monitor_rss_mib": round(metrics["rss_bytes"] / (1 << 20), 2),
                      "elapsed_seconds": round(elapsed, 3)}
            print(json.dumps(report, indent=2))
            if args.live and (live_results["responses"] == 0 or live_results["max_requests"] == 0 or live_results["activity_responses"] == 0):
                raise RuntimeError("live view never returned nonempty counters")
            if unique != min(args.clients, expected) or stored != expected or metrics["counted_requests"] != expected or metrics["kernel_drops"]:
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
            if "viewer" in locals() and args.live:
                viewer.join(3)
            log.close()


if __name__ == "__main__":
    main()
