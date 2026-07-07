#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import contextlib
import http.client
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def proc_metrics(pid: int) -> dict:
    proc_root = Path("/proc") / str(pid)
    status = {}
    with contextlib.suppress(OSError):
        for line in (proc_root / "status").read_text(encoding="utf-8").splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                parts = value.strip().split()
                if parts:
                    status[key] = parts[0]
    fds = 0
    with contextlib.suppress(OSError):
        fds = len(list((proc_root / "fd").iterdir()))
    return {
        "threads": int(status.get("Threads", "0") or 0),
        "fds": fds,
    }


def close_wait_count(port: int) -> int:
    command = f"ss -Htan state close-wait '( sport = :{port} )' | wc -l"
    result = subprocess.run(command, shell=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False)
    try:
        return int((result.stdout or "0").splitlines()[-1].strip() or "0")
    except (IndexError, ValueError):
        return 0


class BlackholeServer:
    def __init__(self, host: str = "127.0.0.1"):
        self.host = host
        self.port = find_free_port()
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._listener: socket.socket | None = None
        self.accepted = 0

    def start(self):
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind((self.host, self.port))
        self._listener.listen()
        thread = threading.Thread(target=self._accept_loop, daemon=True)
        thread.start()
        self._threads.append(thread)

    def stop(self):
        self._stop.set()
        if self._listener is not None:
            with contextlib.suppress(OSError):
                self._listener.close()

    def _accept_loop(self):
        assert self._listener is not None
        while not self._stop.is_set():
            try:
                client, _ = self._listener.accept()
            except OSError:
                return
            self.accepted += 1
            thread = threading.Thread(target=self._hold_connection, args=(client,), daemon=True)
            thread.start()
            self._threads.append(thread)

    def _hold_connection(self, client: socket.socket):
        with client:
            client.settimeout(0.2)
            while not self._stop.is_set():
                with contextlib.suppress(socket.timeout, OSError):
                    data = client.recv(4096)
                    if not data:
                        return


def build_managed_router_config(args) -> dict:
    credentials = []
    for index in range(max(0, args.client_count)):
        username = f"{args.client_prefix}{index + 1:03d}"
        credentials.append(
            {
                "username": username,
                "password": args.client_password,
                "label": f"Stress client {index + 1}",
                "enabled": True,
            }
        )
    return {
        "client_auth": {
            "enabled": bool(credentials),
            "allow_anonymous": True,
            "credentials": credentials,
        }
    }


def wait_for_dashboard(dashboard_url: str, deadline: float):
    last_error = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(dashboard_url, timeout=1.0) as response:
                if response.status == 200:
                    return
        except Exception as exc:  # noqa: BLE001 - diagnostic tool
            last_error = exc
        time.sleep(0.1)
    raise RuntimeError(f"dashboard did not become ready: {last_error}")


def start_managed_router(args, temp_dir: Path) -> tuple[subprocess.Popen, int, int]:
    mixed_port = find_free_port()
    dashboard_port = find_free_port()
    config_path = temp_dir / "router-config.json"
    config_path.write_text(json.dumps(build_managed_router_config(args), indent=2), encoding="utf-8")
    env = os.environ.copy()
    env.update(
        {
            "PROXY_ROUTER_MAX_ACTIVE_TUNNELS": str(args.max_active),
            "PROXY_ROUTER_MAX_ACTIVE_TUNNELS_PER_CLIENT": str(args.max_per_client),
            "PROXY_ROUTER_MAX_ACTIVE_TUNNELS_PER_ADMIN_CLIENT": str(args.max_per_client),
            "PROXY_ROUTER_MAX_ACTIVE_TUNNELS_PER_CLIENT_DESTINATION": str(args.max_per_client_destination),
            "PROXY_ROUTER_TUNNEL_IDLE_TIMEOUT_SECONDS": str(args.idle_timeout),
        }
    )
    command = [
        sys.executable,
        str(REPO_ROOT / "proxy-router"),
        "--bind",
        "127.0.0.1",
        "--mixed-port",
        str(mixed_port),
        "--dashboard-bind",
        "127.0.0.1",
        "--dashboard-port",
        str(dashboard_port),
        "--router-config-file",
        str(config_path),
        "--usage-log-file",
        str(temp_dir / "usage.log"),
        "--failure-log-file",
        str(temp_dir / "failures.log"),
        "--https-traffic-log-file",
        str(temp_dir / "https-traffic.log"),
        "--client-block-history-file",
        str(temp_dir / "client-block-history.log"),
        "--error-log-file",
        str(temp_dir / "error.log"),
        "--client-header-timeout",
        str(args.client_header_timeout),
        "--max-client-handler-threads",
        str(args.max_client_handler_threads),
        "--quiet",
    ]
    process = subprocess.Popen(
        command,
        cwd=str(REPO_ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    wait_for_dashboard(f"http://127.0.0.1:{dashboard_port}/api/health", time.monotonic() + 10.0)
    return process, mixed_port, dashboard_port


def connect_tunnel(
    proxy_host: str,
    proxy_port: int,
    target_host: str,
    target_port: int,
    *,
    username: str | None,
    password: str,
    half_close: bool,
    connect_timeout: float,
) -> tuple[socket.socket | None, str]:
    sock = socket.create_connection((proxy_host, proxy_port), timeout=connect_timeout)
    sock.settimeout(connect_timeout)
    headers = [
        f"CONNECT {target_host}:{target_port} HTTP/1.1",
        f"Host: {target_host}:{target_port}",
    ]
    if username:
        token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
        headers.append(f"Proxy-Authorization: Basic {token}")
    request = "\r\n".join(headers) + "\r\n\r\n"
    sock.sendall(request.encode("ascii"))
    response = b""
    while b"\r\n\r\n" not in response and len(response) < 8192:
        chunk = sock.recv(4096)
        if not chunk:
            break
        response += chunk
    head = response.decode("iso-8859-1", errors="replace").splitlines()[0] if response else ""
    if " 200 " not in head:
        sock.close()
        return None, head or "no_response"
    if half_close:
        with contextlib.suppress(OSError):
            sock.shutdown(socket.SHUT_WR)
    return sock, "connected"


def dashboard_probe(dashboard_port: int) -> bool:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{dashboard_port}/api/dashboard", timeout=1.0) as response:
            return response.status == http.client.OK
    except Exception:
        return False


def health_probe(dashboard_port: int) -> bool:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{dashboard_port}/api/health", timeout=1.0) as response:
            return response.status == http.client.OK
    except Exception:
        return False


def run_pressure(args) -> dict:
    blackholes = [BlackholeServer() for _ in range(max(1, args.destination_count))]
    for blackhole in blackholes:
        blackhole.start()
    process = None
    clients: list[socket.socket] = []
    idle_clients: list[socket.socket] = []
    with tempfile.TemporaryDirectory(prefix="proxy-router-stress-") as temp_name:
        temp_dir = Path(temp_name)
        if args.managed:
            process, proxy_port, dashboard_port = start_managed_router(args, temp_dir)
            proxy_host = "127.0.0.1"
            process_pid = process.pid
        else:
            proxy_host = args.proxy_host
            proxy_port = args.proxy_port
            dashboard_port = args.dashboard_port
            process_pid = args.pid

        metrics = {
            "attempted": args.tunnels,
            "client_count": args.client_count,
            "destination_count": len(blackholes),
            "connected": 0,
            "rejected": 0,
            "errors": 0,
            "dashboard_probe_failures": 0,
            "health_probe_failures": 0,
            "idle_pre_protocol_attempted": args.idle_pre_protocol,
            "idle_pre_protocol_opened": 0,
            "idle_pre_protocol_errors": 0,
            "threads_peak": 0,
            "fds_peak": 0,
            "close_wait_peak": 0,
        }
        statuses: dict[str, int] = {}
        lock = threading.Lock()

        def open_one(index: int):
            half_close = args.half_close_every > 0 and index % args.half_close_every == 0
            username = None
            if args.client_count > 0:
                username = f"{args.client_prefix}{(index % args.client_count) + 1:03d}"
                destination_index = (index // args.client_count) % len(blackholes)
            else:
                destination_index = index % len(blackholes)
            blackhole = blackholes[destination_index]
            try:
                sock, status = connect_tunnel(
                    proxy_host,
                    proxy_port,
                    blackhole.host,
                    blackhole.port,
                    username=username,
                    password=args.client_password,
                    half_close=half_close,
                    connect_timeout=args.connect_timeout,
                )
            except Exception as exc:  # noqa: BLE001 - diagnostic tool
                status = type(exc).__name__
                sock = None
            with lock:
                statuses[status] = statuses.get(status, 0) + 1
                if sock is None:
                    if "503" in status or "Overloaded" in status:
                        metrics["rejected"] += 1
                    else:
                        metrics["errors"] += 1
                else:
                    clients.append(sock)
                    metrics["connected"] += 1

        threads = []
        for index in range(args.tunnels):
            thread = threading.Thread(target=open_one, args=(index,), daemon=True)
            thread.start()
            threads.append(thread)
            if args.open_delay > 0:
                time.sleep(args.open_delay)
        for thread in threads:
            thread.join(timeout=5.0)

        for _ in range(args.idle_pre_protocol):
            try:
                sock = socket.create_connection((proxy_host, proxy_port), timeout=args.connect_timeout)
                idle_clients.append(sock)
                metrics["idle_pre_protocol_opened"] += 1
            except Exception:
                metrics["idle_pre_protocol_errors"] += 1

        sample_until = time.monotonic() + args.duration
        while time.monotonic() < sample_until:
            if process_pid:
                point = proc_metrics(process_pid)
                metrics["threads_peak"] = max(metrics["threads_peak"], point["threads"])
                metrics["fds_peak"] = max(metrics["fds_peak"], point["fds"])
            metrics["close_wait_peak"] = max(metrics["close_wait_peak"], close_wait_count(proxy_port))
            if not dashboard_probe(dashboard_port):
                metrics["dashboard_probe_failures"] += 1
            if not health_probe(dashboard_port):
                metrics["health_probe_failures"] += 1
            time.sleep(args.sample_interval)

        for sock in clients:
            with contextlib.suppress(OSError):
                sock.close()
        for sock in idle_clients:
            with contextlib.suppress(OSError):
                sock.close()
        time.sleep(args.drain_seconds)

        final_close_wait = close_wait_count(proxy_port)
        final_dashboard_ok = dashboard_probe(dashboard_port)
        final_health_ok = health_probe(dashboard_port)
        final_runtime = {}
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{dashboard_port}/api/dashboard", timeout=2.0) as response:
                payload = json.loads(response.read().decode("utf-8"))
                final_runtime = (payload.get("router_runtime") or {}).get("tunnel_limits") or {}
        except Exception:
            pass
        active_final = int(final_runtime.get("active_total") or 0)
        thread_limit = args.max_client_handler_threads if args.max_client_handler_threads > 0 else args.max_active
        thread_budget = args.baseline_threads + thread_limit + args.thread_headroom
        passed = (
            final_close_wait == 0
            and active_final == 0
            and final_dashboard_ok
            and final_health_ok
            and metrics["errors"] == 0
            and metrics["dashboard_probe_failures"] == 0
            and metrics["health_probe_failures"] == 0
            and (not metrics["threads_peak"] or metrics["threads_peak"] <= thread_budget)
        )
        result = {
            "passed": passed,
            "proxy_port": proxy_port,
            "dashboard_port": dashboard_port,
            "target_port": blackholes[0].port,
            "target_ports": [blackhole.port for blackhole in blackholes],
            "accepted_by_target": sum(blackhole.accepted for blackhole in blackholes),
            "accepted_by_destination": {
                f"{blackhole.host}:{blackhole.port}": blackhole.accepted for blackhole in blackholes
            },
            "status_counts": statuses,
            "limits": {
                "max_active": args.max_active,
                "max_per_client": args.max_per_client,
                "max_per_client_destination": args.max_per_client_destination,
                "idle_timeout_seconds": args.idle_timeout,
                "client_header_timeout_seconds": args.client_header_timeout,
                "max_client_handler_threads": args.max_client_handler_threads,
            },
            **metrics,
            "final": {
                "close_wait": final_close_wait,
                "dashboard_ok": final_dashboard_ok,
                "health_ok": final_health_ok,
                "active_tunnels": active_final,
                "thread_budget": thread_budget,
                "tunnel_limits": final_runtime,
            },
        }
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5.0)
            if not passed and args.include_process_output:
                result["process_output"] = {
                    "stdout": (process.stdout.read() if process.stdout else "")[-4000:],
                    "stderr": (process.stderr.read() if process.stderr else "")[-4000:],
                }
        for blackhole in blackholes:
            blackhole.stop()
        return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Stress proxy-router tunnel pressure and report resource behavior.")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--managed", action="store_true", help="Start a temporary local proxy-router process.")
    mode.add_argument("--external", action="store_true", help="Use an already running local proxy-router process.")
    parser.add_argument("--proxy-host", default="127.0.0.1")
    parser.add_argument("--proxy-port", type=int, default=8799)
    parser.add_argument("--dashboard-port", type=int, default=8798)
    parser.add_argument("--pid", type=int, default=0, help="Proxy-router PID for external mode metrics.")
    parser.add_argument("--tunnels", type=int, default=160)
    parser.add_argument("--max-active", type=int, default=40)
    parser.add_argument("--max-per-client", type=int, default=20)
    parser.add_argument("--max-per-client-destination", type=int, default=0)
    parser.add_argument("--client-count", type=int, default=0)
    parser.add_argument("--client-prefix", default="admin")
    parser.add_argument("--client-password", default="stress-secret")
    parser.add_argument("--destination-count", type=int, default=1)
    parser.add_argument("--idle-timeout", type=float, default=1.0)
    parser.add_argument("--client-header-timeout", type=float, default=5.0)
    parser.add_argument("--max-client-handler-threads", type=int, default=256)
    parser.add_argument("--idle-pre-protocol", type=int, default=0)
    parser.add_argument("--duration", type=float, default=20.0)
    parser.add_argument("--connect-timeout", type=float, default=8.0)
    parser.add_argument("--drain-seconds", type=float, default=2.0)
    parser.add_argument("--sample-interval", type=float, default=0.25)
    parser.add_argument("--open-delay", type=float, default=0.0)
    parser.add_argument("--half-close-every", type=int, default=3)
    parser.add_argument("--baseline-threads", type=int, default=8)
    parser.add_argument("--thread-headroom", type=int, default=40)
    parser.add_argument("--include-process-output", action="store_true")
    parser.add_argument("--json", action="store_true", help="Print compact JSON only.")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.external and (not args.proxy_port or not args.dashboard_port):
        parser.error("--external requires --proxy-port and --dashboard-port")
    result = run_pressure(args)
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
