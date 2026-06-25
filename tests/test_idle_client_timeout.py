import contextlib
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def proc_threads(pid: int) -> int:
    with contextlib.suppress(OSError):
        for line in (Path("/proc") / str(pid) / "status").read_text(encoding="utf-8").splitlines():
            if line.startswith("Threads:"):
                return int(line.split(":", 1)[1].strip())
    return 0


def wait_for_health(port: int, deadline: float):
    last_error = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/health", timeout=1.0) as response:
                if response.status == 200:
                    return
        except Exception as exc:  # noqa: BLE001 - regression test includes process startup races
            last_error = exc
        time.sleep(0.05)
    raise AssertionError(f"proxy-router health endpoint did not become ready: {last_error}")


class IdleClientTimeoutTests(unittest.TestCase):
    def test_idle_pre_protocol_clients_are_capped_and_drained(self):
        mixed_port = find_free_port()
        dashboard_port = find_free_port()
        sockets: list[socket.socket] = []
        errors: list[str] = []
        with tempfile.TemporaryDirectory(prefix="proxy-router-idle-test-") as temp_name:
            temp_dir = Path(temp_name)
            env = os.environ.copy()
            env.update(
                {
                    "PROXY_ROUTER_MAX_ACTIVE_TUNNELS": "16",
                    "PROXY_ROUTER_MAX_ACTIVE_TUNNELS_PER_CLIENT": "16",
                    "PROXY_ROUTER_MAX_ACTIVE_TUNNELS_PER_ADMIN_CLIENT": "16",
                    "PROXY_ROUTER_TUNNEL_IDLE_TIMEOUT_SECONDS": "1",
                }
            )
            process = subprocess.Popen(
                [
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
                    str(temp_dir / "router-config.json"),
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
                    "0.2",
                    "--max-client-handler-threads",
                    "16",
                    "--quiet",
                ],
                cwd=str(REPO_ROOT),
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                wait_for_health(dashboard_port, time.monotonic() + 10.0)
                baseline_threads = proc_threads(process.pid)

                def open_idle_socket():
                    try:
                        sock = socket.create_connection(("127.0.0.1", mixed_port), timeout=1.0)
                    except OSError as exc:
                        errors.append(type(exc).__name__)
                        return
                    sockets.append(sock)

                openers = [threading.Thread(target=open_idle_socket, daemon=True) for _ in range(64)]
                for thread in openers:
                    thread.start()
                for thread in openers:
                    thread.join(timeout=2.0)

                peak_threads = baseline_threads
                deadline = time.monotonic() + 1.5
                while time.monotonic() < deadline:
                    peak_threads = max(peak_threads, proc_threads(process.pid))
                    time.sleep(0.05)

                wait_for_health(dashboard_port, time.monotonic() + 3.0)
                for sock in sockets:
                    with contextlib.suppress(OSError):
                        sock.close()
                time.sleep(0.5)
                final_threads = proc_threads(process.pid)

                self.assertGreater(len(sockets) + len(errors), 0)
                self.assertLessEqual(peak_threads, baseline_threads + 40)
                self.assertLessEqual(final_threads, baseline_threads + 12)
            finally:
                for sock in sockets:
                    with contextlib.suppress(OSError):
                        sock.close()
                process.terminate()
                try:
                    process.wait(timeout=5.0)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5.0)


if __name__ == "__main__":
    unittest.main()
