from __future__ import annotations

import base64
import hashlib
import json
import socket
import socketserver
import struct
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit

from .constants import *
from .output import DEBUG_LOGGER, debug_log
from .records import UsageHistoryCache, build_failure_snapshot_from_records
from .util import first_query_value, normalize_history_filter


class ThreadedDashboardServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address, handler_class, *, runtime, router_config):
        super().__init__(server_address, handler_class)
        self.runtime = runtime
        self.dashboard_state = runtime.dashboard_state
        self.history_cache = UsageHistoryCache(runtime.usage_log_path)
        self.router_config = router_config


def build_client_quota_status_map(client_rows, runtime, router_config):
    clients = [item.get("client") for item in client_rows if item.get("client")]
    return runtime.traffic_quota_manager.snapshot_for_clients(clients, router_config)


def build_dashboard_snapshot(server):
    snapshot = server.runtime.dashboard_state.snapshot()
    router_runtime_snapshot = server.router_config.runtime_snapshot()
    router_runtime_snapshot["upstream_status"] = server.runtime.upstream_status.snapshot()
    active_profile = router_runtime_snapshot.get("active_profile") or {}
    active_profile_id = str(active_profile.get("id") or DEFAULT_ROUTING_PROFILE_ID)
    router_config_snapshot = server.router_config.effective_routing_snapshot(profile_id=active_profile_id)
    manager = server.runtime.auto_proxy_failure_manager
    if manager is not None:
        snapshot["recent_failures"] = manager.filter_resolved_failures(
            snapshot.get("recent_failures", []),
            profile_id=active_profile_id,
        )
        review_failures = manager.manual_review_failures(profile_id=active_profile_id)
    else:
        review_failures = []
    if review_failures:
        recent_failures = list(snapshot.get("recent_failures", [])) + review_failures
        recent_failures.sort(key=lambda item: str(item.get("timestamp", "")), reverse=True)
        snapshot["recent_failures"] = recent_failures
    snapshot["failure_summary"] = build_failure_snapshot_from_records(
        snapshot.get("recent_failures", []),
        router_config_snapshot,
    )
    snapshot["client_quota_status"] = build_client_quota_status_map(
        snapshot.get("totals_by_client", []),
        server.runtime,
        server.router_config,
    )
    snapshot["router_runtime"] = router_runtime_snapshot
    return snapshot


def encode_websocket_text_frame(payload_text: str) -> bytes:
    payload = payload_text.encode("utf-8")
    payload_length = len(payload)
    if payload_length < 126:
        header = bytes([0x81, payload_length])
    elif payload_length < 65536:
        header = bytes([0x81, 126]) + struct.pack("!H", payload_length)
    else:
        header = bytes([0x81, 127]) + struct.pack("!Q", payload_length)
    return header + payload


def build_live_update_message(server, event_summary, *, initial: bool = False):
    revision = 0 if initial else int(event_summary.get("revision", 0))
    reasons = [] if initial else list(event_summary.get("reasons") or [])
    return {
        "type": "snapshot",
        "revision": revision,
        "initial": initial,
        "reasons": reasons,
        "history_changed": False if initial else bool(event_summary.get("history_changed")),
        "router_config_changed": False if initial else bool(event_summary.get("router_config_changed")),
        "snapshot": build_dashboard_snapshot(server),
    }

class DashboardRequestHandler(BaseHTTPRequestHandler):
    server_version = "proxy-router-dashboard-api/1.0"

    def log_message(self, fmt, *args):
        if DEBUG_LOGGER.enabled:
            debug_log("dashboard", fmt % args, level="INFO")

    def _send_json(self, payload, status: int = 200):
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self):
        content_length = self.headers.get("Content-Length")
        if not content_length:
            raise ValueError("missing Content-Length header")
        length = int(content_length)
        if length < 0:
            raise ValueError("invalid Content-Length header")
        raw_body = self.rfile.read(length)
        if not raw_body:
            return {}
        return json.loads(raw_body.decode("utf-8"))

    def _is_websocket_upgrade(self) -> bool:
        upgrade = str(self.headers.get("Upgrade") or "").strip().lower()
        connection = str(self.headers.get("Connection") or "").strip().lower()
        return upgrade == "websocket" and "upgrade" in connection

    def _send_websocket_json(self, payload):
        body = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        self.connection.sendall(encode_websocket_text_frame(body))

    def _handle_live_websocket(self):
        websocket_key = str(self.headers.get("Sec-WebSocket-Key") or "").strip()
        if not websocket_key:
            self.send_error(400, "Missing Sec-WebSocket-Key header")
            return

        accept_seed = websocket_key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        accept_value = base64.b64encode(hashlib.sha1(accept_seed.encode("utf-8")).digest()).decode("ascii")

        self.send_response(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept_value)
        self.end_headers()

        try:
            self.connection.settimeout(DASHBOARD_LIVE_HEARTBEAT_SECONDS + 5.0)
        except OSError:
            pass

        last_revision = self.server.runtime.live_updates.current_revision()
        self._send_websocket_json(
            build_live_update_message(self.server, {"revision": last_revision}, initial=True)
        )

        while True:
            event_summary = self.server.runtime.live_updates.wait_for_changes(
                last_revision,
                timeout=DASHBOARD_LIVE_HEARTBEAT_SECONDS,
            )
            if event_summary is None:
                self._send_websocket_json(
                    {
                        "type": "heartbeat",
                        "revision": last_revision,
                    }
                )
                continue

            last_revision = int(event_summary["revision"])
            self._send_websocket_json(build_live_update_message(self.server, event_summary))

    def do_GET(self):
        parsed = urlsplit(self.path)
        route_path = parsed.path

        if route_path == "/api/live":
            if not self._is_websocket_upgrade():
                self.send_error(400, "Expected a WebSocket upgrade request")
                return
            try:
                self._handle_live_websocket()
            except (BrokenPipeError, ConnectionResetError, socket.timeout, OSError):
                return
            return

        if route_path in {"/api/dashboard", "/api/dashboard.json"}:
            self._send_json(build_dashboard_snapshot(self.server))
            return

        if route_path in {"/api/history", "/api/history.json"}:
            query = parse_qs(parsed.query)
            range_key = first_query_value(query, "range") or HISTORY_DEFAULT_RANGE
            proxy_type = normalize_history_filter(first_query_value(query, "proxy_type"))
            client = normalize_history_filter(first_query_value(query, "client"))
            payload = self.server.history_cache.build_history_payload(
                range_key=range_key,
                proxy_type=proxy_type,
                client=client,
            )
            self._send_json(payload)
            return

        if route_path in {"/api/router-config", "/api/router-config.json"}:
            self._send_json(self.server.router_config.snapshot())
            return

        if route_path in {"/api/failures", "/api/failures.json"}:
            snapshot = build_dashboard_snapshot(self.server)
            self._send_json(snapshot.get("failure_summary", {}))
            return

        if route_path not in {"/", "/index.html"}:
            self.send_error(404, "Not Found")
            return

        self._send_json(
            {
                "service": "proxy-router dashboard api",
                "ui": "served separately",
                "endpoints": [
                    "/api/dashboard",
                    "/api/history",
                    "/api/router-config",
                    "/api/failures",
                    "/api/traffic-data/clear",
                    "/api/upstream/check",
                    "/api/live",
                ],
            }
        )

    def do_POST(self):
        parsed = urlsplit(self.path)
        route_path = parsed.path

        if route_path in {"/api/traffic-data/clear", "/api/traffic-data/clear.json"}:
            try:
                self.server.runtime.clear_traffic_data()
                self.server.history_cache.clear()
            except OSError as exc:
                self._send_json({"error": f"failed to clear traffic data: {exc}"}, status=500)
                return

            self._send_json(
                {
                    "ok": True,
                    "snapshot": build_dashboard_snapshot(self.server),
                    "history": self.server.history_cache.build_history_payload(
                        range_key=HISTORY_DEFAULT_RANGE
                    ),
                },
                status=200,
            )
            return

        if route_path in {"/api/upstream/check", "/api/upstream/check.json"}:
            current_config = self.server.router_config.snapshot()
            self.server.runtime.refresh_upstream_status(current_config)
            self._send_json(
                {
                    "ok": True,
                    "status": self.server.runtime.upstream_status.snapshot(),
                },
                status=200,
            )
            return

        if route_path not in {"/api/router-config", "/api/router-config.json"}:
            self.send_error(404, "Not Found")
            return

        try:
            payload = self._read_json_body()
            saved_config = self.server.router_config.update(payload)
        except ValueError as exc:
            self._send_json({"error": str(exc)}, status=400)
            return
        except json.JSONDecodeError as exc:
            self._send_json({"error": f"invalid JSON body: {exc.msg}"}, status=400)
            return
        except OSError as exc:
            self._send_json({"error": f"failed to save router config: {exc}"}, status=500)
            return

        if self.server.runtime.auto_proxy_failure_manager is not None:
            self.server.runtime.auto_proxy_failure_manager.reconcile_config_state()
        self.server.runtime.refresh_upstream_status(saved_config)

        self._send_json(saved_config, status=200)
