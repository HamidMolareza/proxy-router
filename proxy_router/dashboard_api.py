from __future__ import annotations

import base64
import hashlib
import json
import socket
import socketserver
import struct
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit

from .config import RuleSuggestionConflictError
from .constants import *
from .output import DEBUG_LOGGER, debug_log
from .records import HttpsTrafficCache, UsageHistoryCache, build_failure_snapshot_from_records
from .util import client_identity_from_username, first_query_value, normalize_history_filter


DASHBOARD_SCOPES = {"overview", "users", "failures", "proxies", "quotas", "routing", "https-status", "full"}
DASHBOARD_LIVE_SCOPES = DASHBOARD_SCOPES - {"full"}
DASHBOARD_SCOPE_REASON_MAP = {
    "failures": {"failure", "clear", "router-config"},
    "https-status": {"https-interception", "router-config", "clear"},
    "proxies": {"usage", "proxy-status", "router-config", "clear"},
    "quotas": {"usage", "router-config", "clear"},
    "routing": {"rule-suggestions", "network-profile", "router-config", "failure", "clear"},
    "users": {"usage", "connections", "router-config", "clear"},
}


class ThreadedDashboardServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address, handler_class, *, runtime, router_config):
        super().__init__(server_address, handler_class)
        self.runtime = runtime
        self.dashboard_state = runtime.dashboard_state
        self.history_cache = UsageHistoryCache(runtime.usage_log_path)
        self.https_traffic_cache = HttpsTrafficCache(runtime.https_traffic_log_path)
        self.router_config = router_config


def build_client_quota_status_map(client_rows, runtime, router_config):
    clients = [item.get("client") for item in client_rows if item.get("client")]
    return runtime.traffic_quota_manager.snapshot_for_clients(clients, router_config)


def build_client_quota_group_rows(snapshot, runtime, router_config_snapshot, router_config):
    totals_by_client = {
        str(item.get("client") or "").strip(): item
        for item in snapshot.get("totals_by_client", [])
        if str(item.get("client") or "").strip()
    }
    rows = []
    for group in router_config_snapshot.get("client_quota_groups", []):
        if not group.get("enabled", True):
            continue
        members = [str(member or "").strip() for member in group.get("members") or [] if str(member or "").strip()]
        proxy_types = set()
        last_seen_at = None
        row = {
            "id": str(group.get("id") or "").strip(),
            "target": f"group:{str(group.get('id') or '').strip()}",
            "label": str(group.get("label") or group.get("id") or "").strip(),
            "enabled": True,
            "members": members,
            "active_connections": 0,
            "count": 0,
            "uploaded_bytes": 0,
            "downloaded_bytes": 0,
            "total_bytes": 0,
            "proxy_types": [],
            "last_seen_at": None,
            "quota": runtime.traffic_quota_manager.evaluate_client_quota_group(group, router_config),
        }
        for member in members:
            member_total = totals_by_client.get(member)
            if member_total is None:
                continue
            row["active_connections"] += int(member_total.get("active_connections") or 0)
            row["count"] += int(member_total.get("count") or 0)
            row["uploaded_bytes"] += int(member_total.get("uploaded_bytes") or 0)
            row["downloaded_bytes"] += int(member_total.get("downloaded_bytes") or 0)
            row["total_bytes"] += int(member_total.get("total_bytes") or 0)
            proxy_types.update(str(item) for item in (member_total.get("proxy_types") or []) if str(item))
            member_last_seen = str(member_total.get("last_seen_at") or "").strip()
            if member_last_seen and (last_seen_at is None or member_last_seen > last_seen_at):
                last_seen_at = member_last_seen
        row["proxy_types"] = sorted(proxy_types)
        row["last_seen_at"] = last_seen_at
        rows.append(row)
    rows.sort(key=lambda item: (-int(item.get("total_bytes") or 0), str(item.get("id") or "")))
    return rows


def build_known_client_rows(snapshot, router_config_snapshot, client_presence_snapshot=None):
    rows_by_client = {}
    presence_by_client = (
        (client_presence_snapshot or {}).get("clients", {})
        if isinstance(client_presence_snapshot, dict)
        else {}
    )

    def safe_int(value):
        try:
            return int(value or 0)
        except (TypeError, ValueError):
            return 0

    configured_user_ids = {
        client_identity_from_username(credential.get("username"))
        for credential in (router_config_snapshot.get("client_auth") or {}).get("credentials", [])
        if client_identity_from_username(credential.get("username"))
    }

    def ensure_row(client: str):
        normalized_client = str(client or "").strip()
        if not normalized_client:
            return None
        if normalized_client.startswith("user:") and normalized_client not in configured_user_ids:
            return None
        row = rows_by_client.get(normalized_client)
        if row is None:
            if normalized_client.startswith("user:"):
                kind = "user"
            elif "/" in normalized_client:
                kind = "network"
            else:
                kind = "ip"
            row = {
                "client": normalized_client,
                "kind": kind,
                "configured": False,
                "credential_enabled": None,
                "label": "",
                "username": normalized_client[5:] if normalized_client.startswith("user:") else "",
                "source_ips": set(),
                "proxy_types": set(),
                "active_connections": 0,
                "request_count": 0,
                "total_bytes": 0,
                "uploaded_bytes": 0,
                "downloaded_bytes": 0,
                "last_seen_at": None,
                "presence_state": None,
                "presence_vpn_ip": "",
                "presence_last_activity_at": None,
                "presence_last_handshake_at": None,
                "presence_offline_reason": None,
                "active_gateway_sessions": 0,
                "terminated_gateway_sessions": 0,
            }
            rows_by_client[normalized_client] = row
        return row

    def apply_last_seen(row, timestamp: str | None):
        normalized_timestamp = str(timestamp or "").strip() or None
        if row is not None and normalized_timestamp and (
            row["last_seen_at"] is None or normalized_timestamp > str(row["last_seen_at"])
        ):
            row["last_seen_at"] = normalized_timestamp

    for credential in (router_config_snapshot.get("client_auth") or {}).get("credentials", []):
        row = ensure_row(client_identity_from_username(credential.get("username")))
        if row is None:
            continue
        row["configured"] = True
        row["credential_enabled"] = bool(credential.get("enabled", True))
        row["label"] = str(credential.get("label") or "").strip() or row["label"]
        row["username"] = str(credential.get("username") or "").strip() or row["username"]

    for block in router_config_snapshot.get("client_blocks", []):
        row = ensure_row(block.get("client"))
        if row is not None:
            row["configured"] = True

    for total in snapshot.get("totals_by_client", []):
        row = ensure_row(total.get("client"))
        if row is None:
            continue
        row["active_connections"] = max(row["active_connections"], int(total.get("active_connections", 0)))
        row["request_count"] = int(total.get("count", 0))
        row["uploaded_bytes"] = int(total.get("uploaded_bytes", 0))
        row["downloaded_bytes"] = int(total.get("downloaded_bytes", 0))
        row["total_bytes"] = int(total.get("total_bytes", 0))
        row["proxy_types"].update(total.get("proxy_types") or [])
        apply_last_seen(row, total.get("last_seen_at"))

    for client, active_connections in (snapshot.get("active_by_client") or {}).items():
        row = ensure_row(client)
        if row is not None:
            row["active_connections"] = max(row["active_connections"], int(active_connections or 0))

    for client_ip, mapped_client in (snapshot.get("identity_by_client_ip") or {}).items():
        row = ensure_row(mapped_client)
        if row is not None and client_ip and client_ip != mapped_client:
            row["source_ips"].add(str(client_ip))

    for client, presence in presence_by_client.items():
        row = ensure_row(client)
        if row is None or not isinstance(presence, dict):
            continue
        row["presence_state"] = presence.get("state")
        row["presence_vpn_ip"] = str(presence.get("vpn_ip") or "").strip()
        row["presence_last_activity_at"] = presence.get("last_activity_at")
        row["presence_last_handshake_at"] = presence.get("last_handshake_at")
        row["presence_offline_reason"] = presence.get("offline_reason")
        row["active_gateway_sessions"] = safe_int(presence.get("active_gateway_sessions"))
        row["terminated_gateway_sessions"] = safe_int(presence.get("terminated_session_count"))
        if row["presence_vpn_ip"] and row["presence_vpn_ip"] != row["client"]:
            row["source_ips"].add(row["presence_vpn_ip"])

    for record in [*(snapshot.get("recent_requests") or []), *(snapshot.get("recent_failures") or [])]:
        row = ensure_row(record.get("client"))
        if row is None:
            continue
        row["proxy_types"].add(str(record.get("proxy_type") or ""))
        row["label"] = str(record.get("client_auth_label") or "").strip() or row["label"]
        row["username"] = str(record.get("client_auth_username") or "").strip() or row["username"]
        client_ip = str(record.get("client_ip") or "").strip()
        if client_ip and client_ip != row["client"]:
            row["source_ips"].add(client_ip)
        apply_last_seen(row, record.get("timestamp"))

    rows = [
        {
            **row,
            "proxy_types": sorted(item for item in row["proxy_types"] if item),
            "source_ips": sorted(row["source_ips"]),
        }
        for row in rows_by_client.values()
    ]
    rows.sort(key=lambda item: item.get("client", ""))
    rows.sort(key=lambda item: str(item.get("last_seen_at") or ""), reverse=True)
    rows.sort(key=lambda item: int(item.get("active_connections", 0)), reverse=True)
    return rows


def build_client_block_status_map(client_rows, router_config):
    status_map = {}
    for item in client_rows:
        client = item.get("client")
        if not client:
            continue
        evaluation = router_config.find_client_block(client)
        if evaluation is not None:
            status_map[client] = evaluation
    return status_map


def build_router_runtime_dashboard_snapshot(server):
    router_runtime_snapshot = server.router_config.runtime_snapshot()
    router_runtime_snapshot["upstream_status"] = server.runtime.upstream_status.snapshot()
    proxy_status = getattr(server.runtime, "proxy_status", None)
    if proxy_status is not None:
        router_runtime_snapshot["proxy_status"] = proxy_status.snapshot()
    router_runtime_snapshot["https_interception_status"] = server.runtime.https_interception_status(
        server.router_config.https_interception_settings()
    )
    return router_runtime_snapshot


def _filtered_recent_failures(server, snapshot, active_profile_id: str):
    manager = server.runtime.auto_proxy_failure_manager
    if manager is not None:
        recent_failures = manager.filter_resolved_failures(
            snapshot.get("recent_failures", []),
            profile_id=active_profile_id,
        )
        review_failures = manager.manual_review_failures(profile_id=active_profile_id)
    else:
        recent_failures = list(snapshot.get("recent_failures", []))
        review_failures = []
    if review_failures:
        recent_failures = list(recent_failures) + review_failures
        recent_failures.sort(key=lambda item: str(item.get("timestamp", "")), reverse=True)
    return recent_failures


def build_dashboard_overview_snapshot(server):
    snapshot = server.runtime.dashboard_state.snapshot()
    snapshot.pop("recent_failures", None)
    snapshot["router_runtime"] = build_router_runtime_dashboard_snapshot(server)
    return snapshot


def build_dashboard_failures_snapshot(server):
    snapshot = server.runtime.dashboard_state.snapshot()
    router_runtime_snapshot = build_router_runtime_dashboard_snapshot(server)
    active_profile = router_runtime_snapshot.get("active_profile") or {}
    active_profile_id = str(active_profile.get("id") or DEFAULT_ROUTING_PROFILE_ID)
    routing_snapshot = server.router_config.effective_routing_snapshot(profile_id=active_profile_id)
    recent_failures = _filtered_recent_failures(server, snapshot, active_profile_id)
    return {
        "recent_failures": recent_failures,
        "failure_summary": build_failure_snapshot_from_records(
            recent_failures,
            routing_snapshot,
        ),
    }


def build_dashboard_users_snapshot(server):
    snapshot = server.runtime.dashboard_state.snapshot()
    full_router_config_snapshot = server.router_config.snapshot()
    client_presence = getattr(server.runtime, "client_presence", None)
    client_presence_snapshot = client_presence.snapshot() if client_presence is not None else {}
    known_clients = build_known_client_rows(
        snapshot,
        full_router_config_snapshot,
        client_presence_snapshot,
    )
    return {
        "known_clients": known_clients,
        "client_presence": client_presence_snapshot,
        "client_block_status": build_client_block_status_map(
            known_clients,
            server.router_config,
        ),
    }


def build_dashboard_quotas_snapshot(server):
    snapshot = server.runtime.dashboard_state.snapshot()
    totals_by_client = snapshot.get("totals_by_client", [])
    full_router_config_snapshot = server.router_config.snapshot()
    return {
        "totals_by_client": totals_by_client,
        "client_quota_status": build_client_quota_status_map(
            totals_by_client,
            server.runtime,
            server.router_config,
        ),
        "quota_group_rows": build_client_quota_group_rows(
            snapshot,
            server.runtime,
            full_router_config_snapshot,
            server.router_config,
        ),
    }


def build_dashboard_proxies_snapshot(server):
    snapshot = server.runtime.dashboard_state.snapshot()
    full_router_config_snapshot = server.router_config.snapshot()
    return {
        "proxy_quota_status": server.runtime.traffic_quota_manager.proxy_snapshot(
            full_router_config_snapshot.get("proxies", []),
            [row.get("client") for row in snapshot.get("totals_by_client", [])],
        ),
    }


def build_dashboard_routing_snapshot(server):
    rule_suggestion_manager = getattr(server.runtime, "rule_suggestion_manager", None)
    if rule_suggestion_manager is not None:
        rule_suggestions = rule_suggestion_manager.snapshot(include_current_conflicts=True)
    else:
        rule_suggestions = []
    return {
        "router_runtime": build_router_runtime_dashboard_snapshot(server),
        "rule_suggestions": rule_suggestions,
    }


def build_dashboard_https_status_snapshot(server):
    return {
        "router_runtime": {
            "https_interception_status": server.runtime.https_interception_status(
                server.router_config.https_interception_settings()
            )
        }
    }


def build_dashboard_snapshot(server, *, scope: str = "overview"):
    normalized_scope = normalize_dashboard_scope(scope, allow_full=True)
    if normalized_scope == "overview":
        return build_dashboard_overview_snapshot(server)
    if normalized_scope == "failures":
        return build_dashboard_failures_snapshot(server)
    if normalized_scope == "users":
        return build_dashboard_users_snapshot(server)
    if normalized_scope == "quotas":
        return build_dashboard_quotas_snapshot(server)
    if normalized_scope == "proxies":
        return build_dashboard_proxies_snapshot(server)
    if normalized_scope == "routing":
        return build_dashboard_routing_snapshot(server)
    if normalized_scope == "https-status":
        return build_dashboard_https_status_snapshot(server)
    if normalized_scope != "full":
        return build_dashboard_overview_snapshot(server)

    snapshot = build_dashboard_overview_snapshot(server)
    snapshot.update(build_dashboard_failures_snapshot(server))
    snapshot.update(build_dashboard_users_snapshot(server))
    snapshot.update(build_dashboard_quotas_snapshot(server))
    snapshot.update(build_dashboard_proxies_snapshot(server))
    routing_snapshot = build_dashboard_routing_snapshot(server)
    snapshot["rule_suggestions"] = routing_snapshot.get("rule_suggestions", [])
    snapshot["router_runtime"] = {
        **snapshot.get("router_runtime", {}),
        **routing_snapshot.get("router_runtime", {}),
    }
    return snapshot


def normalize_dashboard_scope(scope: str | None, *, allow_full: bool = False):
    normalized_scope = str(scope or "overview").strip().lower()
    allowed_scopes = DASHBOARD_SCOPES if allow_full else DASHBOARD_LIVE_SCOPES
    if normalized_scope not in allowed_scopes:
        return "overview"
    return normalized_scope


def dashboard_scope_matches_reasons(scope: str, reasons, *, initial: bool = False):
    normalized_scope = normalize_dashboard_scope(scope)
    if initial or normalized_scope == "overview":
        return True
    normalized_reasons = {str(reason or "").strip() for reason in (reasons or [])}
    if "clear" in normalized_reasons or "router-config" in normalized_reasons:
        return True
    return bool(DASHBOARD_SCOPE_REASON_MAP.get(normalized_scope, set()) & normalized_reasons)


def merge_dashboard_scope_snapshot(base, patch):
    merged = dict(base or {})
    patch = dict(patch or {})
    base_runtime = merged.get("router_runtime")
    patch_runtime = patch.pop("router_runtime", None)
    if isinstance(base_runtime, dict) or isinstance(patch_runtime, dict):
        merged["router_runtime"] = {
            **(base_runtime if isinstance(base_runtime, dict) else {}),
            **(patch_runtime if isinstance(patch_runtime, dict) else {}),
        }
    merged.update(patch)
    return merged


def build_dashboard_live_snapshot(server, *, scope: str, reasons, initial: bool = False):
    normalized_scope = normalize_dashboard_scope(scope)
    snapshot = build_dashboard_snapshot(server, scope="overview")
    if normalized_scope != "overview" and dashboard_scope_matches_reasons(
        normalized_scope,
        reasons,
        initial=initial,
    ):
        snapshot = merge_dashboard_scope_snapshot(
            snapshot,
            build_dashboard_snapshot(server, scope=normalized_scope),
        )
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


def build_live_update_message(server, event_summary, *, initial: bool = False, scope: str = "overview"):
    revision = 0 if initial else int(event_summary.get("revision", 0))
    reasons = [] if initial else list(event_summary.get("reasons") or [])
    normalized_scope = normalize_dashboard_scope(scope)
    return {
        "type": "snapshot",
        "revision": revision,
        "initial": initial,
        "scope": normalized_scope,
        "reasons": reasons,
        "history_changed": False if initial else bool(event_summary.get("history_changed")),
        "https_traffic_changed": False if initial else bool(event_summary.get("https_traffic_changed")),
        "router_config_changed": False if initial else bool(event_summary.get("router_config_changed")),
        "snapshot": build_dashboard_live_snapshot(
            server,
            scope=normalized_scope,
            reasons=reasons,
            initial=initial,
        ),
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

    def _send_bytes(self, body: bytes, *, content_type: str, filename: str | None = None, status: int = 200):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        if filename:
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
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

    def _bearer_token(self):
        header = str(self.headers.get("Authorization") or "").strip()
        scheme, _, token = header.partition(" ")
        if scheme.lower() != "bearer":
            return ""
        return token.strip()

    def _require_admin_api_token(self) -> bool:
        if not self.server.router_config.admin_api_requires_auth():
            return True
        if self.server.router_config.verify_admin_api_token(
            self._bearer_token(),
            client_ip=self.client_address[0] if self.client_address else None,
        ):
            return True
        self.send_response(401)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("WWW-Authenticate", 'Bearer realm="proxy-router-admin"')
        body = b'{"error": "admin API token is required"}'
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        return False

    def _is_websocket_upgrade(self) -> bool:
        upgrade = str(self.headers.get("Upgrade") or "").strip().lower()
        connection = str(self.headers.get("Connection") or "").strip().lower()
        return upgrade == "websocket" and "upgrade" in connection

    def _send_websocket_json(self, payload):
        body = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        self.connection.sendall(encode_websocket_text_frame(body))

    def _handle_live_websocket(self, *, scope: str = "overview"):
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
            build_live_update_message(
                self.server,
                {"revision": last_revision},
                initial=True,
                scope=scope,
            )
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
            self._send_websocket_json(build_live_update_message(self.server, event_summary, scope=scope))

    def do_GET(self):
        parsed = urlsplit(self.path)
        route_path = parsed.path

        if route_path == "/api/live":
            if not self._is_websocket_upgrade():
                self.send_error(400, "Expected a WebSocket upgrade request")
                return
            try:
                query = parse_qs(parsed.query)
                self._handle_live_websocket(scope=first_query_value(query, "scope") or "overview")
            except (BrokenPipeError, ConnectionResetError, socket.timeout, OSError):
                return
            return

        if route_path in {"/api/dashboard", "/api/dashboard.json"}:
            self._send_json(build_dashboard_snapshot(self.server))
            return

        dashboard_scope_prefix = "/api/dashboard/"
        if route_path.startswith(dashboard_scope_prefix):
            scope = route_path[len(dashboard_scope_prefix):].removesuffix(".json")
            if scope not in DASHBOARD_SCOPES:
                self._send_json({"error": "unknown dashboard scope"}, status=404)
                return
            self._send_json(build_dashboard_snapshot(self.server, scope=scope))
            return

        if route_path in {"/api/history", "/api/history.json"}:
            query = parse_qs(parsed.query)
            range_key = first_query_value(query, "range") or HISTORY_DEFAULT_RANGE
            proxy_type = normalize_history_filter(first_query_value(query, "proxy_type"))
            client = normalize_history_filter(first_query_value(query, "client"))
            upstream_proxy_id = normalize_history_filter(first_query_value(query, "upstream_proxy_id"))
            timezone_name = first_query_value(query, "timezone")
            timezone_offset_minutes = first_query_value(query, "timezone_offset_minutes")
            payload = self.server.history_cache.build_history_payload(
                range_key=range_key,
                proxy_type=proxy_type,
                client=client,
                upstream_proxy_id=upstream_proxy_id,
                timezone_name=timezone_name,
                timezone_offset_minutes=timezone_offset_minutes,
            )
            self._send_json(payload)
            return

        if route_path in {"/api/history/requests", "/api/history/requests.json"}:
            query = parse_qs(parsed.query)

            def parse_optional_int(key):
                value = first_query_value(query, key)
                try:
                    return int(value) if value not in {None, ""} else None
                except ValueError:
                    return None

            payload = self.server.history_cache.query_records(
                client=normalize_history_filter(first_query_value(query, "client")),
                client_ip=normalize_history_filter(first_query_value(query, "client_ip")),
                proxy_type=normalize_history_filter(first_query_value(query, "proxy_type")),
                upstream_proxy_id=normalize_history_filter(first_query_value(query, "upstream_proxy_id")),
                route_label=normalize_history_filter(first_query_value(query, "route_label")),
                host=first_query_value(query, "host"),
                method=normalize_history_filter(first_query_value(query, "method")),
                status_code=first_query_value(query, "status_code"),
                search=first_query_value(query, "search"),
                sort=first_query_value(query, "sort"),
                direction=first_query_value(query, "direction"),
                page=parse_optional_int("page"),
                page_size=parse_optional_int("page_size"),
                max_results=parse_optional_int("max_results"),
            )
            self._send_json(payload)
            return

        if route_path in {"/api/router-config", "/api/router-config.json"}:
            self._send_json(self.server.router_config.public_snapshot())
            return

        if route_path in {"/api/admin-api/status", "/api/admin-api/status.json"}:
            self._send_json(self.server.router_config.admin_api_status())
            return

        if route_path in {"/api/routing/decide", "/api/routing/decide.json"}:
            query = parse_qs(parsed.query)
            host = first_query_value(query, "host")
            if not host:
                self._send_json({"error": "host is required"}, status=400)
                return
            self._send_json(
                self.server.router_config.decide(
                    host,
                    client_id=first_query_value(query, "client_id"),
                    client_ip=first_query_value(query, "client_ip"),
                )
            )
            return

        if route_path in {"/api/rule-suggestions", "/api/rule-suggestions.json"}:
            manager = getattr(self.server.runtime, "rule_suggestion_manager", None)
            if manager is None:
                self._send_json({"suggestions": []})
                return
            self._send_json({"suggestions": manager.snapshot(include_current_conflicts=True)})
            return

        if route_path in {"/api/https-interception/status", "/api/https-interception/status.json"}:
            self._send_json(
                self.server.runtime.https_interception_status(
                    self.server.router_config.https_interception_settings()
                )
            )
            return

        if route_path in {"/api/https-interception/ca.crt", "/api/https-interception/ca.pem"}:
            try:
                body = self.server.runtime.https_interception.ca_certificate_pem()
            except Exception as exc:
                self._send_json({"error": f"failed to load HTTPS interception CA: {exc}"}, status=500)
                return
            self._send_bytes(
                body,
                content_type="application/x-x509-ca-cert",
                filename="proxy-router-ca.crt",
            )
            return

        if route_path in {"/api/https-traffic", "/api/https-traffic.json"}:
            query = parse_qs(parsed.query)
            limit_text = first_query_value(query, "limit")
            try:
                limit = int(limit_text) if limit_text else None
            except ValueError:
                limit = None
            payload = self.server.https_traffic_cache.query(
                client=normalize_history_filter(first_query_value(query, "client")),
                host=first_query_value(query, "host"),
                method=normalize_history_filter(first_query_value(query, "method")),
                status_code=first_query_value(query, "status_code"),
                search=first_query_value(query, "search"),
                sort=first_query_value(query, "sort"),
                direction=first_query_value(query, "direction"),
                limit=limit,
            )
            self._send_json(payload)
            return

        if route_path.startswith("/api/https-traffic/"):
            request_id = route_path.rsplit("/", 1)[-1]
            detail = self.server.https_traffic_cache.detail(request_id)
            if detail is None:
                self._send_json({"error": "HTTPS traffic record not found"}, status=404)
                return
            self._send_json(detail)
            return

        if route_path in {"/api/failures", "/api/failures.json"}:
            snapshot = build_dashboard_snapshot(self.server, scope="failures")
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
                    "/api/history/requests",
                    "/api/router-config",
                    "/api/router-config/preview",
                    "/api/admin-api/status",
                    "/api/admin-api/tokens",
                    "/api/routing/decide",
                    "/api/rule-suggestions",
                    "/api/rule-suggestions/clear",
                    "/api/https-interception/status",
                    "/api/https-interception/ca.crt",
                    "/api/https-traffic",
                    "/api/failures",
                    "/api/traffic-data/clear",
                    "/api/upstream/check",
                    "/api/proxies/check",
                    "/api/live",
                ],
            }
        )

    def do_POST(self):
        parsed = urlsplit(self.path)
        route_path = parsed.path

        if route_path in {"/api/traffic-data/clear", "/api/traffic-data/clear.json"}:
            if not self._require_admin_api_token():
                return
            try:
                self.server.runtime.clear_traffic_data()
                self.server.history_cache.clear()
                self.server.https_traffic_cache.clear()
            except OSError as exc:
                self._send_json({"error": f"failed to clear traffic data: {exc}"}, status=500)
                return

            self._send_json(
                {
                    "ok": True,
                    "snapshot": build_dashboard_snapshot(self.server, scope="full"),
                    "history": self.server.history_cache.build_history_payload(
                        range_key=HISTORY_DEFAULT_RANGE
                    ),
                },
                status=200,
            )
            return

        if route_path in {"/api/rule-suggestions/clear", "/api/rule-suggestions/clear.json"}:
            if not self._require_admin_api_token():
                return
            manager = getattr(self.server.runtime, "rule_suggestion_manager", None)
            if manager is None:
                self._send_json({"error": "rule suggestions are unavailable"}, status=503)
                return
            try:
                result = manager.clear_history()
            except OSError as exc:
                self._send_json({"error": f"failed to clear rule suggestions: {exc}"}, status=500)
                return
            self._send_json(
                {
                    "ok": True,
                    "cleared": result,
                    "suggestions": manager.snapshot(include_current_conflicts=True),
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

        if route_path in {"/api/proxies/check", "/api/proxies/check.json"}:
            current_config = self.server.router_config.snapshot()
            self._send_json(
                {
                    "ok": True,
                    **self.server.runtime.check_upstream_proxies(current_config),
                },
                status=200,
            )
            return

        if route_path in {"/api/router-config/preview", "/api/router-config/preview.json"}:
            try:
                payload = self._read_json_body()
                result = self.server.router_config.preview_update(payload)
            except ValueError as exc:
                self._send_json({"ok": False, "error": str(exc), "issues": []}, status=400)
                return
            except json.JSONDecodeError as exc:
                self._send_json({"ok": False, "error": f"invalid JSON body: {exc.msg}", "issues": []}, status=400)
                return
            self._send_json(result, status=200 if result.get("ok") else 409)
            return

        if route_path in {"/api/admin-api/tokens", "/api/admin-api/tokens.json"}:
            if self.server.router_config.admin_api_requires_auth() and not self._require_admin_api_token():
                return
            try:
                payload = self._read_json_body() if self.headers.get("Content-Length") else {}
                self._send_json(
                    self.server.router_config.create_admin_api_token((payload or {}).get("name")),
                    status=201,
                )
            except (ValueError, json.JSONDecodeError) as exc:
                message = f"invalid JSON body: {exc.msg}" if isinstance(exc, json.JSONDecodeError) else str(exc)
                self._send_json({"error": message}, status=400)
            return

        if route_path.startswith("/api/admin-api/tokens/") and route_path.endswith("/delete"):
            if not self._require_admin_api_token():
                return
            parts = [part for part in route_path.split("/") if part]
            if len(parts) != 5 or parts[:3] != ["api", "admin-api", "tokens"]:
                self.send_error(404, "Not Found")
                return
            try:
                self._send_json({"ok": True, "status": self.server.router_config.delete_admin_api_token(parts[3])})
            except KeyError:
                self._send_json({"error": "admin API token not found"}, status=404)
            return

        if route_path.startswith("/api/rule-suggestions/") and (
            route_path.endswith("/approve") or route_path.endswith("/reject")
        ):
            if not self._require_admin_api_token():
                return
            manager = getattr(self.server.runtime, "rule_suggestion_manager", None)
            if manager is None:
                self._send_json({"error": "rule suggestions are unavailable"}, status=503)
                return
            parts = [part for part in route_path.split("/") if part]
            if len(parts) != 4 or parts[0] != "api" or parts[1] != "rule-suggestions":
                self.send_error(404, "Not Found")
                return
            suggestion_id = parts[2]
            action = parts[3]
            try:
                payload = self._read_json_body() if self.headers.get("Content-Length") else {}
                if action == "approve":
                    result = manager.approve(suggestion_id)
                    saved_config = result.get("router_config")
                    if self.server.runtime.auto_proxy_failure_manager is not None:
                        self.server.runtime.auto_proxy_failure_manager.reconcile_config_state()
                    self.server.runtime.refresh_upstream_status(saved_config)
                    self._send_json(
                        {
                            "ok": True,
                            "suggestion": result.get("suggestion"),
                            "router_config": saved_config,
                            "suggestions": manager.snapshot(include_current_conflicts=True),
                        },
                        status=200,
                    )
                    return
                if action == "reject":
                    suggestion = manager.reject(suggestion_id, message=str((payload or {}).get("message") or ""))
                    self._send_json(
                        {
                            "ok": True,
                            "suggestion": suggestion,
                            "suggestions": manager.snapshot(include_current_conflicts=True),
                        },
                        status=200,
                    )
                    return
            except KeyError:
                self._send_json({"error": "rule suggestion not found"}, status=404)
                return
            except RuleSuggestionConflictError as exc:
                self._send_json(
                    {"error": str(exc), "rule": exc.rule, "conflicts": exc.conflicts},
                    status=409,
                )
                return
            except ValueError as exc:
                self._send_json({"error": str(exc)}, status=400)
                return
            except json.JSONDecodeError as exc:
                self._send_json({"error": f"invalid JSON body: {exc.msg}"}, status=400)
                return
            except OSError as exc:
                self._send_json({"error": f"failed to update rule suggestion: {exc}"}, status=500)
                return

            self.send_error(404, "Not Found")
            return

        if route_path not in {"/api/router-config", "/api/router-config.json"}:
            self.send_error(404, "Not Found")
            return

        if not self._require_admin_api_token():
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
