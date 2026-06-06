from __future__ import annotations

import json
import errno
import queue
import socket
import threading
import time
import uuid
from collections import deque
from datetime import datetime
from pathlib import Path

from .constants import *
from .certificates import HttpsCertificateManager
from .records import ClientBlockHistoryStore, build_failure_snapshot_from_records
from .traffic import AutoProxyFailureManager, HttpsDiscoveryManager, HttpsInterceptionTrustManager, TrafficQuotaManager
from .util import *

PROXY_CONNECTION_FAILURE_THRESHOLD = 3

class DashboardState:
    def __init__(
        self,
        recent_limit: int = RECENT_REQUEST_LIMIT,
        recent_failure_limit: int = RECENT_FAILURE_LIMIT,
    ):
        self._lock = threading.Lock()
        self.started_at = datetime.now().astimezone().isoformat(timespec="seconds")
        self._active_by_proxy = {}
        self._active_by_client = {}
        self._identity_by_client_ip = {}
        self._totals_by_proxy = {}
        self._totals_by_route = {}
        self._totals_by_client = {}
        self._totals_by_upstream_proxy = {}
        self._recent_requests = deque(maxlen=recent_limit)
        self._recent_failures = deque(maxlen=recent_failure_limit)

    def clear_traffic_data(self):
        with self._lock:
            self._totals_by_proxy = {}
            self._totals_by_route = {}
            self._totals_by_client = {}
            self._totals_by_upstream_proxy = {}
            self._recent_requests.clear()
            self._recent_failures.clear()

    def _increment_active_client_locked(self, client: str):
        self._active_by_client[client] = self._active_by_client.get(client, 0) + 1

    def _decrement_active_client_locked(self, client: str):
        current_client_count = self._active_by_client.get(client, 0)
        if current_client_count <= 1:
            self._active_by_client.pop(client, None)
        else:
            self._active_by_client[client] = current_client_count - 1

    def client_connected(self, proxy_label: str, client: str):
        with self._lock:
            self._active_by_proxy[proxy_label] = self._active_by_proxy.get(proxy_label, 0) + 1
            self._increment_active_client_locked(client)

    def client_disconnected(self, proxy_label: str, client: str):
        with self._lock:
            current_proxy_count = self._active_by_proxy.get(proxy_label, 0)
            if current_proxy_count <= 1:
                self._active_by_proxy.pop(proxy_label, None)
            else:
                self._active_by_proxy[proxy_label] = current_proxy_count - 1

            self._decrement_active_client_locked(client)

    def client_reidentified(self, previous_client: str, next_client: str):
        if not previous_client or not next_client or previous_client == next_client:
            return
        with self._lock:
            self._decrement_active_client_locked(previous_client)
            self._increment_active_client_locked(next_client)

    def record_request(
        self,
        *,
        proxy_label: str,
        kind: str,
        client: str,
        destination: str,
        uploaded_bytes: int,
        downloaded_bytes: int,
        method: str | None,
        timestamp: str,
        route_label: str | None = None,
        matched_rule: dict | None = None,
        profile_id: str | None = None,
        status_code: int | None = None,
        client_ip: str | None = None,
        client_auth_type: str | None = None,
        client_auth_username: str | None = None,
        client_auth_label: str | None = None,
        duration_ms: int | None = None,
        upstream_setup_ms: int | None = None,
        relay_ms: int | None = None,
        upstream_retry_count: int | None = None,
        upstream_retry_delay_ms: int | None = None,
        upstream_proxy_id: str | None = None,
        upstream_proxy_name: str | None = None,
        upstream_proxy_access_mode: str | None = None,
        proxy_failover_count: int | None = None,
    ):
        with self._lock:
            summary = self._totals_by_proxy.setdefault(proxy_label, empty_usage_summary())
            total_bytes = uploaded_bytes + downloaded_bytes
            add_usage_to_summary(
                summary,
                uploaded_bytes=uploaded_bytes,
                downloaded_bytes=downloaded_bytes,
                total_bytes=total_bytes,
                duration_ms=duration_ms,
                upstream_setup_ms=upstream_setup_ms,
                relay_ms=relay_ms,
            )

            route_bucket = route_bucket_from_label(route_label)
            route_summary = self._totals_by_route.setdefault(route_bucket, empty_usage_summary())
            add_usage_to_summary(
                route_summary,
                uploaded_bytes=uploaded_bytes,
                downloaded_bytes=downloaded_bytes,
                total_bytes=total_bytes,
                duration_ms=duration_ms,
                upstream_setup_ms=upstream_setup_ms,
                relay_ms=relay_ms,
            )

            client_summary = self._totals_by_client.setdefault(client, empty_client_usage_summary())
            add_usage_to_summary(
                client_summary,
                uploaded_bytes=uploaded_bytes,
                downloaded_bytes=downloaded_bytes,
                total_bytes=total_bytes,
                duration_ms=duration_ms,
                upstream_setup_ms=upstream_setup_ms,
                relay_ms=relay_ms,
            )
            client_summary["proxy_types"].add(proxy_label)
            client_summary["last_seen_at"] = timestamp
            if client_ip and client and client != client_ip:
                self._identity_by_client_ip[str(client_ip)] = str(client)
            if upstream_proxy_id:
                upstream_summary = self._totals_by_upstream_proxy.setdefault(str(upstream_proxy_id), empty_usage_summary())
                add_usage_to_summary(
                    upstream_summary,
                    uploaded_bytes=uploaded_bytes,
                    downloaded_bytes=downloaded_bytes,
                    total_bytes=total_bytes,
                    duration_ms=duration_ms,
                    upstream_setup_ms=upstream_setup_ms,
                    relay_ms=relay_ms,
                )

            request = {
                "timestamp": timestamp,
                "proxy_type": proxy_label,
                "kind": kind,
                "client": client,
                "destination": destination,
                "uploaded_bytes": uploaded_bytes,
                "downloaded_bytes": downloaded_bytes,
                "total_bytes": total_bytes,
                "method": method or kind.upper(),
                "route_label": route_label or "direct",
                "matched_rule": matched_rule,
                "profile_id": profile_id or DEFAULT_ROUTING_PROFILE_ID,
                "status_code": status_code,
                "client_ip": client_ip,
                "client_auth_type": client_auth_type,
                "client_auth_username": client_auth_username,
                "client_auth_label": client_auth_label,
                "upstream_proxy_id": upstream_proxy_id,
                "upstream_proxy_name": upstream_proxy_name,
                "upstream_proxy_access_mode": upstream_proxy_access_mode,
                "proxy_failover_count": proxy_failover_count,
            }
            apply_usage_performance_fields(
                request,
                total_bytes=total_bytes,
                duration_ms=duration_ms,
                upstream_setup_ms=upstream_setup_ms,
                relay_ms=relay_ms,
                upstream_retry_count=upstream_retry_count,
                upstream_retry_delay_ms=upstream_retry_delay_ms,
            )
            self._recent_requests.appendleft(request)

    def record_failure(
        self,
        *,
        proxy_label: str,
        client: str,
        method: str,
        destination: str,
        host: str | None,
        port: int | None,
        error: str,
        context: str,
        timestamp: str,
        route_label: str | None = None,
        matched_rule: dict | None = None,
        profile_id: str | None = None,
        status_code: int | None = None,
        client_ip: str | None = None,
        client_auth_type: str | None = None,
        client_auth_username: str | None = None,
        client_auth_label: str | None = None,
        duration_ms: int | None = None,
        upstream_setup_ms: int | None = None,
        upstream_retry_count: int | None = None,
        upstream_retry_delay_ms: int | None = None,
        upstream_proxy_id: str | None = None,
        upstream_proxy_name: str | None = None,
        upstream_proxy_access_mode: str | None = None,
        proxy_failover_count: int | None = None,
    ):
        with self._lock:
            failure = {
                "timestamp": timestamp,
                "proxy_type": proxy_label,
                "client": client,
                "method": method,
                "destination": destination,
                "host": host,
                "port": port,
                "error": error,
                "context": context,
                "route_label": route_label or "direct",
                "matched_rule": matched_rule,
                "profile_id": profile_id or DEFAULT_ROUTING_PROFILE_ID,
                "client_ip": client_ip,
                "client_auth_type": client_auth_type,
                "client_auth_username": client_auth_username,
                "client_auth_label": client_auth_label,
                "upstream_proxy_id": upstream_proxy_id,
                "upstream_proxy_name": upstream_proxy_name,
                "upstream_proxy_access_mode": upstream_proxy_access_mode,
                "proxy_failover_count": proxy_failover_count,
            }
            apply_failure_performance_fields(
                failure,
                duration_ms=duration_ms,
                upstream_setup_ms=upstream_setup_ms,
                upstream_retry_count=upstream_retry_count,
                upstream_retry_delay_ms=upstream_retry_delay_ms,
            )
            self._recent_failures.appendleft(failure)

    def snapshot(self):
        with self._lock:
            totals_by_proxy = {
                proxy_type: summary.copy() for proxy_type, summary in self._totals_by_proxy.items()
            }
            totals_by_route = {
                route_type: summary.copy() for route_type, summary in self._totals_by_route.items()
            }
            overall = empty_usage_summary()
            for summary in totals_by_proxy.values():
                merge_usage_summary(overall, summary)

            active_by_proxy = dict(sorted(self._active_by_proxy.items()))
            active_by_client = dict(
                sorted(self._active_by_client.items(), key=lambda item: (-item[1], item[0]))
            )
            totals_by_client = []
            totals_by_upstream_proxy = {
                proxy_id: summary.copy()
                for proxy_id, summary in self._totals_by_upstream_proxy.items()
            }
            for client_ip in set(self._active_by_client) | set(self._totals_by_client):
                usage = self._totals_by_client.get(client_ip)
                if usage is None:
                    usage = empty_client_usage_summary()
                totals_by_client.append(
                    {
                        "client": client_ip,
                        "count": usage["count"],
                        "active_connections": self._active_by_client.get(client_ip, 0),
                        "uploaded_bytes": usage["uploaded_bytes"],
                        "downloaded_bytes": usage["downloaded_bytes"],
                        "total_bytes": usage["total_bytes"],
                        "duration_sample_count": usage.get("duration_sample_count", 0),
                        "duration_sample_bytes": usage.get("duration_sample_bytes", 0),
                        "duration_ms_total": usage.get("duration_ms_total", 0),
                        "duration_ms_avg": usage.get("duration_ms_avg"),
                        "duration_ms_max": usage.get("duration_ms_max"),
                        "upstream_setup_sample_count": usage.get("upstream_setup_sample_count", 0),
                        "upstream_setup_ms_total": usage.get("upstream_setup_ms_total", 0),
                        "upstream_setup_ms_avg": usage.get("upstream_setup_ms_avg"),
                        "upstream_setup_ms_max": usage.get("upstream_setup_ms_max"),
                        "relay_sample_count": usage.get("relay_sample_count", 0),
                        "relay_ms_total": usage.get("relay_ms_total", 0),
                        "relay_ms_avg": usage.get("relay_ms_avg"),
                        "relay_ms_max": usage.get("relay_ms_max"),
                        "throughput_bps": usage.get("throughput_bps"),
                        "proxy_types": sorted(usage["proxy_types"]),
                        "last_seen_at": usage["last_seen_at"],
                    }
                )
            totals_by_client.sort(
                key=lambda item: (-item["total_bytes"], -item["count"], item["client"])
            )
            recent_requests = list(self._recent_requests)
            recent_failures = list(self._recent_failures)
            identity_by_client_ip = dict(self._identity_by_client_ip)

        return {
            "started_at": self.started_at,
            "overall": overall,
            "totals_by_proxy": totals_by_proxy,
                "totals_by_route": totals_by_route,
                "totals_by_upstream_proxy": totals_by_upstream_proxy,
            "totals_by_client": totals_by_client,
            "active_by_proxy": active_by_proxy,
            "active_by_client": active_by_client,
            "identity_by_client_ip": identity_by_client_ip,
            "recent_requests": recent_requests,
            "latest_request": recent_requests[0] if recent_requests else None,
            "recent_failures": recent_failures,
        }

    def failure_snapshot(self, router_config_snapshot):
        with self._lock:
            recent_failures = list(self._recent_failures)

        return build_failure_snapshot_from_records(recent_failures, router_config_snapshot)


class ClientPresenceStore:
    def __init__(self):
        self._path: Path | None = None

    def configure(self, presence_file: Path | None):
        self._path = presence_file

    def snapshot(self):
        if self._path is None:
            return {}
        def safe_int(value):
            try:
                return int(value or 0)
            except (TypeError, ValueError):
                return 0

        try:
            with self._path.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return {}
        if not isinstance(payload, dict):
            return {}
        clients = payload.get("clients")
        if not isinstance(clients, dict):
            return {}
        normalized_clients = {}
        for raw_client, raw_state in clients.items():
            client = str(raw_client or "").strip()
            if not client or not isinstance(raw_state, dict):
                continue
            state = str(raw_state.get("state") or "unknown").strip().lower()
            if state not in {"online", "offline", "unknown"}:
                state = "unknown"
            normalized_clients[client] = {
                "state": state,
                "vpn_ip": str(raw_state.get("vpn_ip") or "").strip(),
                "last_activity_at": str(raw_state.get("last_activity_at") or "").strip() or None,
                "last_handshake_at": str(raw_state.get("last_handshake_at") or "").strip() or None,
                "active_gateway_sessions": safe_int(raw_state.get("active_gateway_sessions")),
                "terminated_session_count": safe_int(raw_state.get("terminated_session_count")),
                "offline_reason": str(raw_state.get("offline_reason") or "").strip() or None,
            }
        return {
            "version": safe_int(payload.get("version")) or 1,
            "generated_at": str(payload.get("generated_at") or "").strip() or None,
            "source": str(payload.get("source") or "").strip() or None,
            "clients": normalized_clients,
        }


class DashboardLiveUpdateHub:
    def __init__(self):
        self._lock = threading.Lock()
        self._condition = threading.Condition(self._lock)
        self._revision = 0
        self._events = deque(maxlen=DASHBOARD_LIVE_EVENT_BACKLOG)
        self._pending_debounced_reasons = set()
        self._debounce_timer = None
        self._last_emit_monotonic = 0.0

    def current_revision(self) -> int:
        with self._lock:
            return self._revision

    def notify(self, reason: str):
        normalized_reason = str(reason or "dashboard").strip() or "dashboard"
        if normalized_reason in {"usage", "https-traffic", "connections"}:
            with self._condition:
                now = time.monotonic()
                elapsed = now - self._last_emit_monotonic
                if elapsed < DASHBOARD_LIVE_DEBOUNCE_SECONDS:
                    self._pending_debounced_reasons.add(normalized_reason)
                    if self._debounce_timer is None:
                        delay = max(0.0, DASHBOARD_LIVE_DEBOUNCE_SECONDS - elapsed)
                        self._debounce_timer = threading.Timer(delay, self._flush_debounced)
                        self._debounce_timer.daemon = True
                        self._debounce_timer.start()
                    return
            self._emit(normalized_reason)
            return

        self._emit(normalized_reason)

    def _emit(self, normalized_reason: str):
        event = {
            "revision": 0,
            "reason": normalized_reason,
            "history_changed": normalized_reason in {"usage", "clear"},
            "https_traffic_changed": normalized_reason in {"https-traffic", "clear"},
            "router_config_changed": normalized_reason == "router-config",
        }
        with self._condition:
            self._last_emit_monotonic = time.monotonic()
            self._revision += 1
            event["revision"] = self._revision
            self._events.append(event)
            self._condition.notify_all()

    def _flush_debounced(self):
        with self._condition:
            reasons = sorted(self._pending_debounced_reasons)
            self._pending_debounced_reasons.clear()
            self._debounce_timer = None
        for reason in reasons:
            self._emit(reason)

    def wait_for_changes(self, last_revision: int, *, timeout: float):
        with self._condition:
            if self._revision <= last_revision:
                self._condition.wait(timeout)
            if self._revision <= last_revision:
                return None

            changed_events = [
                event
                for event in self._events
                if int(event.get("revision", 0)) > int(last_revision)
            ]
            if not changed_events and self._events:
                changed_events = [self._events[-1]]

            reasons = sorted({str(event.get("reason") or "dashboard") for event in changed_events})
            return {
                "revision": int(changed_events[-1]["revision"]),
                "reasons": reasons,
                "history_changed": any(bool(event.get("history_changed")) for event in changed_events),
                "https_traffic_changed": any(bool(event.get("https_traffic_changed")) for event in changed_events),
                "router_config_changed": any(bool(event.get("router_config_changed")) for event in changed_events),
            }


def _timestamp_now():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = []
    remaining = size
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise OSError("connection closed while reading from upstream")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _describe_upstream_probe_error(exc: Exception) -> str:
    if isinstance(exc, TimeoutError):
        return "Connection timed out."
    if isinstance(exc, socket.gaierror):
        return "Failed to resolve the upstream host."
    if isinstance(exc, OSError):
        if exc.errno == errno.ENETUNREACH:
            return "Network is unreachable from this machine."
        if exc.errno == errno.EHOSTUNREACH:
            return "Upstream host is unreachable."
        if exc.errno == errno.ECONNREFUSED:
            return "Upstream server refused the connection."
        if exc.errno == errno.ECONNRESET:
            return "Upstream connection was reset."
    return str(exc) or exc.__class__.__name__


def _probe_upstream_connectivity(upstream_config: dict, *, timeout_seconds: int):
    upstream_type = str(upstream_config.get("type") or "http")
    host = str(upstream_config.get("host") or "").strip()
    port = int(upstream_config.get("port") or 0)
    if not host or port <= 0:
        raise ValueError("Upstream host and port must be set before checking connectivity.")

    if upstream_type == "socks5":
        upstream = socket.create_connection((host, port), timeout=timeout_seconds)
        upstream.settimeout(timeout_seconds)
        try:
            upstream.sendall(bytes([SOCKS_VERSION, 0x01, 0x00]))
            reply = _recv_exact(upstream, 2)
            if reply[0] != SOCKS_VERSION:
                raise OSError("SOCKS5 upstream returned an invalid handshake reply.")
            if reply[1] == 0xFF:
                raise OSError("SOCKS5 upstream requires authentication, which proxy-router does not support.")
            if reply[1] != 0x00:
                raise OSError(f"SOCKS5 upstream rejected the no-auth handshake (method 0x{reply[1]:02x}).")
        finally:
            upstream.close()
        return {
            "status": "reachable",
            "checked_at": _timestamp_now(),
            "message": "SOCKS5 handshake succeeded.",
            "protocol_verified": True,
        }

    upstream = socket.create_connection((host, port), timeout=timeout_seconds)
    try:
        pass
    finally:
        upstream.close()
    return {
        "status": "reachable",
        "checked_at": _timestamp_now(),
        "message": "TCP connection succeeded. HTTP proxy protocol will be confirmed by the first proxied request.",
        "protocol_verified": False,
    }


class UpstreamProxyStatus:
    def __init__(self, notify_callback):
        self._lock = threading.Lock()
        self._notify_callback = notify_callback
        self._generation = 0
        self._config_fingerprint = None
        self._state = self._build_state(
            enabled=False,
            upstream_type="http",
            host="127.0.0.1",
            port=0,
            connectivity={
                "status": "disabled",
                "checked_at": None,
                "message": "Upstream proxy is disabled.",
                "protocol_verified": False,
            },
        )

    def _build_state(self, *, enabled, upstream_type, host, port, connectivity, last_success=None, last_failure=None):
        return {
            "enabled": bool(enabled),
            "type": upstream_type,
            "host": host,
            "port": int(port),
            "connectivity": {
                "status": str(connectivity.get("status") or "unknown"),
                "checked_at": connectivity.get("checked_at"),
                "message": str(connectivity.get("message") or ""),
                "protocol_verified": bool(connectivity.get("protocol_verified")),
            },
            "last_success": last_success,
            "last_failure": last_failure,
        }

    def _fingerprint(self, upstream):
        upstream_type = str(upstream.get("type") or "http").strip().lower()
        host = str(upstream.get("host") or "").strip().lower()
        port = int(upstream.get("port") or 0)
        enabled = bool(upstream.get("enabled"))
        return json.dumps(
            {
                "enabled": enabled,
                "type": upstream_type,
                "host": host,
                "port": port,
            },
            sort_keys=True,
        )

    def _matches_current_locked(self, upstream) -> bool:
        if upstream is None:
            return False
        return self._fingerprint(upstream) == self._config_fingerprint

    def _notify(self):
        self._notify_callback("upstream-status")

    def snapshot(self):
        with self._lock:
            return json.loads(json.dumps(self._state))

    def apply_config(self, router_config, *, timeout_seconds: int):
        upstream = dict((router_config or {}).get("upstream") or {})
        normalized = {
            "enabled": bool(upstream.get("enabled")),
            "type": "socks5" if str(upstream.get("type") or "").strip().lower() == "socks5" else "http",
            "host": str(upstream.get("host") or "").strip(),
            "port": int(upstream.get("port") or 0),
        }
        next_fingerprint = self._fingerprint(normalized)
        with self._lock:
            config_changed = next_fingerprint != self._config_fingerprint
            self._config_fingerprint = next_fingerprint
            self._generation += 1
            generation = self._generation
            last_success = None if config_changed else self._state.get("last_success")
            last_failure = None if config_changed else self._state.get("last_failure")
            if not normalized["enabled"]:
                self._state = self._build_state(
                    enabled=False,
                    upstream_type=normalized["type"],
                    host=normalized["host"],
                    port=normalized["port"],
                    connectivity={
                        "status": "disabled",
                        "checked_at": _timestamp_now(),
                        "message": "Upstream proxy is disabled.",
                        "protocol_verified": False,
                    },
                    last_success=last_success,
                    last_failure=last_failure,
                )
                should_probe = False
            elif not normalized["host"] or normalized["port"] <= 0:
                self._state = self._build_state(
                    enabled=True,
                    upstream_type=normalized["type"],
                    host=normalized["host"],
                    port=normalized["port"],
                    connectivity={
                        "status": "error",
                        "checked_at": _timestamp_now(),
                        "message": "Upstream host and port must be set before proxy traffic can use it.",
                        "protocol_verified": False,
                    },
                    last_success=last_success,
                    last_failure=last_failure,
                )
                should_probe = False
            else:
                self._state = self._build_state(
                    enabled=True,
                    upstream_type=normalized["type"],
                    host=normalized["host"],
                    port=normalized["port"],
                    connectivity={
                        "status": "checking",
                        "checked_at": None,
                        "message": "Checking upstream connectivity…",
                        "protocol_verified": False,
                    },
                    last_success=last_success,
                    last_failure=last_failure,
                )
                should_probe = True

        self._notify()

        if not should_probe:
            return

        probe_thread = threading.Thread(
            target=self._run_probe,
            args=(generation, normalized, timeout_seconds),
            daemon=True,
        )
        probe_thread.start()

    def _run_probe(self, generation: int, upstream: dict, timeout_seconds: int):
        try:
            result = _probe_upstream_connectivity(upstream, timeout_seconds=timeout_seconds)
        except Exception as exc:
            result = {
                "status": "error",
                "checked_at": _timestamp_now(),
                "message": _describe_upstream_probe_error(exc),
                "protocol_verified": False,
            }

        with self._lock:
            if generation != self._generation or not self._matches_current_locked(upstream):
                return
            self._state["connectivity"] = {
                "status": result["status"],
                "checked_at": result["checked_at"],
                "message": result["message"],
                "protocol_verified": bool(result.get("protocol_verified")),
            }

        self._notify()

    def trigger_manual_check(self, router_config, *, timeout_seconds: int):
        self.apply_config(router_config, timeout_seconds=timeout_seconds)

    def record_success(self, upstream: dict | None, *, destination: str, proxy_label: str):
        with self._lock:
            if not self._matches_current_locked(upstream):
                return
            self._state["last_success"] = {
                "timestamp": _timestamp_now(),
                "destination": str(destination or ""),
                "proxy_label": str(proxy_label or ""),
            }
        self._notify()

    def record_failure(self, upstream: dict | None, *, destination: str, error: str, context: str, proxy_label: str):
        with self._lock:
            if not self._matches_current_locked(upstream):
                return
            self._state["last_failure"] = {
                "timestamp": _timestamp_now(),
                "destination": str(destination or ""),
                "error": str(error or ""),
                "context": str(context or ""),
                "proxy_label": str(proxy_label or ""),
            }
        self._notify()


class UpstreamProxyListStatus:
    def __init__(self, notify_callback, *, failure_threshold: int = PROXY_CONNECTION_FAILURE_THRESHOLD):
        self._lock = threading.Lock()
        self._notify_callback = notify_callback
        self._failure_threshold = int(failure_threshold)
        self._states = {}

    def _notify(self):
        self._notify_callback("proxy-status")

    def _fingerprint(self, proxy):
        return json.dumps(
            {
                "id": str((proxy or {}).get("id") or "").strip(),
                "enabled": bool((proxy or {}).get("enabled", True)),
                "type": str((proxy or {}).get("type") or "http").strip().lower(),
                "host": str((proxy or {}).get("host") or "").strip().lower(),
                "port": int((proxy or {}).get("port") or 0),
            },
            sort_keys=True,
        )

    def _base_state(self, proxy):
        proxy_id = str((proxy or {}).get("id") or "").strip()
        return {
            "id": proxy_id,
            "name": str((proxy or {}).get("name") or proxy_id).strip() or proxy_id,
            "enabled": bool((proxy or {}).get("enabled", True)),
            "priority": int((proxy or {}).get("priority") or 0),
            "type": str((proxy or {}).get("type") or "http"),
            "host": str((proxy or {}).get("host") or ""),
            "port": int((proxy or {}).get("port") or 0),
            "access_mode": str((proxy or {}).get("access_mode") or "public"),
            "status": "unknown",
            "checked_at": None,
            "message": "Waiting for traffic or a proxy check.",
            "protocol_verified": False,
            "consecutive_failures": 0,
            "last_success": None,
            "last_failure": None,
            "fingerprint": self._fingerprint(proxy),
        }

    def _configured_state(self, proxy, previous=None):
        state = self._base_state(proxy)
        if previous and previous.get("fingerprint") == state["fingerprint"]:
            state.update(
                {
                    "status": previous.get("status", state["status"]),
                    "checked_at": previous.get("checked_at"),
                    "message": previous.get("message", state["message"]),
                    "protocol_verified": bool(previous.get("protocol_verified")),
                    "consecutive_failures": int(previous.get("consecutive_failures") or 0),
                    "last_success": previous.get("last_success"),
                    "last_failure": previous.get("last_failure"),
                }
            )
        if not state["enabled"]:
            state.update(
                {
                    "status": "disabled",
                    "checked_at": state.get("checked_at") or _timestamp_now(),
                    "message": "Proxy is disabled.",
                    "protocol_verified": False,
                    "consecutive_failures": 0,
                }
            )
        elif not state["host"] or state["port"] <= 0:
            state.update(
                {
                    "status": "error",
                    "checked_at": state.get("checked_at") or _timestamp_now(),
                    "message": "Proxy host and port must be set before traffic can use it.",
                    "protocol_verified": False,
                    "consecutive_failures": self._failure_threshold,
                }
            )
        return state

    def _matches_state_locked(self, proxy):
        proxy_id = str((proxy or {}).get("id") or "").strip()
        if not proxy_id:
            return None
        state = self._states.get(proxy_id)
        if state is None or state.get("fingerprint") != self._fingerprint(proxy):
            return None
        return state

    def apply_config(self, router_config):
        proxies = (router_config or {}).get("proxies", [])
        next_states = {}
        with self._lock:
            previous_states = self._states
            for proxy in proxies:
                if not isinstance(proxy, dict):
                    continue
                proxy_id = str(proxy.get("id") or "").strip()
                if not proxy_id:
                    continue
                next_states[proxy_id] = self._configured_state(proxy, previous_states.get(proxy_id))
            self._states = next_states
        self._notify()

    def record_check_results(self, router_config, results):
        proxies_by_id = {
            str((proxy or {}).get("id") or "").strip(): proxy
            for proxy in (router_config or {}).get("proxies", [])
            if isinstance(proxy, dict) and str(proxy.get("id") or "").strip()
        }
        with self._lock:
            next_states = {}
            for proxy_id, proxy in proxies_by_id.items():
                next_states[proxy_id] = self._configured_state(proxy, self._states.get(proxy_id))
            for result in results or []:
                proxy_id = str((result or {}).get("id") or "").strip()
                proxy = proxies_by_id.get(proxy_id)
                if proxy is None:
                    continue
                state = next_states.get(proxy_id) or self._configured_state(proxy)
                status = str((result or {}).get("status") or "unknown")
                state.update(
                    {
                        "status": status,
                        "checked_at": (result or {}).get("checked_at") or _timestamp_now(),
                        "message": str((result or {}).get("message") or ""),
                        "protocol_verified": bool((result or {}).get("protocol_verified")),
                    }
                )
                if status == "reachable":
                    state["consecutive_failures"] = 0
                    state["last_success"] = {
                        "timestamp": state["checked_at"],
                        "destination": "proxy check",
                        "proxy_label": "dashboard",
                    }
                elif status == "error":
                    state["consecutive_failures"] = max(
                        self._failure_threshold,
                        int(state.get("consecutive_failures") or 0),
                    )
                    state["last_failure"] = {
                        "timestamp": state["checked_at"],
                        "destination": "proxy check",
                        "error": state["message"],
                        "context": "proxy check",
                        "proxy_label": "dashboard",
                    }
                next_states[proxy_id] = state
            self._states = next_states
        self._notify()

    def record_success(self, upstream: dict | None, *, destination: str, proxy_label: str):
        with self._lock:
            state = self._matches_state_locked(upstream)
            if state is None:
                return
            timestamp = _timestamp_now()
            state.update(
                {
                    "status": "reachable",
                    "checked_at": timestamp,
                    "message": f"Last proxied request connected to {destination}.",
                    "protocol_verified": True,
                    "consecutive_failures": 0,
                    "last_success": {
                        "timestamp": timestamp,
                        "destination": str(destination or ""),
                        "proxy_label": str(proxy_label or ""),
                    },
                }
            )
        self._notify()

    def record_failure(self, upstream: dict | None, *, destination: str, error: str, context: str, proxy_label: str):
        with self._lock:
            state = self._matches_state_locked(upstream)
            if state is None:
                return
            timestamp = _timestamp_now()
            consecutive_failures = int(state.get("consecutive_failures") or 0) + 1
            state["consecutive_failures"] = consecutive_failures
            state["last_failure"] = {
                "timestamp": timestamp,
                "destination": str(destination or ""),
                "error": str(error or ""),
                "context": str(context or ""),
                "proxy_label": str(proxy_label or ""),
            }
            if consecutive_failures >= self._failure_threshold:
                state.update(
                    {
                        "status": "error",
                        "checked_at": timestamp,
                        "message": (
                            f"{consecutive_failures} consecutive proxied requests failed. "
                            f"Last error: {error}"
                        ),
                        "protocol_verified": False,
                    }
                )
        self._notify()

    def snapshot(self):
        with self._lock:
            results = [json.loads(json.dumps(item)) for item in self._states.values()]
        results.sort(key=lambda item: (int(item.get("priority") or 0), str(item.get("id") or "")))
        connected_count = sum(1 for item in results if item.get("enabled") and item.get("status") == "reachable")
        enabled_count = sum(1 for item in results if item.get("enabled"))
        return {
            "failure_threshold": self._failure_threshold,
            "connected_count": connected_count,
            "enabled_count": enabled_count,
            "results": results,
        }


class AsyncJsonlWriter:
    def __init__(self, log_file: Path | None):
        self.log_file = log_file
        self._lock = threading.Lock()
        self._stream = None
        self._queue = None
        self._thread = None
        self._closed = False

        if self.log_file is not None:
            self.log_file.parent.mkdir(parents=True, exist_ok=True)
            self._stream = self.log_file.open("a", encoding="utf-8", buffering=1)
            self._queue = queue.Queue(maxsize=LOG_WRITER_QUEUE_MAX_SIZE)
            self._thread = threading.Thread(
                target=self._run,
                name=f"proxy-router-jsonl-writer-{self.log_file.name}",
                daemon=True,
            )
            self._thread.start()

    def write(self, event):
        if self.log_file is None:
            return

        line = json.dumps(event, sort_keys=True) + "\n"
        with self._lock:
            if self._closed:
                return
            writer_queue = self._queue

        if writer_queue is None:
            return

        try:
            writer_queue.put_nowait(line)
        except queue.Full:
            self._write_line(line)

    def flush(self):
        writer_queue = self._queue
        if writer_queue is not None:
            writer_queue.join()
        self._flush_stream()

    def close(self):
        with self._lock:
            if self._closed:
                return
            self._closed = True
            writer_queue = self._queue
            writer_thread = self._thread

        if writer_queue is not None:
            writer_queue.put(None)
            writer_queue.join()
        if writer_thread is not None:
            writer_thread.join(timeout=5.0)

        with self._lock:
            if self._stream is not None:
                self._stream.close()
                self._stream = None
            self._queue = None
            self._thread = None

    def clear_data(self):
        if self.log_file is None:
            return

        self.flush()
        with self._lock:
            if self._stream is not None:
                self._stream.seek(0)
                self._stream.truncate(0)
                self._stream.flush()
                return
            self.log_file.parent.mkdir(parents=True, exist_ok=True)
            self.log_file.write_text("", encoding="utf-8")

    def _run(self):
        while True:
            try:
                item = self._queue.get(timeout=LOG_WRITER_FLUSH_INTERVAL_SECONDS)
            except queue.Empty:
                self._flush_stream()
                continue

            if item is None:
                self._queue.task_done()
                break

            self._write_line(item, flush=False)
            self._queue.task_done()

        self._flush_stream()

    def _write_line(self, line: str, *, flush: bool = True):
        with self._lock:
            if self._stream is None:
                return
            self._stream.write(line)
            if flush:
                self._stream.flush()

    def _flush_stream(self):
        with self._lock:
            if self._stream is not None:
                self._stream.flush()


class UsageLogger:
    def __init__(self, log_file: Path | None):
        self.log_file = log_file
        self._writer = AsyncJsonlWriter(log_file)

    def record(
        self,
        *,
        proxy_label: str,
        kind: str,
        client: str,
        destination: str,
        uploaded_bytes: int,
        downloaded_bytes: int,
        timestamp: str,
        method: str | None = None,
        route_label: str | None = None,
        matched_rule: dict | None = None,
        profile_id: str | None = None,
        status_code: int | None = None,
        client_ip: str | None = None,
        client_auth_type: str | None = None,
        client_auth_username: str | None = None,
        client_auth_label: str | None = None,
        duration_ms: int | None = None,
        upstream_setup_ms: int | None = None,
        relay_ms: int | None = None,
        upstream_retry_count: int | None = None,
        upstream_retry_delay_ms: int | None = None,
        upstream_proxy_id: str | None = None,
        upstream_proxy_name: str | None = None,
        upstream_proxy_access_mode: str | None = None,
        proxy_failover_count: int | None = None,
    ):
        if self.log_file is None:
            return

        event = {
            "timestamp": timestamp,
            "proxy_type": proxy_label,
            "kind": kind,
            "client": client,
            "destination": destination,
            "uploaded_bytes": uploaded_bytes,
            "downloaded_bytes": downloaded_bytes,
            "total_bytes": uploaded_bytes + downloaded_bytes,
            "route_label": route_label or "direct",
            "profile_id": profile_id or DEFAULT_ROUTING_PROFILE_ID,
        }
        apply_usage_performance_fields(
            event,
            total_bytes=uploaded_bytes + downloaded_bytes,
            duration_ms=duration_ms,
            upstream_setup_ms=upstream_setup_ms,
            relay_ms=relay_ms,
            upstream_retry_count=upstream_retry_count,
            upstream_retry_delay_ms=upstream_retry_delay_ms,
        )
        if method is not None:
            event["method"] = method
        if matched_rule is not None:
            event["matched_rule"] = matched_rule
        if status_code is not None:
            event["status_code"] = int(status_code)
        if client_ip is not None:
            event["client_ip"] = client_ip
        if client_auth_type is not None:
            event["client_auth_type"] = client_auth_type
        if client_auth_username is not None:
            event["client_auth_username"] = client_auth_username
        if client_auth_label is not None:
            event["client_auth_label"] = client_auth_label
        if upstream_proxy_id is not None:
            event["upstream_proxy_id"] = upstream_proxy_id
        if upstream_proxy_name is not None:
            event["upstream_proxy_name"] = upstream_proxy_name
        if upstream_proxy_access_mode is not None:
            event["upstream_proxy_access_mode"] = upstream_proxy_access_mode
        if proxy_failover_count is not None:
            event["proxy_failover_count"] = int(proxy_failover_count)

        self._writer.write(event)

    def close(self):
        self._writer.close()

    def clear_data(self):
        self._writer.clear_data()


class HttpsTrafficLogger:
    def __init__(self, log_file: Path | None):
        self.log_file = log_file
        self._writer = AsyncJsonlWriter(log_file)

    def record(self, event):
        if self.log_file is None:
            return

        self._writer.write(event)

    def close(self):
        self._writer.close()

    def clear_data(self):
        self._writer.clear_data()


class FailureLogger:
    def __init__(self, log_file: Path | None):
        self.log_file = log_file
        self._writer = AsyncJsonlWriter(log_file)

    def record(
        self,
        *,
        proxy_label: str,
        client: str,
        method: str,
        destination: str,
        host: str | None,
        port: int | None,
        error: str,
        context: str,
        timestamp: str,
        route_label: str | None = None,
        matched_rule: dict | None = None,
        profile_id: str | None = None,
        client_ip: str | None = None,
        client_auth_type: str | None = None,
        client_auth_username: str | None = None,
        client_auth_label: str | None = None,
        duration_ms: int | None = None,
        upstream_setup_ms: int | None = None,
        upstream_retry_count: int | None = None,
        upstream_retry_delay_ms: int | None = None,
        upstream_proxy_id: str | None = None,
        upstream_proxy_name: str | None = None,
        upstream_proxy_access_mode: str | None = None,
        proxy_failover_count: int | None = None,
    ):
        event = {
            "timestamp": timestamp,
            "proxy_type": proxy_label,
            "client": client,
            "method": method,
            "destination": destination,
            "host": host,
            "port": port,
            "error": error,
            "context": context,
            "route_label": route_label or "direct",
            "profile_id": profile_id or DEFAULT_ROUTING_PROFILE_ID,
        }
        if client_ip is not None:
            event["client_ip"] = client_ip
        if client_auth_type is not None:
            event["client_auth_type"] = client_auth_type
        if client_auth_username is not None:
            event["client_auth_username"] = client_auth_username
        if client_auth_label is not None:
            event["client_auth_label"] = client_auth_label
        if upstream_proxy_id is not None:
            event["upstream_proxy_id"] = upstream_proxy_id
        if upstream_proxy_name is not None:
            event["upstream_proxy_name"] = upstream_proxy_name
        if upstream_proxy_access_mode is not None:
            event["upstream_proxy_access_mode"] = upstream_proxy_access_mode
        if proxy_failover_count is not None:
            event["proxy_failover_count"] = int(proxy_failover_count)
        if matched_rule is not None:
            event["matched_rule"] = matched_rule
        apply_failure_performance_fields(
            event,
            duration_ms=duration_ms,
            upstream_setup_ms=upstream_setup_ms,
            upstream_retry_count=upstream_retry_count,
            upstream_retry_delay_ms=upstream_retry_delay_ms,
        )

        self._writer.write(event)

    def close(self):
        self._writer.close()

    def clear_data(self):
        self._writer.clear_data()


class SelfEndpoints:
    def __init__(self):
        self.host_aliases = {"127.0.0.1", "localhost"}
        self.client_portal_primary_host = CLIENT_PORTAL_PRIMARY_HOST
        self.client_portal_aliases = set(CLIENT_PORTAL_HOST_ALIASES)
        self.dashboard_port = DASHBOARD_DEFAULT_PORT
        self.dashboard_connect_host = "127.0.0.1"
        self.dashboard_url = f"http://127.0.0.1:{DASHBOARD_DEFAULT_PORT}/"
        self.proxy_listener_ports = set()
        self.client_portal_direct_host = "127.0.0.1"

    def configure(
        self,
        *,
        bind: str,
        dashboard_bind: str,
        dashboard_port: int,
        dashboard_enabled: bool,
        client_ips,
        listener_ports,
    ):
        aliases = {"127.0.0.1", "localhost", "host.docker.internal"}
        for candidate in [bind, dashboard_bind, *client_ips]:
            if not candidate or candidate == "0.0.0.0":
                continue
            aliases.add(normalize_host(candidate))

        for candidate in [socket.gethostname(), socket.getfqdn()]:
            if candidate:
                aliases.add(normalize_host(candidate))

        self.host_aliases = aliases
        self.dashboard_port = dashboard_port
        self.dashboard_connect_host = "127.0.0.1" if dashboard_bind in {"127.0.0.1", "0.0.0.0"} else dashboard_bind
        if dashboard_enabled:
            redirect_host = "127.0.0.1" if dashboard_bind in {"127.0.0.1", "0.0.0.0"} else dashboard_bind
            self.dashboard_url = f"http://{redirect_host}:{dashboard_port}/"
        else:
            self.dashboard_url = None
        self.proxy_listener_ports = {int(port) for port in listener_ports}
        if bind and bind != "0.0.0.0":
            self.client_portal_direct_host = normalize_host(bind)
        elif client_ips:
            self.client_portal_direct_host = normalize_host(client_ips[0])
        else:
            self.client_portal_direct_host = "127.0.0.1"

    def is_client_portal_host(self, host: str) -> bool:
        return normalize_host(host) in self.client_portal_aliases

    def client_portal_url(self) -> str:
        return f"http://{self.client_portal_primary_host}/"

    def client_portal_quota_url(self) -> str:
        return f"http://{self.client_portal_primary_host}/quota"

    def client_portal_ca_install_url(self) -> str:
        return f"http://{self.client_portal_primary_host}/ca"

    def client_portal_ca_certificate_url(self) -> str:
        return f"http://{self.client_portal_primary_host}/ca.crt"

    def client_portal_ca_check_url(self) -> str:
        return f"https://{self.client_portal_primary_host}/ca-check"

    def client_portal_live_url(self, port: int) -> str:
        return f"ws://{self.client_portal_direct_host}:{int(port)}/api/client/live"

    def resolve_target_kind(self, host: str, port: int) -> str | None:
        normalized_host = normalize_host(host)
        if normalized_host not in self.host_aliases:
            return None
        if int(port) == self.dashboard_port:
            return "dashboard"
        if int(port) in self.proxy_listener_ports:
            return "listener"
        return None


class AppRuntime:
    def __init__(self):
        self.dashboard_state = DashboardState()
        self.client_presence = ClientPresenceStore()
        self.live_updates = DashboardLiveUpdateHub()
        self.usage_log_path: Path | None = None
        self.failure_log_path: Path | None = None
        self.https_traffic_log_path: Path | None = None
        self.client_presence_history_path: Path | None = None
        self.client_block_history_path: Path | None = None
        self.usage_logger = UsageLogger(None)
        self.failure_logger = FailureLogger(None)
        self.https_traffic_logger = HttpsTrafficLogger(None)
        self.client_block_history = ClientBlockHistoryStore(None)
        self.traffic_quota_manager = TrafficQuotaManager()
        self.auto_proxy_failure_manager = None
        self.https_discovery_manager = None
        self.rule_suggestion_manager = None
        self.self_endpoints = SelfEndpoints()
        self.upstream_status = UpstreamProxyStatus(self.notify_dashboard_update)
        self.proxy_status = UpstreamProxyListStatus(self.notify_dashboard_update)
        self.https_interception = HttpsCertificateManager(
            ca_cert_file=DEFAULT_HTTPS_INTERCEPT_CA_CERT_PATH,
            ca_key_file=DEFAULT_HTTPS_INTERCEPT_CA_KEY_PATH,
            cert_cache_dir=DEFAULT_HTTPS_INTERCEPT_CERT_CACHE_DIR,
        )
        self.https_interception_trust = HttpsInterceptionTrustManager(None)

    def configure_usage_log(self, log_file: Path | None):
        self.usage_logger.close()
        self.usage_log_path = log_file
        self.usage_logger = UsageLogger(log_file)

    def configure_failure_log(self, log_file: Path | None):
        self.failure_logger.close()
        self.failure_log_path = log_file
        self.failure_logger = FailureLogger(log_file)

    def configure_https_traffic_log(self, log_file: Path | None):
        self.https_traffic_logger.close()
        self.https_traffic_log_path = log_file
        self.https_traffic_logger = HttpsTrafficLogger(log_file)

    def configure_client_presence_file(self, presence_file: Path | None):
        self.client_presence.configure(presence_file)

    def configure_client_activity_history(
        self,
        presence_history_file: Path | None,
        block_history_file: Path | None,
    ):
        self.client_presence_history_path = presence_history_file
        self.client_block_history_path = block_history_file
        self.client_block_history = ClientBlockHistoryStore(block_history_file)

    def record_client_block_history(self, router_config_snapshot):
        blocks = (router_config_snapshot or {}).get("client_blocks", [])
        if self.client_block_history.record_snapshot(blocks):
            self.notify_dashboard_update("client-activity")

    def configure_traffic_quota_manager(self, log_file: Path | None):
        self.traffic_quota_manager = TrafficQuotaManager()
        self.traffic_quota_manager.load_from_log(log_file)

    def configure_https_interception(
        self,
        *,
        ca_cert_file: Path,
        ca_key_file: Path,
        cert_cache_dir: Path,
        ca_common_name: str,
    ):
        self.https_interception = HttpsCertificateManager(
            ca_cert_file=ca_cert_file,
            ca_key_file=ca_key_file,
            cert_cache_dir=cert_cache_dir,
            ca_common_name=ca_common_name,
        )

    def rehydrate_dashboard_state(self):
        self.dashboard_state.clear_traffic_data()

        usage_records, _ = load_usage_records(
            self.usage_log_path,
            log_invalid=False,
            allow_missing=True,
        )
        usage_records.sort(key=lambda item: str(item.get("timestamp") or ""))
        for record in usage_records:
            client = str(record.get("client") or "").strip()
            timestamp = str(record.get("timestamp") or "").strip()
            if not client or not timestamp:
                continue
            status_code = record.get("status_code")
            try:
                normalized_status_code = int(status_code) if status_code is not None else None
            except (TypeError, ValueError):
                normalized_status_code = None
            self.dashboard_state.record_request(
                proxy_label=str(record.get("proxy_type") or "unknown"),
                kind=str(record.get("kind") or "http"),
                client=client,
                destination=str(record.get("destination") or ""),
                uploaded_bytes=int(record.get("uploaded_bytes", 0)),
                downloaded_bytes=int(record.get("downloaded_bytes", 0)),
                method=str(record.get("method")) if record.get("method") is not None else None,
                timestamp=timestamp,
                route_label=str(record.get("route_label") or "direct"),
                matched_rule=record.get("matched_rule") if isinstance(record.get("matched_rule"), dict) else None,
                profile_id=str(record.get("profile_id") or DEFAULT_ROUTING_PROFILE_ID),
                status_code=normalized_status_code,
                client_ip=str(record.get("client_ip")) if record.get("client_ip") is not None else None,
                client_auth_type=str(record.get("client_auth_type")) if record.get("client_auth_type") is not None else None,
                client_auth_username=str(record.get("client_auth_username")) if record.get("client_auth_username") is not None else None,
                client_auth_label=str(record.get("client_auth_label")) if record.get("client_auth_label") is not None else None,
                duration_ms=record.get("duration_ms"),
                upstream_setup_ms=record.get("upstream_setup_ms"),
                relay_ms=record.get("relay_ms"),
                upstream_retry_count=record.get("upstream_retry_count"),
                upstream_retry_delay_ms=record.get("upstream_retry_delay_ms"),
                upstream_proxy_id=str(record.get("upstream_proxy_id")) if record.get("upstream_proxy_id") is not None else None,
                upstream_proxy_name=str(record.get("upstream_proxy_name")) if record.get("upstream_proxy_name") is not None else None,
                upstream_proxy_access_mode=str(record.get("upstream_proxy_access_mode")) if record.get("upstream_proxy_access_mode") is not None else None,
                proxy_failover_count=record.get("proxy_failover_count"),
            )

        failure_records, _ = load_failure_records(
            self.failure_log_path,
            log_invalid=False,
            allow_missing=True,
        )
        failure_records.sort(key=lambda item: str(item.get("timestamp") or ""))
        for record in failure_records:
            timestamp = str(record.get("timestamp") or "").strip()
            if not timestamp:
                continue

            port = record.get("port")
            try:
                normalized_port = int(port) if port is not None else None
            except (TypeError, ValueError):
                normalized_port = None

            self.dashboard_state.record_failure(
                proxy_label=str(record.get("proxy_type") or "system"),
                client=str(record.get("client") or ""),
                method=str(record.get("method") or "CONNECT"),
                destination=str(record.get("destination") or ""),
                host=str(record.get("host")) if record.get("host") is not None else None,
                port=normalized_port,
                error=str(record.get("error") or ""),
                context=str(record.get("context") or ""),
                timestamp=timestamp,
                route_label=str(record.get("route_label") or "direct"),
                matched_rule=record.get("matched_rule") if isinstance(record.get("matched_rule"), dict) else None,
                profile_id=str(record.get("profile_id") or DEFAULT_ROUTING_PROFILE_ID),
                client_ip=str(record.get("client_ip")) if record.get("client_ip") is not None else None,
                client_auth_type=str(record.get("client_auth_type")) if record.get("client_auth_type") is not None else None,
                client_auth_username=str(record.get("client_auth_username")) if record.get("client_auth_username") is not None else None,
                client_auth_label=str(record.get("client_auth_label")) if record.get("client_auth_label") is not None else None,
                duration_ms=record.get("duration_ms"),
                upstream_setup_ms=record.get("upstream_setup_ms"),
                upstream_retry_count=record.get("upstream_retry_count"),
                upstream_retry_delay_ms=record.get("upstream_retry_delay_ms"),
                upstream_proxy_id=str(record.get("upstream_proxy_id")) if record.get("upstream_proxy_id") is not None else None,
                upstream_proxy_name=str(record.get("upstream_proxy_name")) if record.get("upstream_proxy_name") is not None else None,
                upstream_proxy_access_mode=str(record.get("upstream_proxy_access_mode")) if record.get("upstream_proxy_access_mode") is not None else None,
                proxy_failover_count=record.get("proxy_failover_count"),
            )

    def attach_router_config(self, router_config):
        self.rule_suggestion_manager = None
        if self.auto_proxy_failure_manager is not None:
            self.auto_proxy_failure_manager.shutdown()
            self.auto_proxy_failure_manager = None
        if self.https_discovery_manager is not None:
            self.https_discovery_manager.shutdown()
            self.https_discovery_manager = None
        if router_config is not None:
            from .config import RuleSuggestionManager

            self.rule_suggestion_manager = RuleSuggestionManager(
                rule_suggestions_state_file_path(router_config.config_file),
                router_config,
                change_callback=self.notify_dashboard_update,
            )
            self.auto_proxy_failure_manager = AutoProxyFailureManager(router_config)
            self.https_discovery_manager = HttpsDiscoveryManager(
                router_config,
                self.auto_proxy_failure_manager,
                notify_callback=self.notify_dashboard_update,
            )
            self.https_interception_trust = HttpsInterceptionTrustManager(
                https_interception_state_file_path(router_config.config_file)
            )
            self.refresh_upstream_status(router_config.snapshot())
            self.record_client_block_history(router_config.snapshot())
        else:
            self.https_interception_trust = HttpsInterceptionTrustManager(None)
            self.refresh_upstream_status(None)

    def apply_auto_proxy_probe_route(self, host: str | None, route_decision):
        if self.auto_proxy_failure_manager is None:
            return route_decision
        return self.auto_proxy_failure_manager.route_override(host, route_decision)

    def build_auto_proxy_status_probe_route(self, host: str | None, route_decision, *, status_code: int | None):
        if self.auto_proxy_failure_manager is None:
            return None
        return self.auto_proxy_failure_manager.status_probe_route(
            host,
            route_decision,
            status_code=status_code,
        )

    def build_auto_proxy_direct_failure_probe_route(self, host: str | None, route_decision):
        if self.auto_proxy_failure_manager is None:
            return None
        return self.auto_proxy_failure_manager.direct_failure_probe_route(host, route_decision)

    def https_interception_status(self, settings=None):
        status = self.https_interception.status(settings)
        status.update(self.https_interception_trust.snapshot())
        status["https_discovery"] = (
            self.https_discovery_manager.snapshot()
            if self.https_discovery_manager is not None
            else {
                "state_file": None,
                "probe_cooldown_seconds": int(HTTPS_DISCOVERY_PROBE_COOLDOWN.total_seconds()),
                "probe_timeout_seconds": HTTPS_DISCOVERY_PROBE_TIMEOUT_SECONDS,
                "total_domains": 0,
                "in_flight": 0,
                "proxy_recommended": 0,
                "manual_review": 0,
                "recent": [],
            }
        )
        status["trust_policy"] = str((settings or {}).get("trust_policy") or "adaptive")
        return status

    def observe_https_connect(self, host: str | None, port: int | None, route_decision):
        if self.https_discovery_manager is None:
            return None
        return self.https_discovery_manager.observe_connect(host, port, route_decision)

    def https_interception_adaptive_bypass(self, client: str | None, host: str | None, settings=None):
        trust_policy = str((settings or {}).get("trust_policy") or "adaptive").strip().lower()
        if trust_policy != "adaptive":
            return None
        return self.https_interception_trust.current_bypass(client, host)

    def record_https_interception_success(self, client: str | None, host: str | None, *, source: str = "intercept"):
        self.https_interception_trust.record_success(client, host, source=source)
        self.notify_dashboard_update("https-interception")

    def record_https_interception_failure(
        self,
        client: str | None,
        host: str | None,
        *,
        error: str,
        context: str,
        source: str = "intercept",
    ):
        self.https_interception_trust.record_failure(
            client,
            host,
            error=error,
            context=context,
            source=source,
        )
        self.notify_dashboard_update("https-interception")

    def notify_dashboard_update(self, reason: str):
        self.live_updates.notify(reason)

    def refresh_upstream_status(self, router_config):
        self.upstream_status.apply_config(
            router_config,
            timeout_seconds=UPSTREAM_STATUS_PROBE_TIMEOUT_SECONDS,
        )
        self.proxy_status.apply_config(router_config)

    def check_upstream_proxies(self, router_config):
        results = []
        for proxy in (router_config or {}).get("proxies", []):
            proxy_id = str((proxy or {}).get("id") or "").strip()
            payload = {
                "id": proxy_id,
                "name": str((proxy or {}).get("name") or proxy_id).strip() or proxy_id,
                "enabled": bool((proxy or {}).get("enabled", True)),
                "priority": int((proxy or {}).get("priority") or 0),
                "type": str((proxy or {}).get("type") or "http"),
                "host": str((proxy or {}).get("host") or ""),
                "port": int((proxy or {}).get("port") or 0),
                "access_mode": str((proxy or {}).get("access_mode") or "public"),
            }
            if not payload["enabled"]:
                payload.update(
                    {
                        "status": "disabled",
                        "checked_at": _timestamp_now(),
                        "message": "Proxy is disabled.",
                        "protocol_verified": False,
                    }
                )
            else:
                try:
                    result = _probe_upstream_connectivity(
                        proxy,
                        timeout_seconds=UPSTREAM_STATUS_PROBE_TIMEOUT_SECONDS,
                    )
                except Exception as exc:
                    result = {
                        "status": "error",
                        "checked_at": _timestamp_now(),
                        "message": _describe_upstream_probe_error(exc),
                        "protocol_verified": False,
                    }
                payload.update(result)
            results.append(payload)
        self.proxy_status.record_check_results(router_config, results)
        return {
            "checked_at": _timestamp_now(),
            "results": results,
        }

    def record_upstream_route_success(self, route_decision, *, destination: str, proxy_label: str):
        if route_decision is None or route_decision.get("action") != "proxy":
            return
        self.upstream_status.record_success(
            route_decision.get("upstream"),
            destination=destination,
            proxy_label=proxy_label,
        )
        self.proxy_status.record_success(
            route_decision.get("upstream"),
            destination=destination,
            proxy_label=proxy_label,
        )

    def record_upstream_route_failure(
        self,
        route_decision,
        *,
        destination: str,
        error: str,
        context: str,
        proxy_label: str,
    ):
        if route_decision is None or route_decision.get("action") != "proxy":
            return
        self.upstream_status.record_failure(
            route_decision.get("upstream"),
            destination=destination,
            error=error,
            context=context,
            proxy_label=proxy_label,
        )
        self.proxy_status.record_failure(
            route_decision.get("upstream"),
            destination=destination,
            error=error,
            context=context,
            proxy_label=proxy_label,
        )

    def record_auto_proxy_success(self, host: str | None, route_decision):
        if self.auto_proxy_failure_manager is None or route_decision is None:
            return
        self.auto_proxy_failure_manager.record_success(
            host,
            route_label=route_decision.get("route_label"),
            profile_id=route_decision.get("profile_id"),
            proxy_id=self._proxy_id_from_route_decision(route_decision),
        )

    def _proxy_id_from_route_decision(self, route_decision):
        upstream = (route_decision or {}).get("upstream") or {}
        return (
            (route_decision or {}).get("upstream_proxy_id")
            or upstream.get("id")
            or None
        )

    def record_usage(
        self,
        *,
        proxy_label: str,
        kind: str,
        client: str,
        destination: str,
        uploaded_bytes: int,
        downloaded_bytes: int,
        method: str | None = None,
        route_label: str | None = None,
        matched_rule: dict | None = None,
        profile_id: str | None = None,
        status_code: int | None = None,
        client_ip: str | None = None,
        client_auth_type: str | None = None,
        client_auth_username: str | None = None,
        client_auth_label: str | None = None,
        duration_ms: int | None = None,
        upstream_setup_ms: int | None = None,
        relay_ms: int | None = None,
        upstream_retry_count: int | None = None,
        upstream_retry_delay_ms: int | None = None,
        upstream_proxy_id: str | None = None,
        upstream_proxy_name: str | None = None,
        upstream_proxy_access_mode: str | None = None,
        proxy_failover_count: int | None = None,
    ):
        timestamp = datetime.now().astimezone().isoformat(timespec="milliseconds")
        self.usage_logger.record(
            proxy_label=proxy_label,
            kind=kind,
            client=client,
            destination=destination,
            uploaded_bytes=uploaded_bytes,
            downloaded_bytes=downloaded_bytes,
            timestamp=timestamp,
            method=method,
            route_label=route_label,
            matched_rule=matched_rule,
            profile_id=profile_id,
            status_code=status_code,
            client_ip=client_ip,
            client_auth_type=client_auth_type,
            client_auth_username=client_auth_username,
            client_auth_label=client_auth_label,
            duration_ms=duration_ms,
            upstream_setup_ms=upstream_setup_ms,
            relay_ms=relay_ms,
            upstream_retry_count=upstream_retry_count,
            upstream_retry_delay_ms=upstream_retry_delay_ms,
            upstream_proxy_id=upstream_proxy_id,
            upstream_proxy_name=upstream_proxy_name,
            upstream_proxy_access_mode=upstream_proxy_access_mode,
            proxy_failover_count=proxy_failover_count,
        )
        self.dashboard_state.record_request(
            proxy_label=proxy_label,
            kind=kind,
            client=client,
            destination=destination,
            uploaded_bytes=uploaded_bytes,
            downloaded_bytes=downloaded_bytes,
            method=method,
            timestamp=timestamp,
            route_label=route_label,
            matched_rule=matched_rule,
            profile_id=profile_id,
            status_code=status_code,
            client_ip=client_ip,
            client_auth_type=client_auth_type,
            client_auth_username=client_auth_username,
            client_auth_label=client_auth_label,
            duration_ms=duration_ms,
            upstream_setup_ms=upstream_setup_ms,
            relay_ms=relay_ms,
            upstream_retry_count=upstream_retry_count,
            upstream_retry_delay_ms=upstream_retry_delay_ms,
            upstream_proxy_id=upstream_proxy_id,
            upstream_proxy_name=upstream_proxy_name,
            upstream_proxy_access_mode=upstream_proxy_access_mode,
            proxy_failover_count=proxy_failover_count,
        )
        self.traffic_quota_manager.record_usage(
            client=client,
            total_bytes=uploaded_bytes + downloaded_bytes,
            timestamp=timestamp,
            upstream_proxy_id=upstream_proxy_id,
        )
        self.notify_dashboard_update("usage")

    def record_https_traffic(
        self,
        *,
        client: str,
        client_ip: str | None,
        client_auth_type: str | None,
        client_auth_username: str | None,
        client_auth_label: str | None,
        method: str,
        scheme: str,
        host: str,
        port: int,
        path: str,
        destination: str,
        route_label: str | None,
        matched_rule: dict | None,
        profile_id: str | None,
        status_code: int,
        reason: str | None,
        request_headers,
        request_body_preview,
        request_body_bytes: int,
        response_headers,
        response_body_preview,
        response_body_bytes: int,
        duration_ms: int,
    ):
        timestamp = datetime.now().astimezone().isoformat(timespec="milliseconds")
        event = {
            "id": uuid.uuid4().hex,
            "timestamp": timestamp,
            "client": client,
            "client_ip": client_ip,
            "client_auth_type": client_auth_type,
            "client_auth_username": client_auth_username,
            "client_auth_label": client_auth_label,
            "method": method,
            "scheme": scheme,
            "host": host,
            "port": int(port),
            "path": sanitize_target_path_for_record(path),
            "destination": destination,
            "route_label": route_label or "direct",
            "matched_rule": matched_rule,
            "profile_id": profile_id or DEFAULT_ROUTING_PROFILE_ID,
            "status_code": int(status_code),
            "reason": str(reason or ""),
            "duration_ms": int(duration_ms),
            "request": {
                "headers": request_headers,
                "body_bytes": int(request_body_bytes or 0),
                "body_preview": request_body_preview,
            },
            "response": {
                "headers": response_headers,
                "body_bytes": int(response_body_bytes or 0),
                "body_preview": response_body_preview,
                "content_type": next(
                    (
                        item.get("value", "")
                        for item in response_headers
                        if str(item.get("name") or "").lower() == "content-type"
                    ),
                    "",
                ),
            },
        }
        event["total_bytes"] = event["request"]["body_bytes"] + event["response"]["body_bytes"]
        throughput_bps = calculate_throughput_bps(event["total_bytes"], event["duration_ms"])
        if throughput_bps is not None:
            event["throughput_bps"] = throughput_bps
        self.https_traffic_logger.record(event)
        self.notify_dashboard_update("https-traffic")

    def record_failure(
        self,
        *,
        proxy_label: str,
        client: str,
        method: str,
        destination: str,
        host: str | None,
        port: int | None,
        error: str,
        context: str,
        route_label: str | None = None,
        matched_rule: dict | None = None,
        profile_id: str | None = None,
        client_ip: str | None = None,
        client_auth_type: str | None = None,
        client_auth_username: str | None = None,
        client_auth_label: str | None = None,
        duration_ms: int | None = None,
        upstream_setup_ms: int | None = None,
        upstream_retry_count: int | None = None,
        upstream_retry_delay_ms: int | None = None,
        upstream_proxy_id: str | None = None,
        upstream_proxy_name: str | None = None,
        upstream_proxy_access_mode: str | None = None,
        proxy_failover_count: int | None = None,
    ):
        timestamp = datetime.now().astimezone().isoformat(timespec="milliseconds")
        self.failure_logger.record(
            proxy_label=proxy_label,
            client=client,
            method=method,
            destination=destination,
            host=host,
            port=port,
            error=error,
            context=context,
            timestamp=timestamp,
            route_label=route_label,
            matched_rule=matched_rule,
            profile_id=profile_id,
            client_ip=client_ip,
            client_auth_type=client_auth_type,
            client_auth_username=client_auth_username,
            client_auth_label=client_auth_label,
            duration_ms=duration_ms,
            upstream_setup_ms=upstream_setup_ms,
            upstream_retry_count=upstream_retry_count,
            upstream_retry_delay_ms=upstream_retry_delay_ms,
            upstream_proxy_id=upstream_proxy_id,
            upstream_proxy_name=upstream_proxy_name,
            upstream_proxy_access_mode=upstream_proxy_access_mode,
            proxy_failover_count=proxy_failover_count,
        )
        self.dashboard_state.record_failure(
            proxy_label=proxy_label,
            client=client,
            method=method,
            destination=destination,
            host=host,
            port=port,
            error=error,
            context=context,
            timestamp=timestamp,
            route_label=route_label,
            matched_rule=matched_rule,
            profile_id=profile_id,
            client_ip=client_ip,
            client_auth_type=client_auth_type,
            client_auth_username=client_auth_username,
            client_auth_label=client_auth_label,
            duration_ms=duration_ms,
            upstream_setup_ms=upstream_setup_ms,
            upstream_retry_count=upstream_retry_count,
            upstream_retry_delay_ms=upstream_retry_delay_ms,
            upstream_proxy_id=upstream_proxy_id,
            upstream_proxy_name=upstream_proxy_name,
            upstream_proxy_access_mode=upstream_proxy_access_mode,
            proxy_failover_count=proxy_failover_count,
        )
        if self.auto_proxy_failure_manager is not None:
            self.auto_proxy_failure_manager.record_failure(
                host,
                route_label=route_label,
                destination=destination,
                error=error,
                context=context,
                client=client,
                method=method,
                profile_id=profile_id,
            )
        self.notify_dashboard_update("failure")

    def clear_traffic_data(self):
        self.dashboard_state.clear_traffic_data()
        self.usage_logger.clear_data()
        self.failure_logger.clear_data()
        self.https_traffic_logger.clear_data()
        self.traffic_quota_manager.clear()
        if self.auto_proxy_failure_manager is not None:
            self.auto_proxy_failure_manager.clear_observations()
        if self.https_discovery_manager is not None:
            self.https_discovery_manager.clear_observations()
        self.https_interception_trust.clear_observations()
        self.notify_dashboard_update("clear")

    def close(self):
        if self.https_discovery_manager is not None:
            self.https_discovery_manager.shutdown()
            self.https_discovery_manager = None
        if self.auto_proxy_failure_manager is not None:
            self.auto_proxy_failure_manager.shutdown()
            self.auto_proxy_failure_manager = None
        self.usage_logger.close()
        self.failure_logger.close()
        self.https_traffic_logger.close()
