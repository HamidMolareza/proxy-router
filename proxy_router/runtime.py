from __future__ import annotations

import json
import socket
import threading
from collections import deque
from datetime import datetime
from pathlib import Path

from .constants import *
from .records import build_failure_snapshot_from_records
from .traffic import AutoProxyFailureManager, TrafficQuotaManager
from .util import *

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
        self._totals_by_proxy = {}
        self._totals_by_route = {}
        self._totals_by_client = {}
        self._recent_requests = deque(maxlen=recent_limit)
        self._recent_failures = deque(maxlen=recent_failure_limit)

    def clear_traffic_data(self):
        with self._lock:
            self._totals_by_proxy = {}
            self._totals_by_route = {}
            self._totals_by_client = {}
            self._recent_requests.clear()
            self._recent_failures.clear()

    def client_connected(self, proxy_label: str, client_ip: str):
        with self._lock:
            self._active_by_proxy[proxy_label] = self._active_by_proxy.get(proxy_label, 0) + 1
            self._active_by_client[client_ip] = self._active_by_client.get(client_ip, 0) + 1

    def client_disconnected(self, proxy_label: str, client_ip: str):
        with self._lock:
            current_proxy_count = self._active_by_proxy.get(proxy_label, 0)
            if current_proxy_count <= 1:
                self._active_by_proxy.pop(proxy_label, None)
            else:
                self._active_by_proxy[proxy_label] = current_proxy_count - 1

            current_client_count = self._active_by_client.get(client_ip, 0)
            if current_client_count <= 1:
                self._active_by_client.pop(client_ip, None)
            else:
                self._active_by_client[client_ip] = current_client_count - 1

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
    ):
        with self._lock:
            summary = self._totals_by_proxy.setdefault(proxy_label, empty_usage_summary())
            summary["count"] += 1
            summary["uploaded_bytes"] += uploaded_bytes
            summary["downloaded_bytes"] += downloaded_bytes
            summary["total_bytes"] += uploaded_bytes + downloaded_bytes

            route_bucket = route_bucket_from_label(route_label)
            route_summary = self._totals_by_route.setdefault(route_bucket, empty_usage_summary())
            route_summary["count"] += 1
            route_summary["uploaded_bytes"] += uploaded_bytes
            route_summary["downloaded_bytes"] += downloaded_bytes
            route_summary["total_bytes"] += uploaded_bytes + downloaded_bytes

            client_summary = self._totals_by_client.setdefault(client, empty_client_usage_summary())
            client_summary["count"] += 1
            client_summary["uploaded_bytes"] += uploaded_bytes
            client_summary["downloaded_bytes"] += downloaded_bytes
            client_summary["total_bytes"] += uploaded_bytes + downloaded_bytes
            client_summary["proxy_types"].add(proxy_label)
            client_summary["last_seen_at"] = timestamp

            self._recent_requests.appendleft(
                {
                    "timestamp": timestamp,
                    "proxy_type": proxy_label,
                    "kind": kind,
                    "client": client,
                    "destination": destination,
                    "uploaded_bytes": uploaded_bytes,
                    "downloaded_bytes": downloaded_bytes,
                    "total_bytes": uploaded_bytes + downloaded_bytes,
                    "method": method or kind.upper(),
                    "route_label": route_label or "direct",
                    "matched_rule": matched_rule,
                    "profile_id": profile_id or DEFAULT_ROUTING_PROFILE_ID,
                }
            )

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
    ):
        with self._lock:
            self._recent_failures.appendleft(
                {
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
                }
            )

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
                overall["count"] += summary["count"]
                overall["uploaded_bytes"] += summary["uploaded_bytes"]
                overall["downloaded_bytes"] += summary["downloaded_bytes"]
                overall["total_bytes"] += summary["total_bytes"]

            active_by_proxy = dict(sorted(self._active_by_proxy.items()))
            active_by_client = dict(
                sorted(self._active_by_client.items(), key=lambda item: (-item[1], item[0]))
            )
            totals_by_client = []
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
                        "proxy_types": sorted(usage["proxy_types"]),
                        "last_seen_at": usage["last_seen_at"],
                    }
                )
            totals_by_client.sort(
                key=lambda item: (-item["total_bytes"], -item["count"], item["client"])
            )
            recent_requests = list(self._recent_requests)
            recent_failures = list(self._recent_failures)

        return {
            "started_at": self.started_at,
            "overall": overall,
            "totals_by_proxy": totals_by_proxy,
            "totals_by_route": totals_by_route,
            "totals_by_client": totals_by_client,
            "active_by_proxy": active_by_proxy,
            "active_by_client": active_by_client,
            "recent_requests": recent_requests,
            "latest_request": recent_requests[0] if recent_requests else None,
            "recent_failures": recent_failures,
        }

    def failure_snapshot(self, router_config_snapshot):
        with self._lock:
            recent_failures = list(self._recent_failures)

        return build_failure_snapshot_from_records(recent_failures, router_config_snapshot)

class UsageLogger:
    def __init__(self, log_file: Path | None):
        self.log_file = log_file
        self._lock = threading.Lock()
        self._stream = None

        if self.log_file is not None:
            self.log_file.parent.mkdir(parents=True, exist_ok=True)
            self._stream = self.log_file.open("a", encoding="utf-8", buffering=1)

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
    ):
        if self._stream is None:
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
        if method is not None:
            event["method"] = method
        if matched_rule is not None:
            event["matched_rule"] = matched_rule

        with self._lock:
            self._stream.write(json.dumps(event, sort_keys=True) + "\n")
            self._stream.flush()

    def close(self):
        if self._stream is None:
            return

        with self._lock:
            self._stream.close()
            self._stream = None

    def clear_data(self):
        if self.log_file is None:
            return

        with self._lock:
            if self._stream is not None:
                self._stream.seek(0)
                self._stream.truncate(0)
                self._stream.flush()
                return
            self.log_file.parent.mkdir(parents=True, exist_ok=True)
            self.log_file.write_text("", encoding="utf-8")


class FailureLogger:
    def __init__(self, log_file: Path | None):
        self.log_file = log_file
        self._lock = threading.Lock()
        self._stream = None

        if self.log_file is not None:
            self.log_file.parent.mkdir(parents=True, exist_ok=True)
            self._stream = self.log_file.open("a", encoding="utf-8", buffering=1)

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
        if matched_rule is not None:
            event["matched_rule"] = matched_rule

        if self._stream is not None:
            with self._lock:
                self._stream.write(json.dumps(event, sort_keys=True) + "\n")
                self._stream.flush()

    def close(self):
        if self._stream is None:
            return

        with self._lock:
            self._stream.close()
            self._stream = None

    def clear_data(self):
        if self.log_file is None:
            return

        with self._lock:
            if self._stream is not None:
                self._stream.seek(0)
                self._stream.truncate(0)
                self._stream.flush()
                return
            self.log_file.parent.mkdir(parents=True, exist_ok=True)
            self.log_file.write_text("", encoding="utf-8")


class SelfEndpoints:
    def __init__(self):
        self.host_aliases = {"127.0.0.1", "localhost"}
        self.dashboard_port = DASHBOARD_DEFAULT_PORT
        self.dashboard_connect_host = "127.0.0.1"
        self.dashboard_url = f"http://127.0.0.1:{DASHBOARD_DEFAULT_PORT}/"
        self.proxy_listener_ports = set()

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
        aliases = {"127.0.0.1", "localhost"}
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
        self.usage_log_path: Path | None = None
        self.failure_log_path: Path | None = None
        self.usage_logger = UsageLogger(None)
        self.failure_logger = FailureLogger(None)
        self.traffic_quota_manager = TrafficQuotaManager()
        self.auto_proxy_failure_manager = None
        self.self_endpoints = SelfEndpoints()

    def configure_usage_log(self, log_file: Path | None):
        self.usage_logger.close()
        self.usage_log_path = log_file
        self.usage_logger = UsageLogger(log_file)

    def configure_failure_log(self, log_file: Path | None):
        self.failure_logger.close()
        self.failure_log_path = log_file
        self.failure_logger = FailureLogger(log_file)

    def configure_traffic_quota_manager(self, log_file: Path | None):
        self.traffic_quota_manager = TrafficQuotaManager()
        self.traffic_quota_manager.load_from_log(log_file)

    def attach_router_config(self, router_config):
        if self.auto_proxy_failure_manager is not None:
            self.auto_proxy_failure_manager.shutdown()
            self.auto_proxy_failure_manager = None
        if router_config is not None:
            self.auto_proxy_failure_manager = AutoProxyFailureManager(router_config)

    def apply_auto_proxy_probe_route(self, host: str | None, route_decision):
        if self.auto_proxy_failure_manager is None:
            return route_decision
        return self.auto_proxy_failure_manager.route_override(host, route_decision)

    def record_auto_proxy_success(self, host: str | None, route_decision):
        if self.auto_proxy_failure_manager is None or route_decision is None:
            return
        self.auto_proxy_failure_manager.record_success(
            host,
            route_label=route_decision.get("route_label"),
            profile_id=route_decision.get("profile_id"),
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
        )
        self.traffic_quota_manager.record_usage(
            client=client,
            total_bytes=uploaded_bytes + downloaded_bytes,
            timestamp=timestamp,
        )

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

    def clear_traffic_data(self):
        self.dashboard_state.clear_traffic_data()
        self.usage_logger.clear_data()
        self.failure_logger.clear_data()
        self.traffic_quota_manager.clear()
        if self.auto_proxy_failure_manager is not None:
            self.auto_proxy_failure_manager.clear_observations()

    def close(self):
        if self.auto_proxy_failure_manager is not None:
            self.auto_proxy_failure_manager.shutdown()
            self.auto_proxy_failure_manager = None
        self.usage_logger.close()
        self.failure_logger.close()
