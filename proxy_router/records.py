from __future__ import annotations

import json
import threading
from pathlib import Path
from urllib.parse import urlsplit

from .constants import *
from .util import *

def build_failure_snapshot_from_records(recent_failures, router_config_snapshot):
    ignored_hosts = router_config_snapshot.get("ignored_failure_hosts", [])
    visible_failures = [
        failure for failure in recent_failures if not config_rule_matches_failure(router_config_snapshot, failure)
    ]
    grouped = summarize_failures_by_host(visible_failures, ignored_hosts)
    return {
        "page_size": FAILURE_PAGE_SIZE,
        "recent_failures": recent_failures,
        "grouped_visible": grouped["visible_items"],
        "grouped_ignored": grouped["ignored_items"],
        "visible_total": grouped["visible_total"],
        "ignored_total": grouped["ignored_total"],
    }

class UsageHistoryCache:
    def __init__(self, log_file: Path | None):
        self.log_file = log_file
        self._lock = threading.Lock()
        self._file_id = None
        self._offset = 0
        self._records = []
        self._invalid_lines = 0

    def _reset(self):
        self._file_id = None
        self._offset = 0
        self._records = []
        self._invalid_lines = 0

    def clear(self):
        with self._lock:
            self._reset()

    def _load_if_needed(self):
        if self.log_file is None:
            self._reset()
            return

        try:
            stat = self.log_file.stat()
        except FileNotFoundError:
            self._reset()
            return

        file_id = (getattr(stat, "st_dev", None), getattr(stat, "st_ino", None))
        reload_full = self._file_id != file_id or stat.st_size < self._offset

        if reload_full:
            self._records = []
            self._invalid_lines = 0
            self._offset = 0

        with self.log_file.open("r", encoding="utf-8") as stream:
            if self._offset > 0:
                stream.seek(self._offset)

            for line in stream:
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    self._records.append(json.loads(stripped))
                except json.JSONDecodeError:
                    self._invalid_lines += 1

            self._offset = stream.tell()
            self._file_id = file_id

    def build_history_payload(
        self,
        *,
        range_key: str,
        proxy_type: str | None = None,
        client: str | None = None,
        upstream_proxy_id: str | None = None,
        timezone_name: str | None = None,
        timezone_offset_minutes=None,
    ):
        with self._lock:
            self._load_if_needed()
            records = list(self._records)
            invalid_lines = self._invalid_lines

        return summarize_history_records(
            records,
            invalid_lines=invalid_lines,
            range_key=range_key,
            proxy_type=proxy_type,
            client=client,
            upstream_proxy_id=upstream_proxy_id,
            timezone_name=timezone_name,
            timezone_offset_minutes=timezone_offset_minutes,
        )

    def recent_records(
        self,
        *,
        limit: int,
        proxy_type: str | None = None,
        client: str | None = None,
    ):
        target_limit = max(0, int(limit))
        with self._lock:
            self._load_if_needed()
            records = list(self._records)

        if target_limit == 0:
            return []

        selected = []
        for record in reversed(records):
            if proxy_type is not None and record.get("proxy_type") != proxy_type:
                continue
            if client is not None and record.get("client") != client:
                continue
            selected.append(record)
            if len(selected) >= target_limit:
                break
        return selected

    def query_records(
        self,
        *,
        client: str | None = None,
        client_ip: str | None = None,
        proxy_type: str | None = None,
        upstream_proxy_id: str | None = None,
        route_label: str | None = None,
        host: str | None = None,
        method: str | None = None,
        status_code: str | None = None,
        search: str | None = None,
        sort: str | None = None,
        direction: str | None = None,
        page: int | None = None,
        page_size: int | None = None,
        max_results: int | None = None,
    ):
        with self._lock:
            self._load_if_needed()
            records = list(self._records)
            invalid_lines = self._invalid_lines

        available_clients = sorted({str(item.get("client") or "") for item in records if item.get("client")})
        available_proxy_types = sorted(
            {str(item.get("proxy_type") or "") for item in records if item.get("proxy_type")}
        )
        available_upstream_proxy_ids = sorted(
            {str(item.get("upstream_proxy_id") or "") for item in records if item.get("upstream_proxy_id")}
        )
        available_route_labels = sorted(
            {str(item.get("route_label") or "") for item in records if item.get("route_label")}
        )

        normalized_client = str(client or "").strip()
        normalized_client_ip = str(client_ip or "").strip()
        normalized_proxy_type = str(proxy_type or "").strip()
        normalized_upstream_proxy_id = str(upstream_proxy_id or "").strip()
        normalized_route_label = str(route_label or "").strip()
        normalized_host = str(host or "").strip().lower()
        normalized_method = str(method or "").strip().upper()
        normalized_status = str(status_code or "").strip()
        normalized_search = str(search or "").strip().lower()

        selected = []
        for record in records:
            if normalized_client and str(record.get("client") or "") != normalized_client:
                continue
            if normalized_client_ip and str(record.get("client_ip") or "") != normalized_client_ip:
                continue
            if normalized_proxy_type and str(record.get("proxy_type") or "") != normalized_proxy_type:
                continue
            if normalized_upstream_proxy_id and str(record.get("upstream_proxy_id") or "") != normalized_upstream_proxy_id:
                continue
            if normalized_route_label and str(record.get("route_label") or "") != normalized_route_label:
                continue
            if normalized_host and normalized_host not in self._record_host_text(record):
                continue
            if normalized_method and str(record.get("method") or "").upper() != normalized_method:
                continue
            if normalized_status and str(record.get("status_code") or "") != normalized_status:
                continue
            if normalized_search and normalized_search not in self._record_search_text(record):
                continue
            selected.append(record)

        sort_key = str(sort or "timestamp")
        numeric_sort_keys = {
            "status_code",
            "uploaded_bytes",
            "downloaded_bytes",
            "total_bytes",
            "duration_ms",
            "upstream_setup_ms",
            "relay_ms",
            "throughput_bps",
            "upstream_retry_count",
            "upstream_retry_delay_ms",
        }
        allowed_sort_keys = {
            "timestamp",
            "client",
            "client_ip",
            "host",
            "destination",
            "proxy_type",
            "method",
            "route_label",
            "upstream_proxy_id",
            *numeric_sort_keys,
        }
        if sort_key not in allowed_sort_keys:
            sort_key = "timestamp"
        reverse = str(direction or "desc").lower() != "asc"

        def sortable_value(record):
            value = record.get(sort_key)
            if sort_key == "host":
                value = self._best_host(record)
            if sort_key in numeric_sort_keys:
                return self._int_value(value)
            return str(value or "")

        selected.sort(key=sortable_value, reverse=reverse)

        target_page = max(1, self._int_value(page, default=1))
        target_page_size = min(max(1, self._int_value(page_size, default=50)), 200)
        target_max_results = min(max(1, self._int_value(max_results, default=1000)), 5000)
        total = len(selected)
        truncated = total > target_max_results
        capped = selected[:target_max_results]
        offset = (target_page - 1) * target_page_size
        rows = [self._summary_record(record) for record in capped[offset : offset + target_page_size]]

        return {
            "items": rows,
            "total": total,
            "page": target_page,
            "page_size": target_page_size,
            "max_results": target_max_results,
            "truncated": truncated,
            "invalid_lines": invalid_lines,
            "log_file": str(self.log_file) if self.log_file is not None else None,
            "filters": {
                "client": normalized_client or "all",
                "client_ip": normalized_client_ip,
                "proxy_type": normalized_proxy_type or "all",
                "upstream_proxy_id": normalized_upstream_proxy_id or "all",
                "route_label": normalized_route_label or "all",
                "host": normalized_host,
                "method": normalized_method or "all",
                "status_code": normalized_status,
                "search": normalized_search,
                "sort": sort_key,
                "direction": "desc" if reverse else "asc",
            },
            "available_clients": available_clients,
            "available_proxy_types": available_proxy_types,
            "available_upstream_proxy_ids": available_upstream_proxy_ids,
            "available_route_labels": available_route_labels,
        }

    def _summary_record(self, record):
        return {
            "timestamp": record.get("timestamp"),
            "client": record.get("client"),
            "client_ip": record.get("client_ip"),
            "client_auth_type": record.get("client_auth_type"),
            "client_auth_username": record.get("client_auth_username"),
            "client_auth_label": record.get("client_auth_label"),
            "proxy_type": record.get("proxy_type"),
            "method": record.get("method"),
            "destination": record.get("destination"),
            "host": self._best_host(record),
            "port": record.get("port"),
            "path": record.get("path"),
            "route_label": record.get("route_label"),
            "profile_id": record.get("profile_id"),
            "profile_name": record.get("profile_name"),
            "status_code": record.get("status_code"),
            "uploaded_bytes": record.get("uploaded_bytes", 0),
            "downloaded_bytes": record.get("downloaded_bytes", 0),
            "total_bytes": record.get("total_bytes", 0),
            "duration_ms": record.get("duration_ms"),
            "upstream_setup_ms": record.get("upstream_setup_ms"),
            "relay_ms": record.get("relay_ms"),
            "throughput_bps": record.get("throughput_bps"),
            "upstream_retry_count": record.get("upstream_retry_count"),
            "upstream_retry_delay_ms": record.get("upstream_retry_delay_ms"),
            "upstream_proxy_id": record.get("upstream_proxy_id"),
            "upstream_proxy_name": record.get("upstream_proxy_name"),
            "upstream_proxy_access_mode": record.get("upstream_proxy_access_mode"),
        }

    @staticmethod
    def _int_value(value, *, default: int = 0) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _best_host(record) -> str:
        host = str(record.get("host") or "").strip()
        if host:
            return host
        destination = str(record.get("destination") or "")
        parsed = urlsplit(destination)
        if parsed.hostname:
            return parsed.hostname
        if "/" in destination:
            return destination.split("/", 1)[0]
        if ":" in destination:
            return destination.rsplit(":", 1)[0]
        return destination

    @classmethod
    def _record_host_text(cls, record) -> str:
        return " ".join(
            str(value or "")
            for value in (
                record.get("host"),
                cls._best_host(record),
                record.get("destination"),
            )
        ).lower()

    @classmethod
    def _record_search_text(cls, record) -> str:
        return " ".join(
            str(record.get(key) or "")
            for key in (
                "destination",
                "host",
                "path",
                "client",
                "client_ip",
                "client_auth_username",
                "client_auth_label",
                "proxy_type",
                "method",
                "status_code",
                "route_label",
                "profile_id",
                "profile_name",
                "upstream_proxy_id",
                "upstream_proxy_name",
            )
        ).lower()


class HttpsTrafficCache:
    def __init__(self, log_file: Path | None):
        self.log_file = log_file
        self._lock = threading.Lock()
        self._file_id = None
        self._offset = 0
        self._records = []
        self._invalid_lines = 0

    def _reset(self):
        self._file_id = None
        self._offset = 0
        self._records = []
        self._invalid_lines = 0

    def clear(self):
        with self._lock:
            self._reset()

    def _load_if_needed(self):
        if self.log_file is None:
            self._reset()
            return

        try:
            stat = self.log_file.stat()
        except FileNotFoundError:
            self._reset()
            return

        file_id = (getattr(stat, "st_dev", None), getattr(stat, "st_ino", None))
        reload_full = self._file_id != file_id or stat.st_size < self._offset

        if reload_full:
            self._records = []
            self._invalid_lines = 0
            self._offset = 0

        with self.log_file.open("r", encoding="utf-8") as stream:
            if self._offset > 0:
                stream.seek(self._offset)

            for line in stream:
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    record = json.loads(stripped)
                except json.JSONDecodeError:
                    self._invalid_lines += 1
                    continue
                if isinstance(record, dict):
                    self._records.append(record)
                else:
                    self._invalid_lines += 1

            self._offset = stream.tell()
            self._file_id = file_id

    def query(
        self,
        *,
        client: str | None = None,
        host: str | None = None,
        method: str | None = None,
        status_code: str | None = None,
        search: str | None = None,
        sort: str | None = None,
        direction: str | None = None,
        limit: int | None = None,
    ):
        with self._lock:
            self._load_if_needed()
            records = list(self._records)
            invalid_lines = self._invalid_lines

        available_clients = sorted({str(item.get("client") or "") for item in records if item.get("client")})
        available_hosts = sorted({str(item.get("host") or "") for item in records if item.get("host")})
        available_methods = sorted({str(item.get("method") or "") for item in records if item.get("method")})

        selected = []
        normalized_client = str(client or "").strip()
        normalized_host = str(host or "").strip().lower()
        normalized_method = str(method or "").strip().upper()
        normalized_status = str(status_code or "").strip()
        normalized_search = str(search or "").strip().lower()
        for record in records:
            if normalized_client and str(record.get("client") or "") != normalized_client:
                continue
            if normalized_host and normalized_host not in str(record.get("host") or "").lower():
                continue
            if normalized_method and str(record.get("method") or "").upper() != normalized_method:
                continue
            if normalized_status and str(record.get("status_code") or "") != normalized_status:
                continue
            if normalized_search:
                haystack = " ".join(
                    str(record.get(key) or "")
                    for key in ("destination", "host", "path", "client", "method", "status_code")
                ).lower()
                if normalized_search not in haystack:
                    continue
            selected.append(record)

        sort_key = str(sort or "timestamp")
        allowed_sort_keys = {
            "timestamp",
            "status_code",
            "method",
            "host",
            "client",
            "total_bytes",
            "duration_ms",
        }
        if sort_key not in allowed_sort_keys:
            sort_key = "timestamp"
        reverse = str(direction or "desc").lower() != "asc"

        def sortable_value(record):
            value = record.get(sort_key)
            if sort_key in {"status_code", "total_bytes", "duration_ms"}:
                try:
                    return int(value or 0)
                except (TypeError, ValueError):
                    return 0
            return str(value or "")

        selected.sort(key=sortable_value, reverse=reverse)
        target_limit = min(max(1, int(limit or HTTPS_TRAFFIC_QUERY_LIMIT)), HTTPS_TRAFFIC_MAX_QUERY_LIMIT)
        rows = [self._summary_record(record) for record in selected[:target_limit]]

        return {
            "items": rows,
            "total": len(selected),
            "limit": target_limit,
            "invalid_lines": invalid_lines,
            "log_file": str(self.log_file) if self.log_file is not None else None,
            "filters": {
                "client": normalized_client or "all",
                "host": normalized_host,
                "method": normalized_method or "all",
                "status_code": normalized_status,
                "search": normalized_search,
                "sort": sort_key,
                "direction": "desc" if reverse else "asc",
            },
            "available_clients": available_clients,
            "available_hosts": available_hosts,
            "available_methods": available_methods,
        }

    def detail(self, request_id: str | None):
        normalized_id = str(request_id or "").strip()
        if not normalized_id:
            return None
        with self._lock:
            self._load_if_needed()
            for record in reversed(self._records):
                if str(record.get("id") or "") == normalized_id:
                    return json.loads(json.dumps(record))
        return None

    def _summary_record(self, record):
        request = record.get("request") if isinstance(record.get("request"), dict) else {}
        response = record.get("response") if isinstance(record.get("response"), dict) else {}
        return {
            "id": record.get("id"),
            "timestamp": record.get("timestamp"),
            "client": record.get("client"),
            "client_ip": record.get("client_ip"),
            "method": record.get("method"),
            "scheme": record.get("scheme"),
            "host": record.get("host"),
            "port": record.get("port"),
            "path": record.get("path"),
            "destination": record.get("destination"),
            "route_label": record.get("route_label"),
            "profile_id": record.get("profile_id"),
            "status_code": record.get("status_code"),
            "reason": record.get("reason"),
            "duration_ms": record.get("duration_ms"),
            "throughput_bps": record.get("throughput_bps"),
            "request_body_bytes": request.get("body_bytes", 0),
            "response_body_bytes": response.get("body_bytes", 0),
            "total_bytes": record.get("total_bytes", 0),
            "content_type": response.get("content_type", ""),
            "truncated": bool((request.get("body_preview") or {}).get("truncated"))
            or bool((response.get("body_preview") or {}).get("truncated")),
        }
