from __future__ import annotations

import json
import threading
from pathlib import Path

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
            "request_body_bytes": request.get("body_bytes", 0),
            "response_body_bytes": response.get("body_bytes", 0),
            "total_bytes": record.get("total_bytes", 0),
            "content_type": response.get("content_type", ""),
            "truncated": bool((request.get("body_preview") or {}).get("truncated"))
            or bool((response.get("body_preview") or {}).get("truncated")),
        }
