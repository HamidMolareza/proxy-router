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
