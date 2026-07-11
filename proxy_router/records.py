from __future__ import annotations

import json
import heapq
import os
import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from .constants import *
from .util import *


def iter_jsonl_records(log_file: Path | None):
    if log_file is None:
        return
    try:
        with log_file.open("r", encoding="utf-8", errors="replace") as stream:
            for line in stream:
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    record = json.loads(stripped)
                except json.JSONDecodeError:
                    continue
                if isinstance(record, dict):
                    yield record
    except FileNotFoundError:
        return


def compact_jsonl_file(log_file: Path | None, *, retention_days: int, reference_time: datetime | None = None) -> dict:
    if log_file is None or not log_file.exists():
        return {"kept": 0, "removed": 0, "invalid": 0}
    cutoff = (reference_time or datetime.now().astimezone()).timestamp() - (retention_days * 86400)
    temporary = log_file.with_name(f".{log_file.name}.compact-{os.getpid()}")
    kept = 0
    removed = 0
    invalid = 0
    try:
        with log_file.open("r", encoding="utf-8", errors="replace") as source, temporary.open(
            "w", encoding="utf-8"
        ) as destination:
            for line in source:
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    record = json.loads(stripped)
                except json.JSONDecodeError:
                    invalid += 1
                    continue
                timestamp = parse_usage_timestamp(str(record.get("timestamp") or "")) if isinstance(record, dict) else None
                if timestamp is None:
                    invalid += 1
                    continue
                if timestamp.timestamp() < cutoff:
                    removed += 1
                    continue
                destination.write(json.dumps(record, sort_keys=True) + "\n")
                kept += 1
            destination.flush()
            os.fsync(destination.fileno())
        temporary.chmod(log_file.stat().st_mode & 0o777)
        os.replace(temporary, log_file)
    finally:
        temporary.unlink(missing_ok=True)
    return {"kept": kept, "removed": removed, "invalid": invalid}


class _IncrementalJsonlCache:
    def __init__(self, log_file: Path | None):
        self.log_file = log_file
        self._lock = threading.Lock()
        self._file_id = None
        self._offset = 0
        self._records = []
        self._invalid_lines = 0

    def snapshot(self):
        with self._lock:
            self._load_if_needed()
            return list(self._records), self._invalid_lines

    def _load_if_needed(self):
        if self.log_file is None:
            self._file_id = None
            self._offset = 0
            self._records = []
            self._invalid_lines = 0
            return
        try:
            stat = self.log_file.stat()
        except FileNotFoundError:
            self._file_id = None
            self._offset = 0
            self._records = []
            self._invalid_lines = 0
            return
        file_id = (getattr(stat, "st_dev", None), getattr(stat, "st_ino", None))
        if self._file_id != file_id or stat.st_size < self._offset:
            self._offset = 0
            self._records = []
            self._invalid_lines = 0
        with self.log_file.open("r", encoding="utf-8") as stream:
            if self._offset:
                stream.seek(self._offset)
            for line in stream:
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    item = json.loads(stripped)
                except json.JSONDecodeError:
                    self._invalid_lines += 1
                    continue
                if isinstance(item, dict):
                    self._records.append(item)
                else:
                    self._invalid_lines += 1
            self._offset = stream.tell()
            self._file_id = file_id


class ClientBlockHistoryStore:
    def __init__(self, log_file: Path | None):
        self.log_file = log_file
        self._lock = threading.Lock()
        self._last_fingerprint = None
        if log_file is not None:
            records, _ = _IncrementalJsonlCache(log_file).snapshot()
            if records:
                self._last_fingerprint = self._fingerprint(records[-1].get("blocks"))

    @staticmethod
    def _normalized_blocks(blocks):
        normalized = []
        for block in blocks or []:
            if not isinstance(block, dict):
                continue
            client = str(block.get("client") or "").strip()
            if not client:
                continue
            normalized.append(
                {
                    "client": client,
                    "enabled": bool(block.get("enabled", True)),
                    "duration": str(block.get("duration") or "always"),
                    "expires_at": block.get("expires_at"),
                    "note": str(block.get("note") or ""),
                }
            )
        normalized.sort(key=lambda item: item["client"])
        return normalized

    @classmethod
    def _fingerprint(cls, blocks):
        return json.dumps(cls._normalized_blocks(blocks), sort_keys=True, separators=(",", ":"))

    def record_snapshot(self, blocks, *, timestamp: str | None = None):
        if self.log_file is None:
            return False
        normalized = self._normalized_blocks(blocks)
        fingerprint = self._fingerprint(normalized)
        with self._lock:
            if fingerprint == self._last_fingerprint:
                return False
            self.log_file.parent.mkdir(parents=True, exist_ok=True)
            event = {
                "timestamp": timestamp or datetime.now().astimezone().isoformat(timespec="milliseconds"),
                "blocks": normalized,
            }
            with self.log_file.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(event, sort_keys=True) + "\n")
            self._last_fingerprint = fingerprint
        return True


class ClientActivityCache:
    def __init__(
        self,
        presence_history_file: Path | None,
        block_history_file: Path | None,
        failure_log_file: Path | None,
    ):
        self.presence_history_file = presence_history_file
        self.block_history_file = block_history_file
        self.failure_log_file = failure_log_file
        self._presence = _IncrementalJsonlCache(presence_history_file)
        self._blocks = _IncrementalJsonlCache(block_history_file)
        self._failures = _IncrementalJsonlCache(failure_log_file)

    @staticmethod
    def _timestamp(value):
        parsed = parse_usage_timestamp(str(value or ""))
        if parsed is None:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    @staticmethod
    def _merge_segments(segments):
        merged = []
        for segment in segments:
            if segment["end_at"] <= segment["start_at"]:
                continue
            if (
                merged
                and merged[-1]["state"] == segment["state"]
                and merged[-1].get("reason") == segment.get("reason")
                and merged[-1].get("block_target") == segment.get("block_target")
                and merged[-1]["end_at"] == segment["start_at"]
            ):
                merged[-1]["end_at"] = segment["end_at"]
                continue
            merged.append(segment)
        return merged

    def _presence_segments(self, events, start, end):
        valid = []
        for event in events:
            timestamp = self._timestamp(event.get("timestamp"))
            state = str(event.get("state") or "unknown").lower()
            if timestamp is None or timestamp > end or state not in {"online", "offline", "unknown"}:
                continue
            valid.append((timestamp, state, event.get("reason")))
        valid.sort(key=lambda item: item[0])
        state = "unknown"
        reason = None
        for timestamp, next_state, next_reason in valid:
            if timestamp > start:
                break
            state = next_state
            reason = next_reason
        cursor = start
        segments = []
        for timestamp, next_state, next_reason in valid:
            if timestamp <= start:
                continue
            if timestamp > cursor:
                segments.append({"start_at": cursor, "end_at": timestamp, "state": state, "reason": reason})
            cursor = timestamp
            state = next_state
            reason = next_reason
        if cursor < end:
            segments.append({"start_at": cursor, "end_at": end, "state": state, "reason": reason})
        return self._merge_segments(segments)

    def _matching_block(self, blocks, client, at):
        matches = []
        for block in blocks or []:
            if not isinstance(block, dict) or not block.get("enabled", True):
                continue
            target = str(block.get("client") or "").strip()
            if not target or not client_ip_matches_limit_target(client, target):
                continue
            expires_at = self._timestamp(block.get("expires_at"))
            if expires_at is not None and expires_at <= at:
                continue
            matches.append((client_limit_target_specificity(target), target, expires_at))
        return max(matches, default=None, key=lambda item: item[0])

    def _block_intervals(self, snapshots, client, start, end):
        parsed = []
        for snapshot in snapshots:
            timestamp = self._timestamp(snapshot.get("timestamp"))
            if timestamp is not None and timestamp <= end:
                parsed.append((timestamp, snapshot.get("blocks") or []))
        parsed.sort(key=lambda item: item[0])
        effective = None
        inside = []
        for item in parsed:
            if item[0] <= start:
                effective = item
            else:
                inside.append(item)
        timeline = []
        if effective is not None:
            timeline.append((start, effective[1]))
        timeline.extend(inside)
        intervals = []
        for index, (timestamp, blocks) in enumerate(timeline):
            segment_end = timeline[index + 1][0] if index + 1 < len(timeline) else end
            match = self._matching_block(blocks, client, timestamp)
            if match is None:
                continue
            _, target, expires_at = match
            interval_end = min(segment_end, expires_at) if expires_at is not None else segment_end
            if interval_end > timestamp:
                intervals.append({"start_at": timestamp, "end_at": interval_end, "target": target})
        return intervals

    def _overlay_blocks(self, segments, intervals):
        boundaries = {segment["start_at"] for segment in segments} | {segment["end_at"] for segment in segments}
        for interval in intervals:
            boundaries.add(interval["start_at"])
            boundaries.add(interval["end_at"])
        ordered = sorted(boundaries)
        result = []
        for left, right in zip(ordered, ordered[1:]):
            base = next((item for item in segments if item["start_at"] <= left < item["end_at"]), None)
            block = next((item for item in intervals if item["start_at"] <= left < item["end_at"]), None)
            if base is None:
                continue
            result.append(
                {
                    "start_at": left,
                    "end_at": right,
                    "state": "blocked" if block else base["state"],
                    "reason": "client_access_block" if block else base.get("reason"),
                    "block_target": block.get("target") if block else None,
                }
            )
        return self._merge_segments(result)

    def query(
        self,
        *,
        range_key: str,
        client: str | None,
        configured_users,
        current_presence,
        now: datetime | None = None,
    ):
        window = CLIENT_ACTIVITY_RANGE_OPTIONS.get(range_key, CLIENT_ACTIVITY_RANGE_OPTIONS["24h"])
        end = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        start = end - window
        presence_records, presence_invalid = self._presence.snapshot()
        block_records, block_invalid = self._blocks.snapshot()
        failure_records, failure_invalid = self._failures.snapshot()

        labels = {}
        clients = set()
        for credential in configured_users or []:
            username = str(credential.get("username") or "").strip()
            if not username:
                continue
            user_id = client_identity_from_username(username)
            clients.add(user_id)
            labels[user_id] = str(credential.get("label") or username).strip()
        for event in presence_records:
            event_client = str(event.get("client") or "").strip()
            if event_client.startswith("user:"):
                clients.add(event_client)
        presence_snapshot = current_presence if isinstance(current_presence, dict) else {}
        generated_at = presence_snapshot.get("generated_at")
        for event_client, item in (presence_snapshot.get("clients") or {}).items():
            if not str(event_client).startswith("user:") or not isinstance(item, dict):
                continue
            clients.add(str(event_client))
            presence_records.append(
                {
                    "timestamp": generated_at,
                    "client": event_client,
                    "state": item.get("state"),
                    "reason": item.get("offline_reason"),
                }
            )
        for failure in failure_records:
            failure_client = str(failure.get("client") or "").strip()
            if failure_client.startswith("user:"):
                clients.add(failure_client)
        for snapshot in block_records:
            for block in snapshot.get("blocks") or []:
                target = str((block or {}).get("client") or "").strip()
                if target.startswith("user:"):
                    clients.add(target)

        selected_client = str(client or "").strip()
        if selected_client:
            clients = {selected_client}
        rows = []
        for user_id in sorted(clients):
            user_events = [item for item in presence_records if str(item.get("client") or "") == user_id]
            base_segments = self._presence_segments(user_events, start, end)
            block_intervals = self._block_intervals(block_records, user_id, start, end)
            segments = self._overlay_blocks(base_segments, block_intervals)
            totals = {"connected_seconds": 0, "disconnected_seconds": 0, "blocked_seconds": 0, "unknown_seconds": 0}
            for segment in segments:
                seconds = max(0, int((segment["end_at"] - segment["start_at"]).total_seconds()))
                key = {
                    "online": "connected_seconds",
                    "offline": "disconnected_seconds",
                    "blocked": "blocked_seconds",
                }.get(segment["state"], "unknown_seconds")
                totals[key] += seconds
                segment["start_at"] = segment["start_at"].isoformat()
                segment["end_at"] = segment["end_at"].isoformat()
            attempts = []
            for failure in failure_records:
                if str(failure.get("client") or "") != user_id:
                    continue
                if str(failure.get("route_label") or "") not in {CLIENT_BLOCK_ROUTE_LABEL, CLIENT_TRAFFIC_ROUTE_LABEL}:
                    continue
                timestamp = self._timestamp(failure.get("timestamp"))
                if timestamp is None or timestamp < start or timestamp > end:
                    continue
                attempts.append(
                    {
                        "timestamp": timestamp.isoformat(),
                        "route_label": failure.get("route_label"),
                        "destination": failure.get("destination"),
                        "context": failure.get("context"),
                    }
                )
            attempts.sort(key=lambda item: item["timestamp"], reverse=True)
            current_state = segments[-1]["state"] if segments else "unknown"
            rows.append(
                {
                    "client": user_id,
                    "label": labels.get(user_id, user_id.removeprefix("user:")),
                    "current_state": current_state,
                    "segments": segments,
                    "summary": totals,
                    "blocked_attempts": attempts[:200],
                }
            )
        rank = {"blocked": 0, "online": 1, "offline": 2, "unknown": 3}
        rows.sort(key=lambda item: (rank.get(item["current_state"], 3), item["client"]))
        return {
            "range": range_key if range_key in CLIENT_ACTIVITY_RANGE_OPTIONS else "24h",
            "from": start.isoformat(),
            "to": end.isoformat(),
            "rows": rows,
            "client": selected_client or "all",
            "presence_history_available": bool(self.presence_history_file and self.presence_history_file.exists()),
            "invalid_lines": {
                "presence": presence_invalid,
                "blocks": block_invalid,
                "failures": failure_invalid,
            },
        }

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
        self._file_size = 0
        self._history_payload_cache = {}

    def _reset(self):
        self._file_id = None
        self._file_size = 0
        self._history_payload_cache = {}

    def clear(self):
        with self._lock:
            self._reset()

    def _load_if_needed(self):
        if self.log_file is None:
            self._reset()
            return False

        try:
            stat = self.log_file.stat()
        except FileNotFoundError:
            self._reset()
            return False

        file_id = (getattr(stat, "st_dev", None), getattr(stat, "st_ino", None))
        rotated = self._file_id != file_id or stat.st_size < self._file_size
        changed = rotated or stat.st_size != self._file_size
        if rotated:
            self._history_payload_cache = {}
        self._file_id = file_id
        self._file_size = stat.st_size
        return changed

    def _iter_records(self, invalid_lines: list[int] | None = None):
        if self.log_file is None:
            return
        try:
            stream = self.log_file.open("r", encoding="utf-8", errors="replace")
        except FileNotFoundError:
            return
        with stream:
            for line in stream:
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    record = json.loads(stripped)
                except json.JSONDecodeError:
                    if invalid_lines is not None:
                        invalid_lines[0] += 1
                    continue
                if isinstance(record, dict):
                    yield record
                elif invalid_lines is not None:
                    invalid_lines[0] += 1

    def _history_payload_cache_key(
        self,
        *,
        range_key: str,
        proxy_type: str | None,
        client: str | None,
        upstream_proxy_id: str | None,
        timezone_name: str | None,
        timezone_offset_minutes,
    ):
        time_bucket = int(time.time() // HISTORY_SUMMARY_CACHE_SECONDS)
        return (
            time_bucket,
            self._file_id,
            str(range_key or ""),
            str(proxy_type or ""),
            str(client or ""),
            str(upstream_proxy_id or ""),
            str(timezone_name or ""),
            str(timezone_offset_minutes or ""),
        )

    @staticmethod
    def _clone_payload(payload):
        return json.loads(json.dumps(payload))

    def _remember_history_payload(self, cache_key, payload):
        if len(self._history_payload_cache) >= HISTORY_SUMMARY_CACHE_MAX_SIZE:
            self._history_payload_cache.pop(next(iter(self._history_payload_cache)), None)
        self._history_payload_cache[cache_key] = self._clone_payload(payload)

    def _summarize_history_payload(
        self,
        *,
        range_key: str,
        proxy_type: str | None,
        client: str | None,
        upstream_proxy_id: str | None,
        timezone_name: str | None,
        timezone_offset_minutes,
    ):
        invalid_lines = [0]
        payload = summarize_history_records(
            self._iter_records(invalid_lines),
            invalid_lines=0,
            range_key=range_key,
            proxy_type=proxy_type,
            client=client,
            upstream_proxy_id=upstream_proxy_id,
            timezone_name=timezone_name,
            timezone_offset_minutes=timezone_offset_minutes,
        )
        payload["invalid_lines"] = invalid_lines[0]
        return payload

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
            cache_key = self._history_payload_cache_key(
                range_key=range_key,
                proxy_type=proxy_type,
                client=client,
                upstream_proxy_id=upstream_proxy_id,
                timezone_name=timezone_name,
                timezone_offset_minutes=timezone_offset_minutes,
            )
            cached_payload = self._history_payload_cache.get(cache_key)
            if cached_payload is not None:
                return self._clone_payload(cached_payload)

        payload = self._summarize_history_payload(
            range_key=range_key,
            proxy_type=proxy_type,
            client=client,
            upstream_proxy_id=upstream_proxy_id,
            timezone_name=timezone_name,
            timezone_offset_minutes=timezone_offset_minutes,
        )
        with self._lock:
            self._load_if_needed()
            if cache_key[1] == self._file_id:
                self._remember_history_payload(cache_key, payload)
        return self._clone_payload(payload)

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

        if target_limit == 0:
            return []

        selected = deque(maxlen=target_limit)
        for record in self._iter_records():
            if proxy_type is not None and record.get("proxy_type") != proxy_type:
                continue
            if client is not None and record.get("client") != client:
                continue
            selected.append(record)
        return list(reversed(selected))

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

        normalized_client = str(client or "").strip()
        normalized_client_ip = str(client_ip or "").strip()
        normalized_proxy_type = str(proxy_type or "").strip()
        normalized_upstream_proxy_id = str(upstream_proxy_id or "").strip()
        normalized_route_label = str(route_label or "").strip()
        normalized_host = str(host or "").strip().lower()
        normalized_method = str(method or "").strip().upper()
        normalized_status = str(status_code or "").strip()
        normalized_search = str(search or "").strip().lower()

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

        target_page = max(1, self._int_value(page, default=1))
        target_page_size = min(max(1, self._int_value(page_size, default=50)), 200)
        target_max_results = min(max(1, self._int_value(max_results, default=1000)), 5000)
        available_clients = set()
        available_proxy_types = set()
        available_upstream_proxy_ids = set()
        available_route_labels = set()
        invalid_lines = [0]
        total = [0]

        def matched_records():
            for record in self._iter_records(invalid_lines):
                record_client = str(record.get("client") or "")
                record_proxy_type = str(record.get("proxy_type") or "")
                record_upstream_proxy_id = str(record.get("upstream_proxy_id") or "")
                record_route_label = str(record.get("route_label") or "")
                if record_client:
                    available_clients.add(record_client)
                if record_proxy_type:
                    available_proxy_types.add(record_proxy_type)
                if record_upstream_proxy_id:
                    available_upstream_proxy_ids.add(record_upstream_proxy_id)
                if record_route_label:
                    available_route_labels.add(record_route_label)
                if normalized_client and record_client != normalized_client:
                    continue
                if normalized_client_ip and str(record.get("client_ip") or "") != normalized_client_ip:
                    continue
                if normalized_proxy_type and record_proxy_type != normalized_proxy_type:
                    continue
                if normalized_upstream_proxy_id and record_upstream_proxy_id != normalized_upstream_proxy_id:
                    continue
                if normalized_route_label and record_route_label != normalized_route_label:
                    continue
                if normalized_host and normalized_host not in self._record_host_text(record):
                    continue
                if normalized_method and str(record.get("method") or "").upper() != normalized_method:
                    continue
                if normalized_status and str(record.get("status_code") or "") != normalized_status:
                    continue
                if normalized_search and normalized_search not in self._record_search_text(record):
                    continue
                total[0] += 1
                yield record

        selector = heapq.nlargest if reverse else heapq.nsmallest
        capped = selector(target_max_results, matched_records(), key=sortable_value)
        total_count = total[0]
        truncated = total_count > target_max_results
        offset = (target_page - 1) * target_page_size
        rows = [self._summary_record(record) for record in capped[offset : offset + target_page_size]]

        return {
            "items": rows,
            "total": total_count,
            "page": target_page,
            "page_size": target_page_size,
            "max_results": target_max_results,
            "truncated": truncated,
            "invalid_lines": invalid_lines[0],
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
            "available_clients": sorted(available_clients),
            "available_proxy_types": sorted(available_proxy_types),
            "available_upstream_proxy_ids": sorted(available_upstream_proxy_ids),
            "available_route_labels": sorted(available_route_labels),
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
