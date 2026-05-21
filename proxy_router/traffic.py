from __future__ import annotations

import json
import socket
import ssl
import threading
from collections import deque
from datetime import datetime, timedelta
from pathlib import Path

from .config import RouterConfigManager
from .constants import *
from .output import debug_exception, debug_log, log_event
from .util import *

class AutoProxyFailureManager:
    def __init__(self, router_config: RouterConfigManager):
        self.router_config = router_config
        self.state_file = auto_proxy_state_file_path(router_config.config_file)
        self._lock = threading.Lock()
        self._state = self._load_state()
        self._stop_event = threading.Event()
        self._wake_event = threading.Event()
        self._reconcile_state()
        self._thread = threading.Thread(
            target=self._run,
            name="auto-proxy-failure-manager",
            daemon=True,
        )
        self._thread.start()

    def record_failure(
        self,
        host: str | None,
        *,
        route_label: str | None = None,
        destination: str | None = None,
        error: str | None = None,
        context: str | None = None,
        client: str | None = None,
        method: str | None = None,
        profile_id: str | None = None,
    ):
        evaluation = self.router_config.auto_proxy_evaluation(host, profile_id=profile_id)
        pattern = evaluation["pattern"]
        if not pattern:
            return
        resolved_profile_id = evaluation.get("profile_id") or DEFAULT_ROUTING_PROFILE_ID

        now = datetime.now().astimezone()
        normalized_route_label = str(route_label or "direct")
        synthetic_failure = None
        with self._lock:
            profile_domains = self._profile_domains_locked(resolved_profile_id, create=True)
            if evaluation["handled"] or evaluation["ignored"] or not evaluation["enabled"] or not evaluation["upstream_enabled"]:
                state = profile_domains.get(pattern)
                if state is not None and self._clear_review_state_locked(pattern, state):
                    self._save_state_locked()
                self._wake_event.set()
                return

            if is_auto_proxy_probe_route_label(normalized_route_label):
                state = profile_domains.setdefault(pattern, self._default_state())
                state["probe_pending"] = False
                state["probe_in_flight"] = False
                state["manual_review"] = True
                state["failure_count"] = 0
                state["last_failure_at"] = now.isoformat()
                synthetic_failure = {
                    "timestamp": now.isoformat(timespec="milliseconds"),
                    "proxy_type": "system",
                    "client": client or "",
                    "method": method or "AUTO",
                    "destination": destination or (evaluation["host"] or pattern),
                    "host": evaluation["host"] or pattern,
                    "port": None,
                    "error": error or "Automatic proxy probe failed.",
                    "context": context or "auto-proxy probe failed",
                    "route_label": normalized_route_label,
                    "matched_rule": None,
                    "profile_id": resolved_profile_id,
                }
                state["review_failure"] = synthetic_failure
                self._save_state_locked()
                self._wake_event.set()
                return

            if not evaluation["eligible"]:
                self._wake_event.set()
                return

            state = profile_domains.setdefault(pattern, self._default_state())
            active_until = parse_datetime_text(state.get("active_until"))
            if active_until is not None and active_until <= now:
                self._clear_active_activation_locked(state, completed=True)
                active_until = None
            if active_until is None or active_until <= now:
                state["failure_count"] = int(state.get("failure_count", 0)) + 1
                state["last_failure_at"] = now.isoformat()
                required_failures = self._required_failures_locked(state)
                if state["failure_count"] >= required_failures:
                    state["probe_pending"] = True
                self._save_state_locked()

        self._wake_event.set()

    def record_success(
        self,
        host: str | None,
        *,
        route_label: str | None = None,
        profile_id: str | None = None,
        proxy_id: str | None = None,
    ):
        pattern = summarize_domain(host) or normalize_host(host or "")
        if not pattern or is_ip_address_text(pattern):
            return

        activation = None
        normalized_route_label = str(route_label or "direct")
        now = datetime.now().astimezone()
        resolved_profile_id = str(profile_id or DEFAULT_ROUTING_PROFILE_ID)
        with self._lock:
            profile_domains = self._profile_domains_locked(resolved_profile_id, create=bool(is_auto_proxy_probe_route_label(normalized_route_label)))
            state = profile_domains.get(pattern)
            if state is None and not is_auto_proxy_probe_route_label(normalized_route_label):
                return
            if state is None:
                state = profile_domains.setdefault(pattern, self._default_state())
            if is_auto_proxy_probe_route_label(normalized_route_label):
                activation = self._prepare_activation_locked(
                    resolved_profile_id,
                    pattern,
                    normalize_host(host or pattern),
                    state,
                    now,
                    proxy_id=proxy_id,
                )
                state["last_success_at"] = now.isoformat()
                state["probe_pending"] = False
                state["probe_in_flight"] = False
                state["manual_review"] = False
                state["review_failure"] = None
                self._save_state_locked()
            else:
                state["last_success_at"] = now.isoformat()
                if self._clear_review_state_locked(pattern, state):
                    self._save_state_locked()
                else:
                    self._save_state_locked()

        if activation is not None:
            self._activate_rule(activation)
        self._wake_event.set()

    def route_override(self, host: str | None, route_decision):
        pattern = summarize_domain(host) or normalize_host(host or "")
        if not pattern or is_ip_address_text(pattern):
            return route_decision
        if route_decision.get("action") != "direct" or route_decision.get("matched_rule") is not None:
            return route_decision
        upstream = route_decision.get("upstream")
        if upstream is None:
            return route_decision
        profile_id = str(route_decision.get("profile_id") or DEFAULT_ROUTING_PROFILE_ID)

        with self._lock:
            state = self._profile_domains_locked(profile_id).get(pattern)
            if state is None or not state.get("probe_pending"):
                return route_decision
            state["probe_pending"] = False
            state["probe_in_flight"] = True
            self._save_state_locked()

        probe_decision = dict(route_decision)
        probe_decision["action"] = "proxy"
        probe_decision["route_label"] = build_auto_proxy_probe_route_label(upstream)
        probe_decision["matched_rule"] = None
        probe_decision["auto_proxy_probe"] = True
        probe_decision["auto_proxy_pattern"] = pattern
        return probe_decision

    def status_probe_route(self, host: str | None, route_decision, *, status_code: int | None = None):
        try:
            normalized_status_code = int(status_code or 0)
        except (TypeError, ValueError):
            return None
        if normalized_status_code != 403:
            return None

        pattern = summarize_domain(host) or normalize_host(host or "")
        if not pattern or is_ip_address_text(pattern):
            return None
        if route_decision.get("action") != "direct" or route_decision.get("matched_rule") is not None:
            return None
        upstream = route_decision.get("upstream")
        if upstream is None:
            return None

        profile_id = str(route_decision.get("profile_id") or DEFAULT_ROUTING_PROFILE_ID)
        evaluation = self.router_config.auto_proxy_evaluation(host, profile_id=profile_id)
        if not evaluation["eligible"]:
            return None
        resolved_profile_id = evaluation.get("profile_id") or profile_id

        with self._lock:
            state = self._profile_domains_locked(resolved_profile_id, create=True).setdefault(
                pattern,
                self._default_state(),
            )
            state["probe_pending"] = False
            state["probe_in_flight"] = True
            self._save_state_locked()

        probe_decision = dict(route_decision)
        probe_decision["action"] = "proxy"
        probe_decision["route_label"] = build_auto_proxy_probe_route_label(upstream)
        probe_decision["matched_rule"] = None
        probe_decision["profile_id"] = resolved_profile_id
        probe_decision["auto_proxy_probe"] = True
        probe_decision["auto_proxy_pattern"] = pattern
        return probe_decision

    def direct_failure_probe_route(self, host: str | None, route_decision):
        pattern = summarize_domain(host) or normalize_host(host or "")
        if not pattern or is_ip_address_text(pattern):
            return None
        if route_decision.get("action") != "direct" or route_decision.get("matched_rule") is not None:
            return None
        upstream = route_decision.get("upstream")
        if upstream is None:
            return None

        profile_id = str(route_decision.get("profile_id") or DEFAULT_ROUTING_PROFILE_ID)
        evaluation = self.router_config.auto_proxy_evaluation(host, profile_id=profile_id)
        if not evaluation["eligible"]:
            return None
        resolved_profile_id = evaluation.get("profile_id") or profile_id

        with self._lock:
            state = self._profile_domains_locked(resolved_profile_id, create=True).setdefault(
                pattern,
                self._default_state(),
            )
            state["failure_count"] = max(1, int(state.get("failure_count", 0)))
            state["last_failure_at"] = datetime.now().astimezone().isoformat()
            state["probe_pending"] = False
            state["probe_in_flight"] = True
            self._save_state_locked()

        probe_decision = dict(route_decision)
        probe_decision["action"] = "proxy"
        probe_decision["route_label"] = build_auto_proxy_probe_route_label(upstream)
        probe_decision["matched_rule"] = None
        probe_decision["profile_id"] = resolved_profile_id
        probe_decision["auto_proxy_probe"] = True
        probe_decision["auto_proxy_pattern"] = pattern
        return probe_decision

    def manual_review_failures(self, *, profile_id: str | None = None):
        review_failures = []
        active_profile_id = self._resolved_profile_id(profile_id)
        with self._lock:
            for pattern, state in self._profile_domains_locked(active_profile_id).items():
                if not state.get("manual_review"):
                    continue
                failure = state.get("review_failure") or {}
                timestamp = str(
                    failure.get("timestamp")
                    or state.get("last_failure_at")
                    or datetime.now().astimezone().isoformat(timespec="milliseconds")
                )
                review_failures.append(
                    {
                        "timestamp": timestamp,
                        "proxy_type": str(failure.get("proxy_type") or "system"),
                        "client": str(failure.get("client") or ""),
                        "method": str(failure.get("method") or "AUTO"),
                        "destination": str(failure.get("destination") or pattern),
                        "host": str(failure.get("host") or pattern),
                        "port": failure.get("port"),
                        "error": str(
                            failure.get("error")
                            or "Direct traffic failed repeatedly and an automatic proxy probe also failed."
                        ),
                        "context": str(failure.get("context") or "auto-proxy manual review"),
                        "route_label": str(
                            failure.get("route_label") or f"{AUTO_PROXY_PROBE_ROUTE_LABEL_PREFIX}failed"
                        ),
                        "matched_rule": None,
                        "profile_id": active_profile_id,
                    }
                )
        return review_failures

    def filter_resolved_failures(self, failures, *, profile_id: str | None = None):
        active_profile_id = self._resolved_profile_id(profile_id)
        with self._lock:
            state_by_pattern = {
                pattern: {
                    "manual_review": bool(state.get("manual_review")),
                    "last_success_at": parse_datetime_text(state.get("last_success_at")),
                }
                for pattern, state in self._profile_domains_locked(active_profile_id).items()
            }

        filtered = []
        for failure in failures:
            failure_profile_id = str(failure.get("profile_id") or DEFAULT_ROUTING_PROFILE_ID)
            if failure_profile_id != active_profile_id:
                continue
            pattern = summarize_domain(failure.get("host")) or normalize_host(str(failure.get("host") or ""))
            if not pattern:
                filtered.append(failure)
                continue
            state = state_by_pattern.get(pattern)
            if state is None or state["manual_review"]:
                filtered.append(failure)
                continue
            failure_timestamp = parse_datetime_text(failure.get("timestamp"))
            if state["last_success_at"] is not None and failure_timestamp is not None and failure_timestamp <= state["last_success_at"]:
                continue
            filtered.append(failure)
        return filtered

    def clear_observations(self):
        with self._lock:
            dirty = False
            for profile_entry in self._state.get("profiles", {}).values():
                for state in profile_entry.get("domains", {}).values():
                    if any(
                        (
                            state.get("failure_count"),
                            state.get("probe_pending"),
                            state.get("probe_in_flight"),
                            state.get("manual_review"),
                            state.get("review_failure"),
                            state.get("last_failure_at"),
                            state.get("last_success_at"),
                        )
                    ):
                        state["failure_count"] = 0
                        state["probe_pending"] = False
                        state["probe_in_flight"] = False
                        state["manual_review"] = False
                        state["review_failure"] = None
                        state["last_failure_at"] = None
                        state["last_success_at"] = None
                        dirty = True
            if dirty:
                self._save_state_locked()

    def shutdown(self):
        self._stop_event.set()
        self._wake_event.set()
        self._thread.join(timeout=2)

    def _default_state(self):
        return {
            "activation_count": 0,
            "active_until": None,
            "failure_count": 0,
            "probe_pending": False,
            "probe_in_flight": False,
            "manual_review": False,
            "last_activated_at": None,
            "last_failure_at": None,
            "last_success_at": None,
            "review_failure": None,
        }

    def _load_state(self):
        try:
            payload = json.loads(self.state_file.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {"version": 2, "profiles": {}}
        except (OSError, json.JSONDecodeError):
            return {"version": 2, "profiles": {}}

        if not isinstance(payload, dict):
            return {"version": 2, "profiles": {}}

        legacy_activation_counts = int(payload.get("version", 1)) < 2
        loaded_profiles = {}
        raw_profiles = payload.get("profiles")
        if isinstance(raw_profiles, dict):
            for raw_profile_id, raw_profile_entry in raw_profiles.items():
                profile_id = str(raw_profile_id or "").strip() or DEFAULT_ROUTING_PROFILE_ID
                raw_domains = raw_profile_entry.get("domains", {}) if isinstance(raw_profile_entry, dict) else {}
                loaded_domains = self._load_profile_domains(
                    raw_domains,
                    legacy_activation_counts=legacy_activation_counts,
                )
                if loaded_domains:
                    loaded_profiles[profile_id] = {"domains": loaded_domains}
        elif isinstance(payload.get("domains"), dict):
            loaded_domains = self._load_profile_domains(
                payload.get("domains", {}),
                legacy_activation_counts=True,
            )
            if loaded_domains:
                loaded_profiles[DEFAULT_ROUTING_PROFILE_ID] = {"domains": loaded_domains}
        return {"version": 2, "profiles": loaded_profiles}

    def _save_state_locked(self):
        serialized = {"version": 2, "profiles": self._state.get("profiles", {})}
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        temporary_file = self.state_file.with_name(f"{self.state_file.name}.tmp")
        temporary_file.write_text(json.dumps(serialized, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary_file.replace(self.state_file)

    def _required_failures_locked(self, state) -> int:
        if int(state.get("activation_count", 0)) > 0:
            return AUTO_PROXY_REPEAT_FAILURE_THRESHOLD
        return DEFAULT_AUTO_PROXY_FAILURE_THRESHOLD

    def _clear_active_activation_locked(self, state, *, completed: bool):
        if completed:
            state["activation_count"] = int(state.get("activation_count", 0)) + 1
        state["active_until"] = None
        state["failure_count"] = 0
        state["probe_pending"] = False
        state["probe_in_flight"] = False

    def _complete_activation_if_due_locked(self, state, now: datetime) -> bool:
        active_until = parse_datetime_text(state.get("active_until"))
        if active_until is None or active_until > now:
            return False
        self._clear_active_activation_locked(state, completed=True)
        return True

    def _target_has_auto_proxy_rule(self, profile_id: str, pattern: str) -> bool:
        target_profile = self.router_config.routing_target_snapshot(profile_id=profile_id)
        if target_profile is None:
            return False
        for rule in target_profile.get("rules", []):
            if rule.get("enabled", True) and is_auto_proxy_rule(rule, pattern):
                return True
        return False

    def _prepare_activation_locked(
        self,
        profile_id: str,
        pattern: str,
        host: str | None,
        state,
        now: datetime,
        proxy_id: str | None = None,
    ):
        self._complete_activation_if_due_locked(state, now)
        stage_index = auto_proxy_stage_index_for_activation_count(int(state.get("activation_count", 0)))
        duration = AUTO_PROXY_STAGE_DURATIONS[stage_index]
        expires_at = now + duration
        state["active_until"] = expires_at.isoformat()
        state["failure_count"] = 0
        state["probe_pending"] = False
        state["probe_in_flight"] = False
        state["manual_review"] = False
        state["review_failure"] = None
        state["last_activated_at"] = now.isoformat()
        return {
            "profile_id": profile_id,
            "pattern": pattern,
            "host": host,
            "stage_index": stage_index,
            "duration_seconds": int(duration.total_seconds()),
            "expires_at": expires_at,
            "proxy_id": normalize_upstream_proxy_id(proxy_id),
        }

    def _reconcile_state(self):
        now = datetime.now().astimezone()
        active_patterns = []
        expired_patterns = []

        with self._lock:
            dirty = False
            for profile_id, profile_entry in self._state.get("profiles", {}).items():
                for pattern, state in profile_entry.get("domains", {}).items():
                    if state.get("probe_in_flight"):
                        state["probe_in_flight"] = False
                        state["probe_pending"] = True
                        dirty = True
                    active_until = parse_datetime_text(state.get("active_until"))
                    if active_until is None:
                        continue
                    if active_until > now and not self._target_has_auto_proxy_rule(profile_id, pattern):
                        self._clear_active_activation_locked(state, completed=False)
                        dirty = True
                        continue
                    if active_until <= now:
                        self._clear_active_activation_locked(state, completed=True)
                        expired_patterns.append((profile_id, pattern))
                        dirty = True
                    else:
                        stage_index = auto_proxy_stage_index_for_activation_count(int(state.get("activation_count", 0)))
                        active_patterns.append(
                            {
                                "profile_id": profile_id,
                                "pattern": pattern,
                                "stage_index": stage_index,
                                "duration_seconds": int(AUTO_PROXY_STAGE_DURATIONS[stage_index].total_seconds()),
                                "expires_at": active_until,
                            }
                        )
            if dirty:
                self._save_state_locked()

        for profile_id, pattern in expired_patterns:
            self._expire_rule(profile_id, pattern, state_already_cleared=True)

        for entry in active_patterns:
            self._ensure_rule_active(entry)

    def _ensure_rule_active(self, entry):
        host = entry["pattern"]
        try:
            self.router_config.add_auto_proxy_rule(
                host,
                duration_seconds=entry["duration_seconds"],
                stage_index=entry["stage_index"],
                expires_at=entry["expires_at"],
                profile_id=entry["profile_id"],
                proxy_id=entry.get("proxy_id"),
            )
        except Exception as exc:
            debug_exception(
                "system",
                f"failed to reconcile auto-proxy rule for {entry['pattern']}",
                exc,
            )

    def _run(self):
        while not self._stop_event.is_set():
            due_patterns = []
            wait_time = None
            now = datetime.now().astimezone()
            with self._lock:
                soonest = None
                for profile_id, profile_entry in self._state.get("profiles", {}).items():
                    for pattern, state in profile_entry.get("domains", {}).items():
                        active_until = parse_datetime_text(state.get("active_until"))
                        if active_until is None:
                            continue
                        if active_until <= now:
                            due_patterns.append((profile_id, pattern))
                        elif soonest is None or active_until < soonest:
                            soonest = active_until

                if not due_patterns and soonest is not None:
                    wait_time = max(0.5, (soonest - now).total_seconds())

            if due_patterns:
                for profile_id, pattern in due_patterns:
                    self._expire_rule(profile_id, pattern)
                continue

            self._wake_event.wait(timeout=wait_time)
            self._wake_event.clear()

    def _activate_rule(self, activation):
        result = None
        try:
            result = self.router_config.add_auto_proxy_rule(
                activation["host"],
                duration_seconds=activation["duration_seconds"],
                stage_index=activation["stage_index"],
                expires_at=activation["expires_at"],
                profile_id=activation["profile_id"],
                proxy_id=activation.get("proxy_id"),
            )
        except Exception as exc:
            debug_exception(
                "system",
                f"failed to activate auto-proxy rule for {activation['pattern']}",
                exc,
            )
            result = {"status": "error", "reason": repr(exc)}

        if result is not None and result.get("status") in {"added", "updated"}:
            log_event(
                "system",
                "auto-proxy enabled for "
                f"{activation['pattern']} for {format_auto_proxy_duration(activation['duration_seconds'])}",
            )
            return

        with self._lock:
            state = self._profile_domains_locked(activation["profile_id"]).get(activation["pattern"])
            if state is None:
                return
            state["active_until"] = None
            state["failure_count"] = 0
            state["probe_pending"] = False
            state["probe_in_flight"] = False
            self._save_state_locked()
        if result is not None and result.get("status") == "skipped":
            debug_log(
                "system",
                f"auto-proxy skipped for {activation['pattern']}: {result.get('reason', 'unknown')}",
                level="INFO",
            )

    def _expire_rule(self, profile_id: str, pattern: str, *, state_already_cleared: bool = False):
        result = None
        try:
            result = self.router_config.remove_auto_proxy_rule(pattern, profile_id=profile_id)
        except Exception as exc:
            debug_exception(
                "system",
                f"failed to expire auto-proxy rule for {pattern}",
                exc,
            )
            result = {"status": "error", "reason": repr(exc)}

        with self._lock:
            state = self._profile_domains_locked(profile_id).get(pattern)
            if state is not None and not state_already_cleared:
                now = datetime.now().astimezone()
                if self._complete_activation_if_due_locked(state, now):
                    self._save_state_locked()

        if result is not None and result.get("status") == "removed":
            log_event("system", f"auto-proxy expired for {pattern}; routing returned to direct")

    def _clear_review_state_locked(self, pattern: str, state) -> bool:
        had_state = bool(
            state.get("failure_count")
            or state.get("probe_pending")
            or state.get("probe_in_flight")
            or state.get("manual_review")
            or state.get("review_failure")
        )
        state["failure_count"] = 0
        state["probe_pending"] = False
        state["probe_in_flight"] = False
        state["manual_review"] = False
        state["review_failure"] = None
        return had_state

    def _load_profile_domains(self, raw_domains, *, legacy_activation_counts: bool = False):
        loaded = {}
        if not isinstance(raw_domains, dict):
            return loaded
        for raw_pattern, raw_state in raw_domains.items():
            pattern = normalize_rule_pattern(str(raw_pattern))
            if not pattern or not isinstance(raw_state, dict):
                continue
            try:
                activation_count = max(0, int(raw_state.get("activation_count", 0)))
                failure_count = max(0, int(raw_state.get("failure_count", 0)))
            except (TypeError, ValueError):
                continue
            active_until_text = str(raw_state.get("active_until") or "").strip() or None
            if legacy_activation_counts and active_until_text and activation_count > 0:
                activation_count = max(0, activation_count - 1)
            loaded[pattern] = {
                "activation_count": activation_count,
                "active_until": active_until_text,
                "failure_count": failure_count,
                "probe_pending": bool(raw_state.get("probe_pending", False)),
                "probe_in_flight": False,
                "manual_review": bool(raw_state.get("manual_review", False)),
                "last_activated_at": str(raw_state.get("last_activated_at") or "").strip() or None,
                "last_failure_at": str(raw_state.get("last_failure_at") or "").strip() or None,
                "last_success_at": str(raw_state.get("last_success_at") or "").strip() or None,
                "review_failure": raw_state.get("review_failure") if isinstance(raw_state.get("review_failure"), dict) else None,
            }
        return loaded

    def _profile_domains_locked(self, profile_id: str | None = None, *, create: bool = False):
        normalized_profile_id = str(profile_id or DEFAULT_ROUTING_PROFILE_ID).strip() or DEFAULT_ROUTING_PROFILE_ID
        profiles = self._state.setdefault("profiles", {})
        profile_entry = profiles.get(normalized_profile_id)
        if profile_entry is None:
            if not create:
                return {}
            profile_entry = {"domains": {}}
            profiles[normalized_profile_id] = profile_entry
        return profile_entry.setdefault("domains", {})

    def _resolved_profile_id(self, profile_id: str | None = None) -> str:
        if profile_id:
            normalized_profile_id = str(profile_id).strip()
            if normalized_profile_id:
                return normalized_profile_id
        runtime = self.router_config.runtime_snapshot()
        active_profile = runtime.get("active_profile") or {}
        return str(active_profile.get("id") or DEFAULT_ROUTING_PROFILE_ID)

    def reconcile_config_state(self):
        now = datetime.now().astimezone()
        with self._lock:
            dirty = False
            for profile_id, profile_entry in self._state.get("profiles", {}).items():
                for pattern, state in profile_entry.get("domains", {}).items():
                    active_until = parse_datetime_text(state.get("active_until"))
                    if active_until is None or active_until <= now:
                        continue
                    if self._target_has_auto_proxy_rule(profile_id, pattern):
                        continue
                    self._clear_active_activation_locked(state, completed=False)
                    dirty = True
            if dirty:
                self._save_state_locked()


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = []
    remaining = size
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise OSError("connection closed while reading from socket")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _create_http_proxy_tunnel(proxy_host: str, proxy_port: int, target_host: str, target_port: int, timeout: int):
    sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    sock.settimeout(timeout)
    try:
        authority = f"{target_host}:{int(target_port)}"
        request = (
            f"CONNECT {authority} HTTP/1.1\r\n"
            f"Host: {authority}\r\n"
            "Proxy-Connection: close\r\n"
            "\r\n"
        ).encode("ascii", errors="replace")
        sock.sendall(request)
        response = bytearray()
        while b"\r\n\r\n" not in response and len(response) < 65536:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response.extend(chunk)
        head = bytes(response).split(b"\r\n\r\n", 1)[0]
        status_line = head.splitlines()[0].decode("iso-8859-1", errors="replace") if head else ""
        parts = status_line.split(" ", 2)
        status_code = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
        if status_code != 200:
            raise OSError(f"HTTP upstream CONNECT failed with status {status_code or 'unknown'}")
        return sock
    except Exception:
        sock.close()
        raise


def _create_socks5_proxy_tunnel(proxy_host: str, proxy_port: int, target_host: str, target_port: int, timeout: int):
    sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    sock.settimeout(timeout)
    try:
        sock.sendall(bytes([SOCKS_VERSION, 0x01, 0x00]))
        method_reply = _recv_exact(sock, 2)
        if method_reply[0] != SOCKS_VERSION or method_reply[1] != 0x00:
            raise OSError("SOCKS5 upstream rejected no-auth handshake")

        address_bytes = target_host.encode("idna")
        if len(address_bytes) > 255:
            raise ValueError("destination host is too long for SOCKS5")
        request = bytearray([SOCKS_VERSION, SOCKS_CMD_CONNECT, 0x00, SOCKS_ATYP_DOMAIN, len(address_bytes)])
        request.extend(address_bytes)
        request.extend(int(target_port).to_bytes(2, "big"))
        sock.sendall(request)

        header = _recv_exact(sock, 4)
        if header[0] != SOCKS_VERSION:
            raise OSError("invalid SOCKS5 upstream reply")
        if header[1] != 0x00:
            raise OSError(f"SOCKS5 upstream connect failed with reply code 0x{header[1]:02x}")
        atyp = header[3]
        if atyp == SOCKS_ATYP_IPV4:
            _recv_exact(sock, 4)
        elif atyp == SOCKS_ATYP_IPV6:
            _recv_exact(sock, 16)
        elif atyp == SOCKS_ATYP_DOMAIN:
            length = _recv_exact(sock, 1)[0]
            _recv_exact(sock, length)
        else:
            raise OSError("invalid SOCKS5 upstream address type")
        _recv_exact(sock, 2)
        return sock
    except Exception:
        sock.close()
        raise


class HttpsDiscoveryManager:
    def __init__(
        self,
        router_config: RouterConfigManager,
        auto_proxy_failure_manager: AutoProxyFailureManager | None,
        *,
        timeout_seconds: int = HTTPS_DISCOVERY_PROBE_TIMEOUT_SECONDS,
        notify_callback=None,
    ):
        self.router_config = router_config
        self.auto_proxy_failure_manager = auto_proxy_failure_manager
        self.state_file = https_discovery_state_file_path(router_config.config_file)
        self.timeout_seconds = int(timeout_seconds)
        self._notify_callback = notify_callback
        self._lock = threading.Lock()
        self._state = self._load_state()
        self._stop_event = threading.Event()

    def observe_connect(self, host: str | None, port: int | None, route_decision):
        plan = self._prepare_probe(host, port, route_decision)
        if plan is None:
            return None
        thread = threading.Thread(
            target=self._run_probe,
            args=(plan,),
            name=f"https-discovery-{plan['pattern']}",
            daemon=True,
        )
        thread.start()
        self._notify()
        return {"status": "scheduled", "pattern": plan["pattern"], "profile_id": plan["profile_id"]}

    def probe_now(self, host: str | None, port: int | None, route_decision):
        plan = self._prepare_probe(host, port, route_decision)
        if plan is None:
            return None
        return self._run_probe(plan)

    def snapshot(self):
        now = datetime.now().astimezone()
        with self._lock:
            dirty = self._prune_in_flight_locked()
            total_domains = 0
            in_flight = 0
            proxy_recommended = 0
            manual_review = 0
            recent = []
            for profile_id, profile in sorted(self._state.get("profiles", {}).items()):
                for pattern, state in sorted((profile.get("domains") or {}).items()):
                    total_domains += 1
                    if state.get("probe_in_flight"):
                        in_flight += 1
                    if state.get("status") == "proxy-recommended":
                        proxy_recommended += 1
                    if state.get("status") == "manual-review":
                        manual_review += 1
                    recent.append(
                        {
                            "profile_id": profile_id,
                            "pattern": pattern,
                            "host": str(state.get("host") or ""),
                            "status": str(state.get("status") or "seen"),
                            "last_seen_at": state.get("last_seen_at"),
                            "last_probe_at": state.get("last_probe_at"),
                            "direct_tls": state.get("direct_tls") if isinstance(state.get("direct_tls"), dict) else None,
                            "proxy_tls": state.get("proxy_tls") if isinstance(state.get("proxy_tls"), dict) else None,
                        }
                    )
            recent.sort(key=lambda item: str(item.get("last_probe_at") or item.get("last_seen_at") or ""), reverse=True)
            if dirty:
                self._save_state_locked()
            return {
                "state_file": str(self.state_file),
                "probe_cooldown_seconds": int(HTTPS_DISCOVERY_PROBE_COOLDOWN.total_seconds()),
                "probe_timeout_seconds": self.timeout_seconds,
                "total_domains": total_domains,
                "in_flight": in_flight,
                "proxy_recommended": proxy_recommended,
                "manual_review": manual_review,
                "recent": recent[:20],
                "generated_at": now.isoformat(timespec="milliseconds"),
            }

    def clear_observations(self):
        with self._lock:
            self._state = {"version": 1, "profiles": {}}
            self._save_state_locked()

    def shutdown(self):
        self._stop_event.set()

    def _prepare_probe(self, host: str | None, port: int | None, route_decision):
        if self._stop_event.is_set() or route_decision is None:
            return None
        try:
            normalized_port = int(port)
        except (TypeError, ValueError):
            return None
        if normalized_port != 443:
            return None
        normalized_host = normalize_host(host or "")
        pattern = summarize_domain(normalized_host) or normalized_host
        if not normalized_host or not pattern or is_ip_address_text(pattern):
            return None
        if route_decision.get("action") != "direct" or route_decision.get("matched_rule") is not None:
            return None
        if route_decision.get("auto_proxy_probe"):
            return None
        upstream = route_decision.get("upstream")
        if not isinstance(upstream, dict):
            return None

        profile_id = str(route_decision.get("profile_id") or DEFAULT_ROUTING_PROFILE_ID)
        evaluation = self.router_config.auto_proxy_evaluation(normalized_host, profile_id=profile_id)
        if not evaluation.get("eligible"):
            return None
        resolved_profile_id = str(evaluation.get("profile_id") or profile_id)

        now = datetime.now().astimezone()
        with self._lock:
            self._prune_in_flight_locked()
            domains = self._profile_domains_locked(resolved_profile_id, create=True)
            state = domains.setdefault(pattern, self._default_state(normalized_host))
            state["host"] = normalized_host
            state["last_seen_at"] = now.isoformat(timespec="milliseconds")
            last_probe_at = parse_datetime_text(state.get("last_probe_at"))
            if state.get("probe_in_flight"):
                self._save_state_locked()
                return None
            if last_probe_at is not None and now - last_probe_at < HTTPS_DISCOVERY_PROBE_COOLDOWN:
                self._save_state_locked()
                return None
            state["probe_in_flight"] = True
            state["probe_started_at"] = now.isoformat(timespec="milliseconds")
            state["status"] = "probing"
            self._save_state_locked()

        return {
            "host": normalized_host,
            "port": normalized_port,
            "pattern": pattern,
            "profile_id": resolved_profile_id,
            "upstream": json.loads(json.dumps(upstream)),
        }

    def _run_probe(self, plan):
        if self._stop_event.is_set():
            return None
        direct_result = self._probe_tls_direct(plan["host"], plan["port"])
        proxy_result = None
        status = "direct-ok" if direct_result["ok"] else "direct-failed"
        if not direct_result["ok"] and not self._stop_event.is_set():
            proxy_result = self._probe_tls_via_upstream(plan["host"], plan["port"], plan["upstream"])
            status = "proxy-recommended" if proxy_result["ok"] else "manual-review"

        now = datetime.now().astimezone()
        with self._lock:
            state = self._profile_domains_locked(plan["profile_id"], create=True).setdefault(
                plan["pattern"],
                self._default_state(plan["host"]),
            )
            state["host"] = plan["host"]
            state["status"] = status
            state["probe_in_flight"] = False
            state["probe_started_at"] = None
            state["last_probe_at"] = now.isoformat(timespec="milliseconds")
            state["direct_tls"] = direct_result
            state["proxy_tls"] = proxy_result
            self._save_state_locked()

        if status == "proxy-recommended":
            self._activate_auto_proxy(plan)
        elif status == "manual-review":
            self._record_manual_review(plan, direct_result, proxy_result)
        self._notify()
        return {"status": status, "direct_tls": direct_result, "proxy_tls": proxy_result}

    def _activate_auto_proxy(self, plan):
        if self.auto_proxy_failure_manager is None:
            return
        self.auto_proxy_failure_manager.record_success(
            plan["host"],
            route_label=build_auto_proxy_probe_route_label(plan["upstream"]),
            profile_id=plan["profile_id"],
            proxy_id=plan["upstream"].get("id"),
        )

    def _record_manual_review(self, plan, direct_result, proxy_result):
        if self.auto_proxy_failure_manager is None:
            return
        direct_error = direct_result.get("error") or "direct TLS failed"
        proxy_error = (proxy_result or {}).get("error") or "upstream TLS failed"
        self.auto_proxy_failure_manager.record_failure(
            plan["host"],
            route_label=build_auto_proxy_probe_route_label(plan["upstream"]),
            destination=f"https://{plan['host']}/",
            error=f"HTTPS discovery probe failed direct and through upstream. Direct: {direct_error}; upstream: {proxy_error}",
            context="https discovery tls probe",
            method="CONNECT",
            profile_id=plan["profile_id"],
        )

    def _probe_tls_direct(self, host: str, port: int):
        try:
            raw = socket.create_connection((host, int(port)), timeout=self.timeout_seconds)
            return self._wrap_tls_probe(raw, host)
        except Exception as exc:
            return {"ok": False, "error": self._describe_probe_error(exc)}

    def _probe_tls_via_upstream(self, host: str, port: int, upstream: dict):
        try:
            upstream_type = str(upstream.get("type") or "http").strip().lower()
            upstream_host = str(upstream.get("host") or "").strip()
            upstream_port = int(upstream.get("port") or 0)
            if upstream_type == "socks5":
                raw = _create_socks5_proxy_tunnel(upstream_host, upstream_port, host, int(port), self.timeout_seconds)
            else:
                raw = _create_http_proxy_tunnel(upstream_host, upstream_port, host, int(port), self.timeout_seconds)
            return self._wrap_tls_probe(raw, host)
        except Exception as exc:
            return {"ok": False, "error": self._describe_probe_error(exc)}

    def _wrap_tls_probe(self, raw_socket: socket.socket, host: str):
        try:
            with raw_socket:
                with ssl.create_default_context().wrap_socket(raw_socket, server_hostname=host):
                    return {"ok": True, "error": ""}
        except Exception as exc:
            return {"ok": False, "error": self._describe_probe_error(exc)}

    def _describe_probe_error(self, exc: Exception) -> str:
        if isinstance(exc, TimeoutError):
            return "TLS probe timed out."
        if isinstance(exc, socket.gaierror):
            return "TLS probe could not resolve host."
        if isinstance(exc, ssl.SSLError):
            return f"TLS handshake failed: {exc}"
        if isinstance(exc, OSError):
            return str(exc) or exc.__class__.__name__
        return str(exc) or exc.__class__.__name__

    def _notify(self):
        if self._notify_callback is None:
            return
        try:
            self._notify_callback("https-discovery")
        except Exception as exc:
            debug_exception("system", "failed to notify HTTPS discovery update", exc)

    def _default_state(self, host: str | None = None):
        return {
            "host": normalize_host(host or "") or None,
            "status": "seen",
            "last_seen_at": None,
            "last_probe_at": None,
            "probe_in_flight": False,
            "probe_started_at": None,
            "direct_tls": None,
            "proxy_tls": None,
        }

    def _load_state(self):
        try:
            payload = json.loads(self.state_file.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, json.JSONDecodeError):
            return {"version": 1, "profiles": {}}
        if not isinstance(payload, dict):
            return {"version": 1, "profiles": {}}
        loaded_profiles = {}
        raw_profiles = payload.get("profiles")
        if isinstance(raw_profiles, dict):
            for raw_profile_id, raw_profile in raw_profiles.items():
                profile_id = str(raw_profile_id or "").strip() or DEFAULT_ROUTING_PROFILE_ID
                raw_domains = raw_profile.get("domains", {}) if isinstance(raw_profile, dict) else {}
                loaded_domains = {}
                if isinstance(raw_domains, dict):
                    for raw_pattern, raw_state in raw_domains.items():
                        pattern = normalize_rule_pattern(str(raw_pattern or ""))
                        if not pattern or not isinstance(raw_state, dict):
                            continue
                        loaded_domains[pattern] = {
                            "host": normalize_host(str(raw_state.get("host") or "")) or None,
                            "status": str(raw_state.get("status") or "seen"),
                            "last_seen_at": str(raw_state.get("last_seen_at") or "").strip() or None,
                            "last_probe_at": str(raw_state.get("last_probe_at") or "").strip() or None,
                            "probe_in_flight": False,
                            "probe_started_at": None,
                            "direct_tls": raw_state.get("direct_tls") if isinstance(raw_state.get("direct_tls"), dict) else None,
                            "proxy_tls": raw_state.get("proxy_tls") if isinstance(raw_state.get("proxy_tls"), dict) else None,
                        }
                if loaded_domains:
                    loaded_profiles[profile_id] = {"domains": loaded_domains}
        return {"version": 1, "profiles": loaded_profiles}

    def _save_state_locked(self):
        serialized = {"version": 1, "profiles": self._state.get("profiles", {})}
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        temporary_file = self.state_file.with_name(f"{self.state_file.name}.tmp")
        temporary_file.write_text(json.dumps(serialized, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary_file.replace(self.state_file)

    def _profile_domains_locked(self, profile_id: str | None = None, *, create: bool = False):
        normalized_profile_id = str(profile_id or DEFAULT_ROUTING_PROFILE_ID).strip() or DEFAULT_ROUTING_PROFILE_ID
        profiles = self._state.setdefault("profiles", {})
        profile_entry = profiles.get(normalized_profile_id)
        if profile_entry is None:
            if not create:
                return {}
            profile_entry = {"domains": {}}
            profiles[normalized_profile_id] = profile_entry
        return profile_entry.setdefault("domains", {})

    def _prune_in_flight_locked(self) -> bool:
        now = datetime.now().astimezone()
        dirty = False
        for profile in self._state.get("profiles", {}).values():
            for state in (profile.get("domains") or {}).values():
                if not state.get("probe_in_flight"):
                    continue
                started_at = parse_datetime_text(state.get("probe_started_at"))
                if started_at is not None and now - started_at <= timedelta(seconds=max(30, self.timeout_seconds * 4)):
                    continue
                state["probe_in_flight"] = False
                state["probe_started_at"] = None
                if state.get("status") == "probing":
                    state["status"] = "seen"
                dirty = True
        return dirty


class HttpsInterceptionTrustManager:
    def __init__(self, state_file: Path | None):
        self.state_file = Path(state_file) if state_file is not None else None
        self._lock = threading.Lock()
        self._state = self._load_state()

    def current_bypass(self, client: str | None, host: str | None):
        client_key = self._client_key(client)
        pattern = self._pattern_for_host(host)
        now = datetime.now().astimezone()
        with self._lock:
            dirty = self._prune_locked(now)
            client_state = self._state.get("clients", {}).get(client_key)
            result = None
            if client_state is not None:
                untrusted_until = parse_datetime_text(client_state.get("untrusted_until"))
                if untrusted_until is not None and untrusted_until > now:
                    result = {
                        "scope": "client",
                        "client": client_key,
                        "host": normalize_host(host or "") or None,
                        "pattern": "*",
                        "expires_at": untrusted_until.isoformat(),
                        "reason": str(client_state.get("untrusted_reason") or "client has not trusted the CA yet"),
                    }
                elif pattern:
                    bypass = client_state.get("bypasses", {}).get(pattern)
                    if bypass is not None:
                        expires_at = parse_datetime_text(bypass.get("expires_at"))
                        if expires_at is not None and expires_at > now:
                            result = {
                                "scope": "host",
                                "client": client_key,
                                "host": str(bypass.get("host") or host or ""),
                                "pattern": pattern,
                                "expires_at": expires_at.isoformat(),
                                "reason": str(bypass.get("error") or "recent HTTPS interception trust failure"),
                            }
            if dirty:
                self._save_state_locked()
            return result

    def record_success(self, client: str | None, host: str | None, *, source: str = "intercept"):
        client_key = self._client_key(client)
        normalized_host = normalize_host(host or "")
        pattern = self._pattern_for_host(normalized_host)
        now = datetime.now().astimezone()
        with self._lock:
            client_state = self._client_state_locked(client_key)
            client_state["trusted_at"] = now.isoformat()
            client_state["untrusted_until"] = None
            client_state["untrusted_reason"] = None
            if source == "trust-check":
                client_state["bypasses"] = {}
            elif pattern:
                client_state.setdefault("bypasses", {}).pop(pattern, None)
            client_state["last_success"] = {
                "timestamp": now.isoformat(timespec="milliseconds"),
                "client": client_key,
                "host": normalized_host or None,
                "pattern": pattern,
                "source": str(source or "intercept"),
            }
            self._save_state_locked()

    def record_failure(
        self,
        client: str | None,
        host: str | None,
        *,
        error: str,
        context: str,
        source: str = "intercept",
    ):
        client_key = self._client_key(client)
        normalized_host = normalize_host(host or "")
        pattern = self._pattern_for_host(normalized_host)
        if not pattern:
            return

        now = datetime.now().astimezone()
        expires_at = now + HTTPS_INTERCEPTION_ADAPTIVE_BYPASS_DURATION
        reason = str(error or "HTTPS interception TLS trust failure")
        with self._lock:
            client_state = self._client_state_locked(client_key)
            client_state.setdefault("bypasses", {})[pattern] = {
                "host": normalized_host or None,
                "pattern": pattern,
                "created_at": now.isoformat(),
                "expires_at": expires_at.isoformat(),
                "error": reason,
                "context": str(context or "HTTPS interception TLS handshake"),
                "source": str(source or "intercept"),
            }
            active_bypass_count = self._active_bypass_count_locked(client_state, now)
            if source == "trust-check" or (
                not client_state.get("trusted_at")
                and active_bypass_count >= HTTPS_INTERCEPTION_CLIENT_BYPASS_FAILURE_THRESHOLD
            ):
                client_state["untrusted_until"] = expires_at.isoformat()
                client_state["untrusted_reason"] = reason
            client_state["last_failure"] = {
                "timestamp": now.isoformat(timespec="milliseconds"),
                "client": client_key,
                "host": normalized_host or None,
                "pattern": pattern,
                "source": str(source or "intercept"),
                "error": reason,
                "context": str(context or "HTTPS interception TLS handshake"),
                "expires_at": expires_at.isoformat(),
            }
            self._save_state_locked()

    def snapshot(self):
        now = datetime.now().astimezone()
        with self._lock:
            dirty = self._prune_locked(now)
            active_bypasses = []
            last_success = None
            last_failure = None
            for client, client_state in sorted(self._state.get("clients", {}).items()):
                untrusted_until = parse_datetime_text(client_state.get("untrusted_until"))
                if untrusted_until is not None and untrusted_until > now:
                    active_bypasses.append(
                        {
                            "scope": "client",
                            "client": client,
                            "host": None,
                            "pattern": "*",
                            "expires_at": untrusted_until.isoformat(),
                            "reason": str(client_state.get("untrusted_reason") or "client has not trusted the CA yet"),
                        }
                    )
                for pattern, bypass in sorted((client_state.get("bypasses") or {}).items()):
                    expires_at = parse_datetime_text(bypass.get("expires_at"))
                    if expires_at is None or expires_at <= now:
                        continue
                    active_bypass_entry = {
                        "scope": "host",
                        "client": client,
                        "host": str(bypass.get("host") or ""),
                        "pattern": pattern,
                        "expires_at": expires_at.isoformat(),
                        "reason": str(bypass.get("error") or "recent HTTPS interception trust failure"),
                    }
                    active_bypasses.append(active_bypass_entry)

                last_success = self._latest_activity(last_success, client_state.get("last_success"))
                last_failure = self._latest_activity(last_failure, client_state.get("last_failure"))

            active_bypasses.sort(key=lambda item: (item.get("expires_at") or "", item.get("client") or ""))
            if dirty:
                self._save_state_locked()
            return {
                "state_file": str(self.state_file) if self.state_file is not None else None,
                "adaptive_bypass_ttl_seconds": int(HTTPS_INTERCEPTION_ADAPTIVE_BYPASS_DURATION.total_seconds()),
                "adaptive_bypass_count": len(active_bypasses),
                "active_bypasses": active_bypasses[:20],
                "last_success": last_success,
                "last_failure": last_failure,
            }

    def clear_observations(self):
        with self._lock:
            self._state = {"version": 1, "clients": {}}
            self._save_state_locked()

    def _client_key(self, client: str | None) -> str:
        return str(client or "unknown").strip() or "unknown"

    def _pattern_for_host(self, host: str | None) -> str:
        normalized_host = normalize_host(host or "")
        if not normalized_host:
            return ""
        if is_ip_address_text(normalized_host):
            return normalized_host
        return summarize_domain(normalized_host) or normalized_host

    def _client_state_locked(self, client_key: str):
        clients = self._state.setdefault("clients", {})
        state = clients.get(client_key)
        if state is None:
            state = {
                "trusted_at": None,
                "untrusted_until": None,
                "untrusted_reason": None,
                "bypasses": {},
                "last_success": None,
                "last_failure": None,
            }
            clients[client_key] = state
        return state

    def _load_state(self):
        if self.state_file is None:
            return {"version": 1, "clients": {}}
        try:
            payload = json.loads(self.state_file.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, json.JSONDecodeError):
            return {"version": 1, "clients": {}}
        if not isinstance(payload, dict):
            return {"version": 1, "clients": {}}

        loaded_clients = {}
        raw_clients = payload.get("clients")
        if isinstance(raw_clients, dict):
            for raw_client, raw_state in raw_clients.items():
                client = self._client_key(raw_client)
                if not isinstance(raw_state, dict):
                    continue
                loaded_bypasses = {}
                raw_bypasses = raw_state.get("bypasses")
                if isinstance(raw_bypasses, dict):
                    for raw_pattern, raw_bypass in raw_bypasses.items():
                        pattern = normalize_rule_pattern(str(raw_pattern or ""))
                        if not pattern or not isinstance(raw_bypass, dict):
                            continue
                        loaded_bypasses[pattern] = {
                            "host": normalize_host(str(raw_bypass.get("host") or "")) or None,
                            "pattern": pattern,
                            "created_at": str(raw_bypass.get("created_at") or "").strip() or None,
                            "expires_at": str(raw_bypass.get("expires_at") or "").strip() or None,
                            "error": str(raw_bypass.get("error") or "").strip(),
                            "context": str(raw_bypass.get("context") or "").strip(),
                            "source": str(raw_bypass.get("source") or "intercept").strip() or "intercept",
                        }
                loaded_clients[client] = {
                    "trusted_at": str(raw_state.get("trusted_at") or "").strip() or None,
                    "untrusted_until": str(raw_state.get("untrusted_until") or "").strip() or None,
                    "untrusted_reason": str(raw_state.get("untrusted_reason") or "").strip() or None,
                    "bypasses": loaded_bypasses,
                    "last_success": raw_state.get("last_success") if isinstance(raw_state.get("last_success"), dict) else None,
                    "last_failure": raw_state.get("last_failure") if isinstance(raw_state.get("last_failure"), dict) else None,
                }
        return {"version": 1, "clients": loaded_clients}

    def _save_state_locked(self):
        if self.state_file is None:
            return
        serialized = {"version": 1, "clients": self._state.get("clients", {})}
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        temporary_file = self.state_file.with_name(f"{self.state_file.name}.tmp")
        temporary_file.write_text(json.dumps(serialized, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        temporary_file.replace(self.state_file)

    def _prune_locked(self, now: datetime) -> bool:
        dirty = False
        for client_state in self._state.get("clients", {}).values():
            untrusted_until = parse_datetime_text(client_state.get("untrusted_until"))
            if untrusted_until is not None and untrusted_until <= now:
                client_state["untrusted_until"] = None
                client_state["untrusted_reason"] = None
                dirty = True
            bypasses = client_state.get("bypasses")
            if not isinstance(bypasses, dict):
                client_state["bypasses"] = {}
                dirty = True
                continue
            for pattern, bypass in list(bypasses.items()):
                expires_at = parse_datetime_text(bypass.get("expires_at")) if isinstance(bypass, dict) else None
                if expires_at is None or expires_at <= now:
                    bypasses.pop(pattern, None)
                    dirty = True
        return dirty

    def _active_bypass_count_locked(self, client_state, now: datetime) -> int:
        count = 0
        for bypass in (client_state.get("bypasses") or {}).values():
            expires_at = parse_datetime_text(bypass.get("expires_at")) if isinstance(bypass, dict) else None
            if expires_at is not None and expires_at > now:
                count += 1
        return count

    def _latest_activity(self, current, candidate):
        if not isinstance(candidate, dict):
            return current
        if current is None:
            return json.loads(json.dumps(candidate))
        current_timestamp = parse_datetime_text(current.get("timestamp"))
        candidate_timestamp = parse_datetime_text(candidate.get("timestamp"))
        if candidate_timestamp is None:
            return current
        if current_timestamp is None or candidate_timestamp > current_timestamp:
            return json.loads(json.dumps(candidate))
        return current


class TrafficQuotaManager:
    def __init__(self):
        self._lock = threading.Lock()
        self._records_by_client = {}
        self._records_by_proxy = {}
        self._records_by_proxy_client = {}
        self._proxy_snapshot_cache = {}

    def clear(self):
        with self._lock:
            self._records_by_client = {}
            self._records_by_proxy = {}
            self._records_by_proxy_client = {}
            self._proxy_snapshot_cache = {}

    def load_from_log(self, log_file: Path | None):
        if log_file is None:
            return

        cutoff = datetime.now().astimezone() - CLIENT_TRAFFIC_MAX_WINDOW
        proxy_cutoff = datetime.now().astimezone() - PROXY_TRAFFIC_MAX_WINDOW
        loaded_records = {}
        loaded_proxy_records = {}
        loaded_proxy_client_records = {}

        try:
            with log_file.open("r", encoding="utf-8") as stream:
                for line in stream:
                    stripped = line.strip()
                    if not stripped:
                        continue
                    try:
                        record = json.loads(stripped)
                    except json.JSONDecodeError:
                        continue

                    client = str(record.get("client") or "").strip()
                    if not client:
                        continue

                    timestamp = parse_usage_timestamp(record.get("timestamp"))
                    if timestamp is None or timestamp < proxy_cutoff:
                        continue

                    total_bytes = int(
                        record.get(
                            "total_bytes",
                            int(record.get("uploaded_bytes", 0)) + int(record.get("downloaded_bytes", 0)),
                        )
                    )
                    if timestamp >= cutoff:
                        loaded_records.setdefault(client, deque()).append(
                            {
                                "timestamp": timestamp,
                                "total_bytes": total_bytes,
                            }
                        )
                    proxy_id = str(record.get("upstream_proxy_id") or "").strip()
                    if proxy_id and timestamp >= proxy_cutoff:
                        proxy_record = {
                            "timestamp": timestamp,
                            "total_bytes": total_bytes,
                        }
                        loaded_proxy_records.setdefault(proxy_id, deque()).append(proxy_record)
                        loaded_proxy_client_records.setdefault((proxy_id, client), deque()).append(proxy_record)
        except FileNotFoundError:
            return

        with self._lock:
            self._records_by_client = loaded_records
            self._records_by_proxy = loaded_proxy_records
            self._records_by_proxy_client = loaded_proxy_client_records
            self._proxy_snapshot_cache = {}

    def record_usage(
        self,
        *,
        client: str,
        total_bytes: int,
        timestamp: str | datetime | None = None,
        upstream_proxy_id: str | None = None,
    ):
        if not client:
            return

        if isinstance(timestamp, datetime):
            event_time = timestamp
        else:
            event_time = parse_usage_timestamp(timestamp) if timestamp is not None else None
        if event_time is None:
            event_time = datetime.now().astimezone()

        with self._lock:
            records = self._records_by_client.setdefault(client, deque())
            records.append(
                {
                    "timestamp": event_time,
                    "total_bytes": int(total_bytes),
                }
            )
            self._prune_locked(client, now=event_time)
            proxy_id = str(upstream_proxy_id or "").strip()
            if proxy_id:
                proxy_record = {
                    "timestamp": event_time,
                    "total_bytes": int(total_bytes),
                }
                proxy_records = self._records_by_proxy.setdefault(proxy_id, deque())
                proxy_records.append(proxy_record)
                proxy_client_records = self._records_by_proxy_client.setdefault((proxy_id, client), deque())
                proxy_client_records.append(proxy_record)
                self._prune_proxy_locked(proxy_id, now=event_time)
                self._prune_proxy_client_locked(proxy_id, client, now=event_time)

    def usage_for_client(self, client: str, now: datetime | None = None):
        current_time = now or datetime.now().astimezone()
        with self._lock:
            self._prune_locked(client, now=current_time)
            records = list(self._records_by_client.get(client, ()))

        usage = {}
        for window_key, window_config in CLIENT_TRAFFIC_WINDOW_CONFIG.items():
            cutoff = current_time - window_config["window"]
            total_bytes = sum(
                record["total_bytes"] for record in records if record["timestamp"] >= cutoff
            )
            usage[window_key] = {
                "window_seconds": int(window_config["window"].total_seconds()),
                "total_bytes": total_bytes,
            }
        return usage

    def evaluate_client(self, client: str, router_config: RouterConfigManager):
        matched_limit = router_config.find_client_traffic_limit(client)
        usage = self.usage_for_client(client)
        evaluation = {
            "client": client,
            "limit": matched_limit,
            "usage": usage,
            "allowed": True,
            "exempt": bool(matched_limit and matched_limit.get("exempt")),
            "exceeded_windows": [],
            "retry_after_seconds": None,
            "retry_after_at": None,
        }
        if matched_limit is None:
            return evaluation
        if matched_limit.get("exempt"):
            return evaluation

        retry_after_at = None
        with self._lock:
            self._prune_locked(client, now=datetime.now().astimezone())
            records = list(self._records_by_client.get(client, ()))

        for window_key, window_config in CLIENT_TRAFFIC_WINDOW_CONFIG.items():
            limit_bytes = matched_limit.get(
                "max_past_hour_bytes" if window_key == "1h" else "max_past_3h_bytes"
            )
            if limit_bytes is None:
                continue

            total_bytes = usage[window_key]["total_bytes"]
            if total_bytes < limit_bytes:
                continue

            blocked_until = self._estimate_unblock_at(
                records=records,
                now=datetime.now().astimezone(),
                window=window_config["window"],
                limit_bytes=limit_bytes,
            )
            evaluation["allowed"] = False
            evaluation["exceeded_windows"].append(
                {
                    "key": window_key,
                    "label": window_config["label"],
                    "used_bytes": total_bytes,
                    "limit_bytes": limit_bytes,
                    "limit_mb": matched_limit.get(window_config["config_field"]),
                    "retry_after_at": blocked_until.isoformat() if blocked_until is not None else None,
                }
            )
            if blocked_until is not None and (retry_after_at is None or blocked_until > retry_after_at):
                retry_after_at = blocked_until

        if retry_after_at is not None:
            retry_after_seconds = max(
                1,
                int((retry_after_at - datetime.now().astimezone()).total_seconds()),
            )
            evaluation["retry_after_seconds"] = retry_after_seconds
            evaluation["retry_after_at"] = retry_after_at.isoformat()

        return evaluation

    def snapshot_for_clients(self, clients, router_config: RouterConfigManager):
        snapshot = {}
        for client in clients:
            snapshot[client] = self.evaluate_client(client, router_config)
        return snapshot

    def usage_for_proxy(self, proxy_id: str, client: str | None = None, now: datetime | None = None):
        current_time = now or datetime.now().astimezone()
        normalized_proxy_id = str(proxy_id or "").strip()
        with self._lock:
            if client is None:
                self._prune_proxy_locked(normalized_proxy_id, now=current_time)
                records = list(self._records_by_proxy.get(normalized_proxy_id, ()))
            else:
                self._prune_proxy_client_locked(normalized_proxy_id, client, now=current_time)
                records = list(self._records_by_proxy_client.get((normalized_proxy_id, client), ()))

        usage = {}
        for window_key, window_config in PROXY_TRAFFIC_WINDOW_CONFIG.items():
            cutoff = current_time - window_config["window"]
            total_bytes = sum(
                record["total_bytes"] for record in records if record["timestamp"] >= cutoff
            )
            usage[window_key] = {
                "window_seconds": int(window_config["window"].total_seconds()),
                "total_bytes": total_bytes,
            }
        return usage

    def evaluate_proxy(self, proxy, *, client: str | None = None):
        proxy_id = str((proxy or {}).get("id") or "").strip()
        usage = self.usage_for_proxy(proxy_id)
        client_usage = self.usage_for_proxy(proxy_id, client) if client else {}
        return self._evaluate_proxy_from_usage(
            proxy,
            usage=usage,
            client=client,
            client_usage=client_usage,
        )

    def _evaluate_proxy_from_usage(self, proxy, *, usage, client: str | None = None, client_usage=None):
        proxy = proxy or {}
        proxy_id = str(proxy.get("id") or "").strip()
        evaluation = {
            "proxy_id": proxy_id,
            "client": client,
            "usage": usage,
            "client_usage": client_usage or {},
            "allowed": True,
            "exceeded_windows": [],
            "client_exceeded_windows": [],
        }
        self._apply_proxy_limit_evaluation(
            evaluation,
            proxy.get("traffic_limit") or {},
            usage,
            exceeded_key="exceeded_windows",
            client=None,
        )
        if client:
            self._apply_proxy_limit_evaluation(
                evaluation,
                proxy.get("per_client_traffic_limit") or {},
                client_usage,
                exceeded_key="client_exceeded_windows",
                client=client,
            )
        return evaluation

    def proxy_snapshot(self, proxies, clients):
        current_time = datetime.now().astimezone()
        normalized_clients = tuple(sorted({
            str(client or "").strip()
            for client in clients
            if str(client or "").strip()
        }))
        normalized_proxies = [
            proxy
            for proxy in (proxies or [])
            if str((proxy or {}).get("id") or "").strip()
        ]
        cache_key = self._proxy_snapshot_cache_key(
            normalized_proxies,
            normalized_clients,
            current_time,
        )
        with self._lock:
            cached_snapshot = self._proxy_snapshot_cache.get(cache_key)
            if cached_snapshot is not None:
                return json.loads(json.dumps(cached_snapshot))

            proxy_records = {}
            proxy_client_records = {}
            for proxy in normalized_proxies:
                proxy_id = str((proxy or {}).get("id") or "").strip()
                self._prune_proxy_locked(proxy_id, now=current_time)
                proxy_records[proxy_id] = list(self._records_by_proxy.get(proxy_id, ()))
                for client in normalized_clients:
                    self._prune_proxy_client_locked(proxy_id, client, now=current_time)
                    proxy_client_records[(proxy_id, client)] = list(
                        self._records_by_proxy_client.get((proxy_id, client), ())
                    )

        snapshot = {}
        for proxy in normalized_proxies:
            proxy_id = str((proxy or {}).get("id") or "").strip()
            usage = self._usage_from_records(proxy_records.get(proxy_id, ()), current_time)
            proxy_payload = self._evaluate_proxy_from_usage(proxy, usage=usage)
            proxy_payload["clients"] = {
                client: self._evaluate_proxy_from_usage(
                    proxy,
                    usage=usage,
                    client=client,
                    client_usage=self._usage_from_records(
                        proxy_client_records.get((proxy_id, client), ()),
                        current_time,
                    ),
                )
                for client in normalized_clients
            }
            snapshot[proxy_id] = proxy_payload

        with self._lock:
            if len(self._proxy_snapshot_cache) >= PROXY_QUOTA_SNAPSHOT_CACHE_MAX_SIZE:
                self._proxy_snapshot_cache.pop(next(iter(self._proxy_snapshot_cache)), None)
            self._proxy_snapshot_cache[cache_key] = json.loads(json.dumps(snapshot))
        return snapshot

    def _proxy_snapshot_cache_key(self, proxies, clients, current_time: datetime):
        bucket = int(current_time.timestamp() // PROXY_QUOTA_SNAPSHOT_CACHE_SECONDS)
        proxy_fingerprints = tuple(
            json.dumps(
                {
                    "id": str((proxy or {}).get("id") or "").strip(),
                    "enabled": bool((proxy or {}).get("enabled", True)),
                    "priority": int((proxy or {}).get("priority") or 0),
                    "traffic_limit": (proxy or {}).get("traffic_limit") or {},
                    "per_client_traffic_limit": (proxy or {}).get("per_client_traffic_limit") or {},
                },
                sort_keys=True,
            )
            for proxy in proxies
        )
        return (bucket, proxy_fingerprints, tuple(clients))

    def _usage_from_records(self, records, current_time: datetime):
        usage = {}
        totals = {window_key: 0 for window_key in PROXY_TRAFFIC_WINDOW_CONFIG}
        cutoffs = {
            window_key: current_time - window_config["window"]
            for window_key, window_config in PROXY_TRAFFIC_WINDOW_CONFIG.items()
        }
        for record in records:
            timestamp = record.get("timestamp")
            total_bytes = int(record.get("total_bytes") or 0)
            for window_key, cutoff in cutoffs.items():
                if timestamp >= cutoff:
                    totals[window_key] += total_bytes
        for window_key, window_config in PROXY_TRAFFIC_WINDOW_CONFIG.items():
            usage[window_key] = {
                "window_seconds": int(window_config["window"].total_seconds()),
                "total_bytes": totals[window_key],
            }
        return usage

    def proxy_allowed(self, proxy, *, client: str | None = None):
        return self.evaluate_proxy(proxy, client=client).get("allowed", True)

    def _apply_proxy_limit_evaluation(self, evaluation, limit, usage, *, exceeded_key: str, client: str | None):
        if not limit.get("enabled", False):
            return
        for window_key, window_config in PROXY_TRAFFIC_WINDOW_CONFIG.items():
            limit_mb = limit.get(window_config["config_field"])
            limit_bytes = traffic_limit_mb_to_bytes(limit_mb)
            if limit_bytes is None:
                continue
            total_bytes = int((usage.get(window_key) or {}).get("total_bytes", 0))
            if total_bytes < limit_bytes:
                continue
            evaluation["allowed"] = False
            evaluation[exceeded_key].append(
                {
                    "key": window_key,
                    "label": window_config["label"],
                    "used_bytes": total_bytes,
                    "limit_bytes": limit_bytes,
                    "limit_mb": limit_mb,
                    "client": client,
                }
            )

    def _prune_locked(self, client: str, *, now: datetime):
        cutoff = now - CLIENT_TRAFFIC_MAX_WINDOW
        records = self._records_by_client.get(client)
        if not records:
            return

        while records and records[0]["timestamp"] < cutoff:
            records.popleft()

        if not records:
            self._records_by_client.pop(client, None)

    def _prune_proxy_locked(self, proxy_id: str, *, now: datetime):
        cutoff = now - PROXY_TRAFFIC_MAX_WINDOW
        records = self._records_by_proxy.get(proxy_id)
        if not records:
            return
        while records and records[0]["timestamp"] < cutoff:
            records.popleft()
        if not records:
            self._records_by_proxy.pop(proxy_id, None)

    def _prune_proxy_client_locked(self, proxy_id: str, client: str, *, now: datetime):
        cutoff = now - PROXY_TRAFFIC_MAX_WINDOW
        records = self._records_by_proxy_client.get((proxy_id, client))
        if not records:
            return
        while records and records[0]["timestamp"] < cutoff:
            records.popleft()
        if not records:
            self._records_by_proxy_client.pop((proxy_id, client), None)

    def _estimate_unblock_at(self, *, records, now: datetime, window: timedelta, limit_bytes: int):
        cutoff = now - window
        in_window_records = [record for record in records if record["timestamp"] >= cutoff]
        total_bytes = sum(record["total_bytes"] for record in in_window_records)
        if total_bytes < limit_bytes:
            return None

        remaining_bytes = total_bytes
        for record in in_window_records:
            remaining_bytes -= record["total_bytes"]
            if remaining_bytes < limit_bytes:
                return record["timestamp"] + window

        if in_window_records:
            return in_window_records[-1]["timestamp"] + window
        return None
