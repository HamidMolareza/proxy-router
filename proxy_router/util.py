from __future__ import annotations

import ipaddress
import importlib
import io
import json
import hashlib
import hmac
import re
import secrets
import socket
import uuid
import zlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

try:
    from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
except ImportError:  # pragma: no cover - zoneinfo is available on supported Python versions
    ZoneInfo = None
    ZoneInfoNotFoundError = ValueError

from .constants import *
from .output import debug_log

def auto_proxy_stage_durations_seconds() -> list[int]:
    return [int(duration.total_seconds()) for duration in AUTO_PROXY_STAGE_DURATIONS]


def format_auto_proxy_duration(seconds: int) -> str:
    if seconds % 86400 == 0:
        days = seconds // 86400
        return f"{days}d"
    if seconds % 3600 == 0:
        hours = seconds // 3600
        return f"{hours}h"
    if seconds % 60 == 0:
        minutes = seconds // 60
        return f"{minutes}m"
    return f"{seconds}s"


def auto_proxy_schedule_label() -> str:
    return ", ".join(format_auto_proxy_duration(seconds) for seconds in auto_proxy_stage_durations_seconds())


def auto_proxy_stage_index_for_activation_count(activation_count: int) -> int:
    return max(0, min(int(activation_count), len(AUTO_PROXY_STAGE_DURATIONS) - 1))


def build_auto_proxy_rule_note(stage_index: int, duration_seconds: int, expires_at: datetime) -> str:
    stage_total = len(AUTO_PROXY_STAGE_DURATIONS)
    duration_label = format_auto_proxy_duration(duration_seconds)
    return (
        f"{AUTO_PROXY_RULE_NOTE_PREFIX} stage {stage_index + 1}/{stage_total} "
        f"for {duration_label} until {expires_at.isoformat()}"
    )


def is_auto_proxy_rule(rule, pattern: str | None = None) -> bool:
    if str(rule.get("action", "")).strip().lower() != "proxy":
        return False
    if str(rule.get("match", "")).strip().lower() != "suffix":
        return False
    source = normalize_rule_source(rule.get("source"), rule.get("note"))
    note = str(rule.get("note", "")).strip().lower()
    if source != "auto" and not note.startswith(AUTO_PROXY_RULE_NOTE_PREFIX):
        return False
    if pattern is None:
        return True
    return normalize_rule_pattern(str(rule.get("pattern", ""))) == normalize_rule_pattern(pattern)


def auto_proxy_state_file_path(config_file: Path) -> Path:
    return config_file.with_name(f"{config_file.stem}{AUTO_PROXY_STATE_FILE_SUFFIX}")


def rule_suggestions_state_file_path(config_file: Path) -> Path:
    return config_file.with_name(f"{config_file.stem}{RULE_SUGGESTIONS_STATE_FILE_SUFFIX}")


def https_interception_state_file_path(config_file: Path) -> Path:
    return config_file.with_name(f"{config_file.stem}{HTTPS_INTERCEPTION_STATE_FILE_SUFFIX}")


def https_discovery_state_file_path(config_file: Path) -> Path:
    return config_file.with_name(f"{config_file.stem}{HTTPS_DISCOVERY_STATE_FILE_SUFFIX}")


def parse_datetime_text(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=datetime.now().astimezone().tzinfo)
    return parsed


def normalize_rule_source(value: str | None, note: str | None = None) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in RULE_SOURCES:
        return normalized
    if str(note or "").strip().lower().startswith(AUTO_PROXY_RULE_NOTE_PREFIX):
        return "auto"
    return "manual"


def prioritize_router_rules(rules):
    manual_override_patterns = {
        normalize_rule_pattern(str(rule.get("pattern", "")))
        for rule in rules
        if rule.get("enabled", True)
        and normalize_rule_source(rule.get("source"), rule.get("note")) == "manual"
    }

    prioritized_rules = []
    auto_rules = []
    for rule in rules:
        pattern = normalize_rule_pattern(str(rule.get("pattern", "")))
        source = normalize_rule_source(rule.get("source"), rule.get("note"))
        if source == "auto":
            if pattern in manual_override_patterns:
                continue
            auto_rules.append(rule)
            continue
        prioritized_rules.append(rule)

    return prioritized_rules + auto_rules


def router_rule_identity(rule) -> tuple[str, str]:
    return (
        normalize_rule_pattern(str(rule.get("pattern", ""))),
        str(rule.get("match", "suffix")).strip().lower(),
    )


def suffix_patterns_overlap(left_pattern: str, right_pattern: str) -> bool:
    return (
        left_pattern == right_pattern
        or left_pattern.endswith(f".{right_pattern}")
        or right_pattern.endswith(f".{left_pattern}")
    )


def rule_patterns_overlap(left_rule, right_rule) -> bool:
    left_pattern, left_match = router_rule_identity(left_rule)
    right_pattern, right_match = router_rule_identity(right_rule)
    if not left_pattern or not right_pattern:
        return False

    if left_match == "exact" and right_match == "exact":
        return left_pattern == right_pattern
    if left_match == "exact" and right_match == "suffix":
        return left_pattern == right_pattern or left_pattern.endswith(f".{right_pattern}")
    if left_match == "suffix" and right_match == "exact":
        return right_pattern == left_pattern or right_pattern.endswith(f".{left_pattern}")
    if left_match == "suffix" and right_match == "suffix":
        return suffix_patterns_overlap(left_pattern, right_pattern)
    if left_match == "contains" and right_match == "contains":
        return True
    if left_match == "contains" and right_match == "exact":
        return left_pattern in right_pattern
    if left_match == "exact" and right_match == "contains":
        return right_pattern in left_pattern
    if left_match == "contains" and right_match == "suffix":
        return True
    if left_match == "suffix" and right_match == "contains":
        return True
    return False


def router_rule_issue_ref(entry) -> dict:
    rule = entry["rule"]
    return {
        "scope": entry["scope"],
        "scope_label": entry["scope_label"],
        "index": entry["index"],
        "pattern": str(rule.get("pattern", "")),
        "match": str(rule.get("match", "")),
        "action": str(rule.get("action", "")),
        "enabled": bool(rule.get("enabled", True)),
        "source": normalize_rule_source(rule.get("source"), rule.get("note")),
    }


def find_rule_issues_for_entries(entries, *, context_id: str, context_label: str) -> list[dict]:
    issues = []
    seen_identities = {}
    for entry in entries:
        identity = router_rule_identity(entry["rule"])
        if not identity[0]:
            continue
        existing = seen_identities.get(identity)
        if existing is not None:
            issues.append(
                {
                    "type": "duplicate",
                    "context_id": context_id,
                    "context_label": context_label,
                    "message": (
                        f"duplicate {identity[1]} rule for {identity[0]} "
                        f"in {context_label}"
                    ),
                    "left": router_rule_issue_ref(existing),
                    "right": router_rule_issue_ref(entry),
                }
            )
        else:
            seen_identities[identity] = entry

    for left_index, left_entry in enumerate(entries):
        left_rule = left_entry["rule"]
        if not left_rule.get("enabled", True):
            continue
        for right_entry in entries[left_index + 1:]:
            right_rule = right_entry["rule"]
            if not right_rule.get("enabled", True):
                continue
            if str(left_rule.get("action")) == str(right_rule.get("action")):
                continue
            if not rule_patterns_overlap(left_rule, right_rule):
                continue
            issues.append(
                {
                    "type": "conflict",
                    "context_id": context_id,
                    "context_label": context_label,
                    "message": (
                        f"conflicting actions for overlapping rules "
                        f"{left_rule.get('pattern')} and {right_rule.get('pattern')} "
                        f"in {context_label}"
                    ),
                    "left": router_rule_issue_ref(left_entry),
                    "right": router_rule_issue_ref(right_entry),
                }
            )
    return issues


def find_router_rule_issues(config) -> list[dict]:
    shared_entries = [
        {
            "scope": DEFAULT_ROUTING_PROFILE_ID,
            "scope_label": "Shared",
            "index": index,
            "rule": rule,
        }
        for index, rule in enumerate(config.get("rules", []))
    ]
    contexts = [
        {
            "id": DEFAULT_ROUTING_PROFILE_ID,
            "label": "Shared",
            "entries": shared_entries,
        }
    ]
    for profile in config.get("routing_profiles", []):
        if not profile.get("enabled", True):
            continue
        profile_id = str(profile.get("id") or "").strip()
        profile_label = str(profile.get("name") or profile_id or "Profile").strip()
        profile_entries = [
            {
                "scope": profile_id,
                "scope_label": profile_label,
                "index": index,
                "rule": rule,
            }
            for index, rule in enumerate(profile.get("rules", []))
        ]
        contexts.append(
            {
                "id": profile_id,
                "label": f"{profile_label} + Shared",
                "entries": [*profile_entries, *shared_entries],
            }
        )

    issues = []
    seen_issue_keys = set()
    for context in contexts:
        for issue in find_rule_issues_for_entries(
            context["entries"],
            context_id=context["id"],
            context_label=context["label"],
        ):
            key = (
                issue["type"],
                issue["context_id"],
                issue["left"]["scope"],
                issue["left"]["index"],
                issue["right"]["scope"],
                issue["right"]["index"],
            )
            if key in seen_issue_keys:
                continue
            seen_issue_keys.add(key)
            issues.append(issue)
    return issues


def validate_router_rule_issues(config) -> None:
    issues = find_router_rule_issues(config)
    if not issues:
        return
    issue_count = len(issues)
    issue_word = "issue" if issue_count == 1 else "issues"
    preview = "; ".join(issue["message"] for issue in issues[:3])
    if issue_count > 3:
        preview = f"{preview}; and {issue_count - 3} more"
    raise ValueError(f"router rules have {issue_count} blocking {issue_word}: {preview}")


def default_routing_fields():
    return {
        "default_action": "direct",
        "ignored_failure_hosts": [],
        "rules": [],
    }


def default_routing_profile_signature():
    return {
        "internet_key": "",
        "internet_label": "",
        "route_interface": "",
        "route_gateway": "",
        "vpn_keys": [],
        "vpn_labels": [],
    }


def routing_profile_identity(signature) -> dict:
    normalized_signature = default_routing_profile_signature()
    if isinstance(signature, dict):
        normalized_signature.update(
            {
                "internet_key": str(signature.get("internet_key") or "").strip(),
                "route_interface": str(signature.get("route_interface") or "").strip(),
                "route_gateway": str(signature.get("route_gateway") or "").strip(),
                "vpn_keys": sorted(
                    {
                        str(item).strip()
                        for item in (signature.get("vpn_keys") or [])
                        if str(item).strip()
                    }
                ),
            }
        )
    return {
        "internet_key": normalized_signature["internet_key"],
        "route_interface": normalized_signature["route_interface"],
        "route_gateway": normalized_signature["route_gateway"],
        "vpn_keys": normalized_signature["vpn_keys"],
    }


def routing_profile_identity_key(signature) -> str:
    return json.dumps(routing_profile_identity(signature), sort_keys=True, separators=(",", ":"))


def default_routing_profile_entry() -> dict:
    fields = default_routing_fields()
    return {
        "id": DEFAULT_ROUTING_PROFILE_ID,
        "name": "Default",
        "enabled": True,
        "signature": default_routing_profile_signature(),
        "default_action": fields["default_action"],
        "ignored_failure_hosts": list(fields["ignored_failure_hosts"]),
        "rules": list(fields["rules"]),
    }


def normalize_rule_duration(
    value: str | None,
    *,
    source: str,
    note: str | None = None,
) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in RULE_DURATION_SECONDS:
        return normalized
    parsed = parse_auto_proxy_rule_note(note)
    if parsed is not None:
        return parsed["duration"]
    if source == "auto":
        return "1h"
    return "always"


def duration_seconds_for_rule(duration: str) -> int | None:
    return RULE_DURATION_SECONDS.get(duration)


def parse_auto_proxy_rule_note(note: str | None):
    text = str(note or "").strip()
    if not text:
        return None
    match = AUTO_PROXY_NOTE_PATTERN.match(text)
    if match is None:
        return None
    duration = str(match.group(1)).strip().lower()
    expires_at = parse_datetime_text(match.group(2))
    if duration not in RULE_DURATION_SECONDS or expires_at is None:
        return None
    return {
        "duration": duration,
        "expires_at": expires_at,
    }


def normalize_rule_expiration(
    expires_at_value,
    *,
    duration: str,
    source: str,
    note: str | None = None,
    now: datetime | None = None,
) -> datetime | None:
    if duration == "always":
        return None
    parsed = parse_datetime_text(expires_at_value)
    if parsed is not None:
        return parsed
    parsed_note = parse_auto_proxy_rule_note(note)
    if parsed_note is not None:
        return parsed_note["expires_at"]
    duration_seconds = duration_seconds_for_rule(duration)
    if duration_seconds is None:
        return None
    base = now or datetime.now().astimezone()
    return base + timedelta(seconds=duration_seconds)


def is_rule_expired(rule, *, now: datetime | None = None) -> bool:
    expires_at = parse_datetime_text(rule.get("expires_at"))
    if expires_at is None:
        return False
    check_time = now or datetime.now().astimezone()
    return expires_at <= check_time


def rule_remaining_seconds(rule, *, now: datetime | None = None) -> int | None:
    expires_at = parse_datetime_text(rule.get("expires_at"))
    if expires_at is None:
        return None
    check_time = now or datetime.now().astimezone()
    return max(0, int((expires_at - check_time).total_seconds()))

def empty_usage_summary():
    return {
        "count": 0,
        "uploaded_bytes": 0,
        "downloaded_bytes": 0,
        "total_bytes": 0,
        "duration_sample_count": 0,
        "duration_sample_bytes": 0,
        "duration_ms_total": 0,
        "duration_ms_avg": None,
        "duration_ms_max": None,
        "upstream_setup_sample_count": 0,
        "upstream_setup_ms_total": 0,
        "upstream_setup_ms_avg": None,
        "upstream_setup_ms_max": None,
        "relay_sample_count": 0,
        "relay_ms_total": 0,
        "relay_ms_avg": None,
        "relay_ms_max": None,
        "throughput_bps": None,
    }


def optional_nonnegative_int(value) -> int | None:
    if value is None:
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed >= 0 else None


def calculate_throughput_bps(total_bytes: int, duration_ms: int | None) -> int | None:
    normalized_duration = optional_nonnegative_int(duration_ms)
    if normalized_duration is None or normalized_duration <= 0:
        return None
    return int(max(0, int(total_bytes or 0)) * 1000 / normalized_duration)


def apply_usage_performance_fields(
    event,
    *,
    total_bytes: int,
    duration_ms=None,
    upstream_setup_ms=None,
    relay_ms=None,
    upstream_retry_count=None,
    upstream_retry_delay_ms=None,
):
    normalized_duration = optional_nonnegative_int(duration_ms)
    if normalized_duration is not None:
        event["duration_ms"] = normalized_duration
        throughput_bps = calculate_throughput_bps(total_bytes, normalized_duration)
        if throughput_bps is not None:
            event["throughput_bps"] = throughput_bps
    normalized_upstream_setup = optional_nonnegative_int(upstream_setup_ms)
    if normalized_upstream_setup is not None:
        event["upstream_setup_ms"] = normalized_upstream_setup
    normalized_relay = optional_nonnegative_int(relay_ms)
    if normalized_relay is not None:
        event["relay_ms"] = normalized_relay
    normalized_retry_count = optional_nonnegative_int(upstream_retry_count)
    if normalized_retry_count is not None:
        event["upstream_retry_count"] = normalized_retry_count
    normalized_retry_delay = optional_nonnegative_int(upstream_retry_delay_ms)
    if normalized_retry_delay is not None:
        event["upstream_retry_delay_ms"] = normalized_retry_delay


def apply_failure_performance_fields(
    event,
    *,
    duration_ms=None,
    upstream_setup_ms=None,
    upstream_retry_count=None,
    upstream_retry_delay_ms=None,
):
    normalized_duration = optional_nonnegative_int(duration_ms)
    if normalized_duration is not None:
        event["duration_ms"] = normalized_duration
    normalized_upstream_setup = optional_nonnegative_int(upstream_setup_ms)
    if normalized_upstream_setup is not None:
        event["upstream_setup_ms"] = normalized_upstream_setup
    normalized_retry_count = optional_nonnegative_int(upstream_retry_count)
    if normalized_retry_count is not None:
        event["upstream_retry_count"] = normalized_retry_count
    normalized_retry_delay = optional_nonnegative_int(upstream_retry_delay_ms)
    if normalized_retry_delay is not None:
        event["upstream_retry_delay_ms"] = normalized_retry_delay


def _add_timing_sample(summary, prefix: str, value: int | None):
    sample = optional_nonnegative_int(value)
    if sample is None:
        return
    count_key = f"{prefix}_sample_count"
    total_key = f"{prefix}_ms_total"
    avg_key = f"{prefix}_ms_avg"
    max_key = f"{prefix}_ms_max"
    summary[count_key] = int(summary.get(count_key, 0)) + 1
    summary[total_key] = int(summary.get(total_key, 0)) + sample
    summary[avg_key] = int(summary[total_key] / summary[count_key])
    current_max = summary.get(max_key)
    summary[max_key] = sample if current_max is None else max(int(current_max), sample)


def add_performance_to_summary(
    summary,
    *,
    total_bytes: int,
    duration_ms=None,
    upstream_setup_ms=None,
    relay_ms=None,
):
    normalized_duration = optional_nonnegative_int(duration_ms)
    if normalized_duration is not None:
        _add_timing_sample(summary, "duration", normalized_duration)
        summary["duration_sample_bytes"] = int(summary.get("duration_sample_bytes", 0)) + max(0, int(total_bytes or 0))
        duration_total = int(summary.get("duration_ms_total", 0))
        if duration_total > 0:
            summary["throughput_bps"] = int(summary["duration_sample_bytes"] * 1000 / duration_total)
    _add_timing_sample(summary, "upstream_setup", upstream_setup_ms)
    _add_timing_sample(summary, "relay", relay_ms)


def merge_usage_summary(target, source):
    target["count"] += int(source.get("count", 0))
    target["uploaded_bytes"] += int(source.get("uploaded_bytes", 0))
    target["downloaded_bytes"] += int(source.get("downloaded_bytes", 0))
    target["total_bytes"] += int(source.get("total_bytes", 0))
    target["duration_sample_count"] += int(source.get("duration_sample_count", 0))
    target["duration_sample_bytes"] += int(source.get("duration_sample_bytes", 0))
    target["duration_ms_total"] += int(source.get("duration_ms_total", 0))
    if target["duration_sample_count"]:
        target["duration_ms_avg"] = int(target["duration_ms_total"] / target["duration_sample_count"])
    if target["duration_ms_total"] > 0:
        target["throughput_bps"] = int(target["duration_sample_bytes"] * 1000 / target["duration_ms_total"])

    for prefix in ("duration", "upstream_setup", "relay"):
        max_key = f"{prefix}_ms_max"
        source_max = source.get(max_key)
        if source_max is not None:
            target[max_key] = int(source_max) if target.get(max_key) is None else max(int(target[max_key]), int(source_max))
        if prefix == "duration":
            continue
        count_key = f"{prefix}_sample_count"
        total_key = f"{prefix}_ms_total"
        avg_key = f"{prefix}_ms_avg"
        target[count_key] += int(source.get(count_key, 0))
        target[total_key] += int(source.get(total_key, 0))
        if target[count_key]:
            target[avg_key] = int(target[total_key] / target[count_key])


def route_bucket_from_label(route_label: str | None) -> str:
    label = route_label or "direct"
    if label.startswith("proxy:"):
        return "proxy"
    if label.startswith("self:"):
        return "self"
    if label.startswith("reject:"):
        return "rejected"
    return "direct"


def summarize_route_totals(records):
    totals = {}
    for record in records:
        bucket = route_bucket_from_label(record.get("route_label"))
        summary = totals.setdefault(bucket, empty_usage_summary())
        uploaded_bytes = int(record.get("uploaded_bytes", 0))
        downloaded_bytes = int(record.get("downloaded_bytes", 0))
        add_usage_to_summary(
            summary,
            uploaded_bytes=uploaded_bytes,
            downloaded_bytes=downloaded_bytes,
            total_bytes=int(record.get("total_bytes", uploaded_bytes + downloaded_bytes)),
            duration_ms=record.get("duration_ms"),
            upstream_setup_ms=record.get("upstream_setup_ms"),
            relay_ms=record.get("relay_ms"),
        )
    return totals


def empty_client_usage_summary():
    return {
        **empty_usage_summary(),
        "proxy_types": set(),
        "last_seen_at": None,
    }


def normalize_host(value: str) -> str:
    return value.strip().rstrip(".").lower()


def normalize_rule_pattern(value: str) -> str:
    pattern = normalize_host(value)
    if pattern.startswith("*."):
        pattern = pattern[2:]
    pattern = pattern.lstrip(".")
    return pattern


def normalize_host_pattern_list(value, *, field_name: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        raw_items = [value]
    elif isinstance(value, list):
        raw_items = value
    else:
        raise ValueError(f"{field_name} must be an array")

    patterns = []
    for item in raw_items:
        normalized = normalize_rule_pattern(str(item or ""))
        if normalized and normalized not in patterns:
            patterns.append(normalized)
    return patterns


def host_matches_suffix_pattern(host: str | None, pattern: str | None) -> bool:
    normalized_host = normalize_host(host or "")
    normalized_pattern = normalize_rule_pattern(pattern or "")
    if not normalized_host or not normalized_pattern:
        return False
    return normalized_host == normalized_pattern or normalized_host.endswith(f".{normalized_pattern}")


def host_matches_any_suffix_pattern(host: str | None, patterns) -> bool:
    return any(host_matches_suffix_pattern(host, pattern) for pattern in patterns or [])


def should_intercept_https_connect(settings, host: str | None, port: int | None) -> bool:
    if not settings or not settings.get("enabled", False):
        return False

    try:
        normalized_port = int(port)
    except (TypeError, ValueError):
        return False
    if normalized_port not in HTTPS_INTERCEPTION_DEFAULT_PORTS:
        return False

    if host_matches_any_suffix_pattern(host, settings.get("bypass_patterns")):
        return False

    mode = str(settings.get("mode") or "allowlist").strip().lower()
    if mode == "all":
        return True
    return host_matches_any_suffix_pattern(host, settings.get("host_patterns"))


def normalize_client_auth_username(value: str) -> str:
    username = str(value or "").strip()
    if username.startswith("user:"):
        username = username[5:].strip()
    if not username:
        return ""
    if not CLIENT_AUTH_USERNAME_PATTERN.fullmatch(username):
        raise ValueError(
            "client auth username must be 1-80 characters and contain only letters, numbers, dot, underscore, at, plus, or hyphen"
        )
    return username


def client_identity_from_username(username: str) -> str:
    normalized_username = normalize_client_auth_username(username)
    return f"user:{normalized_username}" if normalized_username else ""


def hash_client_auth_password(password: str) -> str:
    salt = secrets.token_bytes(CLIENT_AUTH_PBKDF2_SALT_BYTES)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        str(password or "").encode("utf-8"),
        salt,
        CLIENT_AUTH_PBKDF2_ITERATIONS,
    )
    return (
        "pbkdf2_sha256:"
        f"{CLIENT_AUTH_PBKDF2_ITERATIONS}:"
        f"{salt.hex()}:"
        f"{digest.hex()}"
    )


def normalize_client_auth_password_hash(value: str | None) -> str:
    password_hash = str(value or "").strip()
    if not password_hash:
        return ""
    if password_hash.startswith("pbkdf2_sha256:"):
        parts = password_hash.split(":")
        if len(parts) != 4:
            raise ValueError("client auth password_hash must be a valid pbkdf2_sha256 hash")
        _, iterations_text, salt_hex, digest_hex = parts
        try:
            iterations = int(iterations_text)
        except ValueError as exc:
            raise ValueError("client auth password_hash iterations must be an integer") from exc
        if iterations <= 0:
            raise ValueError("client auth password_hash iterations must be positive")
        salt_hex = salt_hex.lower()
        digest_hex = digest_hex.lower()
        if (
            len(salt_hex) < 16
            or len(salt_hex) % 2
            or any(character not in "0123456789abcdef" for character in salt_hex)
            or len(digest_hex) != 64
            or any(character not in "0123456789abcdef" for character in digest_hex)
        ):
            raise ValueError("client auth password_hash must be a valid pbkdf2_sha256 hash")
        return f"pbkdf2_sha256:{iterations}:{salt_hex}:{digest_hex}"
    if password_hash.startswith("sha256:"):
        digest = password_hash.split(":", 1)[1].lower()
    else:
        digest = password_hash.lower()
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise ValueError("client auth password_hash must be a sha256 hex digest")
    return f"sha256:{digest}"


def verify_client_auth_password(password: str, password_hash: str | None) -> bool:
    expected_hash = normalize_client_auth_password_hash(password_hash)
    if not expected_hash:
        return False
    if expected_hash.startswith("pbkdf2_sha256:"):
        _, iterations_text, salt_hex, digest_hex = expected_hash.split(":")
        computed_digest = hashlib.pbkdf2_hmac(
            "sha256",
            str(password or "").encode("utf-8"),
            bytes.fromhex(salt_hex),
            int(iterations_text),
        ).hex()
        return hmac.compare_digest(computed_digest, digest_hex)
    legacy_digest = "sha256:" + hashlib.sha256(str(password or "").encode("utf-8")).hexdigest()
    return hmac.compare_digest(legacy_digest, expected_hash)


def authenticate_client_auth_credentials(settings, username: str | None, password: str | None):
    normalized_username = normalize_client_auth_username(username or "")
    if not normalized_username:
        return None
    for credential in (settings or {}).get("credentials") or []:
        if not credential.get("enabled", True):
            continue
        if str(credential.get("username") or "") != normalized_username:
            continue
        if verify_client_auth_password(str(password or ""), credential.get("password_hash")):
            return {
                "username": normalized_username,
                "id": client_identity_from_username(normalized_username),
                "label": str(credential.get("label") or "").strip(),
            }
        return None
    return None


def normalize_client_limit_target(value: str) -> str:
    target = str(value or "").strip()
    if not target:
        return ""

    if target.lower().startswith("user:"):
        return client_identity_from_username(target)

    try:
        return str(ipaddress.ip_address(target))
    except ValueError:
        pass

    try:
        return str(ipaddress.ip_network(target, strict=False))
    except ValueError:
        return client_identity_from_username(target)


def client_limit_target_specificity(target: str) -> int:
    if str(target).startswith("user:"):
        return 1000
    if "/" in target:
        return ipaddress.ip_network(target, strict=False).prefixlen
    return ipaddress.ip_address(target).max_prefixlen


def client_ip_matches_limit_target(client_ip: str, target: str) -> bool:
    if str(target).startswith("user:"):
        return str(client_ip or "") == str(target)

    try:
        client_address = ipaddress.ip_address(client_ip)
    except ValueError:
        return False

    if "/" in target:
        return client_address in ipaddress.ip_network(target, strict=False)

    return client_address == ipaddress.ip_address(target)


def normalize_traffic_limit_mb(value, *, field_name: str):
    if value is None:
        return None

    text = str(value).strip()
    if not text:
        return None

    try:
        limit_mb = int(text)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} must be an integer") from exc

    if limit_mb <= 0:
        raise ValueError(f"{field_name} must be greater than 0")

    return limit_mb


def traffic_limit_mb_to_bytes(limit_mb):
    if limit_mb is None:
        return None
    return int(limit_mb) * BYTES_IN_MB


def default_proxy_traffic_limit() -> dict:
    return {
        "enabled": False,
        "max_past_hour_mb": None,
        "max_past_3h_mb": None,
        "max_past_week_mb": None,
        "note": "",
    }


def normalize_upstream_proxy_id(value) -> str:
    normalized = str(value or "").strip().lower()
    normalized = re.sub(r"[^a-z0-9_.-]+", "-", normalized)
    normalized = normalized.strip(".-")
    return normalized[:80]


def normalize_proxy_access_mode(value) -> str:
    normalized = str(value or "public").strip().lower()
    return normalized if normalized in UPSTREAM_PROXY_ACCESS_MODES else "public"


def validate_proxy_traffic_limit_definition(*, enabled: bool, limit: dict, field_prefix: str):
    if not enabled:
        return
    if all(limit.get(field["config_field"]) is None for field in PROXY_TRAFFIC_WINDOW_CONFIG.values()):
        raise ValueError(
            f"{field_prefix} must set at least one of max_past_hour_mb, "
            "max_past_3h_mb, or max_past_week_mb when enabled"
        )


def normalize_proxy_traffic_limit(payload, *, field_prefix: str) -> dict:
    default_limit = default_proxy_traffic_limit()
    if payload is None:
        payload = {}
    if not isinstance(payload, dict):
        raise ValueError(f"{field_prefix} must be an object")
    normalized = {
        "enabled": bool(payload.get("enabled", default_limit["enabled"])),
        "max_past_hour_mb": normalize_traffic_limit_mb(
            payload.get("max_past_hour_mb", default_limit["max_past_hour_mb"]),
            field_name=f"{field_prefix} max_past_hour_mb",
        ),
        "max_past_3h_mb": normalize_traffic_limit_mb(
            payload.get("max_past_3h_mb", default_limit["max_past_3h_mb"]),
            field_name=f"{field_prefix} max_past_3h_mb",
        ),
        "max_past_week_mb": normalize_traffic_limit_mb(
            payload.get("max_past_week_mb", default_limit["max_past_week_mb"]),
            field_name=f"{field_prefix} max_past_week_mb",
        ),
        "note": str(payload.get("note", default_limit["note"])).strip(),
    }
    validate_proxy_traffic_limit_definition(
        enabled=normalized["enabled"],
        limit=normalized,
        field_prefix=field_prefix,
    )
    return normalized


def upstream_proxy_label(proxy) -> str:
    if not isinstance(proxy, dict):
        return ""
    return f"{proxy.get('type', 'http')}://{proxy.get('host', '')}:{proxy.get('port', '')}"


def proxy_allows_client(proxy, client_id: str | None = None, *, client_ip: str | None = None) -> bool:
    mode = normalize_proxy_access_mode((proxy or {}).get("access_mode"))
    if mode == "public":
        return True
    normalized_client = str(client_id or "").strip()
    if mode == "authenticated":
        return normalized_client.startswith("user:")
    client_candidates = []
    for candidate in (normalized_client, str(client_ip or "").strip()):
        if candidate and candidate not in client_candidates:
            client_candidates.append(candidate)
    for target in (proxy or {}).get("allowed_clients") or []:
        for candidate in client_candidates:
            if client_ip_matches_limit_target(candidate, target):
                return True
    return False


def normalize_upstream_proxy_entry(proxy_payload, *, index: int) -> dict | None:
    if not isinstance(proxy_payload, dict):
        raise ValueError(f"router proxies entry #{index} must be an object")

    proxy_type = str(proxy_payload.get("type", "http")).strip().lower()
    if proxy_type not in UPSTREAM_PROXY_TYPES:
        raise ValueError(f"router proxies entry #{index} type must be one of: {', '.join(sorted(UPSTREAM_PROXY_TYPES))}")

    host = str(proxy_payload.get("host", "")).strip()
    port_raw = proxy_payload.get("port", HTTPS_DEFAULT_PORT)
    try:
        port = int(port_raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"router proxies entry #{index} port must be an integer") from exc
    ensure_valid_port(port, f"router proxies entry #{index} port")

    proxy_id = normalize_upstream_proxy_id(proxy_payload.get("id"))
    if not proxy_id:
        proxy_id = normalize_upstream_proxy_id(proxy_payload.get("name")) or f"proxy-{index}"

    enabled = bool(proxy_payload.get("enabled", True))
    if enabled and not host:
        raise ValueError(f"router proxies entry #{index} host is required when enabled")

    allowed_clients_payload = proxy_payload.get("allowed_clients") or []
    if not isinstance(allowed_clients_payload, list):
        raise ValueError(f"router proxies entry #{index} allowed_clients must be an array")
    allowed_clients = []
    for target in allowed_clients_payload:
        normalized_target = normalize_client_limit_target(str(target))
        if normalized_target and normalized_target not in allowed_clients:
            allowed_clients.append(normalized_target)

    access_mode = normalize_proxy_access_mode(proxy_payload.get("access_mode"))
    if access_mode == "private" and enabled and not allowed_clients:
        raise ValueError(f"router proxies entry #{index} private proxies require at least one allowed client")

    priority = normalize_positive_int(
        proxy_payload.get("priority", index),
        field_name=f"router proxies entry #{index} priority",
        minimum=1,
        maximum=100000,
    )
    return {
        "id": proxy_id,
        "name": str(proxy_payload.get("name") or proxy_id).strip() or proxy_id,
        "enabled": enabled,
        "priority": priority,
        "type": proxy_type,
        "host": host,
        "port": port,
        "access_mode": access_mode,
        "allowed_clients": allowed_clients,
        "traffic_limit": normalize_proxy_traffic_limit(
            proxy_payload.get("traffic_limit"),
            field_prefix=f"router proxies entry #{index} traffic_limit",
        ),
        "per_client_traffic_limit": normalize_proxy_traffic_limit(
            proxy_payload.get("per_client_traffic_limit"),
            field_prefix=f"router proxies entry #{index} per_client_traffic_limit",
        ),
        "note": str(proxy_payload.get("note", "")).strip(),
    }


def legacy_upstream_proxy_entry(upstream_payload, *, default_config) -> dict | None:
    if not bool(upstream_payload.get("enabled", default_config["upstream"]["enabled"])):
        return None
    payload = {
        "id": "upstream-default",
        "name": "Default upstream",
        "enabled": True,
        "priority": 1,
        "type": upstream_payload.get("type", default_config["upstream"]["type"]),
        "host": upstream_payload.get("host", default_config["upstream"]["host"]),
        "port": upstream_payload.get("port", default_config["upstream"]["port"]),
        "access_mode": "public",
        "allowed_clients": [],
    }
    return normalize_upstream_proxy_entry(payload, index=1)


def normalize_positive_int(value, *, field_name: str, minimum: int = 1, maximum: int | None = None) -> int:
    text = str(value).strip()
    try:
        parsed = int(text)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} must be an integer") from exc

    if parsed < minimum:
        raise ValueError(f"{field_name} must be at least {minimum}")
    if maximum is not None and parsed > maximum:
        raise ValueError(f"{field_name} must be at most {maximum}")
    return parsed


def validate_traffic_limit_definition(
    *,
    enabled: bool,
    max_past_hour_mb,
    max_past_3h_mb,
    field_prefix: str,
):
    if enabled and max_past_hour_mb is None and max_past_3h_mb is None:
        raise ValueError(
            f"{field_prefix} must set at least one of max_past_hour_mb or max_past_3h_mb when enabled"
        )


def normalize_default_traffic_limit(payload, *, default_payload, config_key: str):
    if payload is None:
        payload = {}
    if not isinstance(payload, dict):
        raise ValueError(f"router {config_key} must be an object")

    normalized = {
        "enabled": bool(payload.get("enabled", default_payload["enabled"])),
        "max_past_hour_mb": normalize_traffic_limit_mb(
            payload.get("max_past_hour_mb", default_payload["max_past_hour_mb"]),
            field_name=f"router {config_key} max_past_hour_mb",
        ),
        "max_past_3h_mb": normalize_traffic_limit_mb(
            payload.get("max_past_3h_mb", default_payload["max_past_3h_mb"]),
            field_name=f"router {config_key} max_past_3h_mb",
        ),
        "note": str(payload.get("note", default_payload["note"])).strip(),
    }
    validate_traffic_limit_definition(
        enabled=normalized["enabled"],
        max_past_hour_mb=normalized["max_past_hour_mb"],
        max_past_3h_mb=normalized["max_past_3h_mb"],
        field_prefix=f"router {config_key}",
    )
    return normalized


def parse_client_traffic_exemption_duration(value: str | None, *, field_name: str) -> timedelta | None:
    normalized = str(value or "").strip().lower()
    if normalized == "always":
        return None

    match = CLIENT_TRAFFIC_EXEMPTION_DURATION_PATTERN.fullmatch(normalized)
    if match is None:
        raise ValueError(f"{field_name} must be 'always' or a compact duration such as 2h, 1d, or 7d")

    amount = int(match.group(1))
    unit = match.group(2).lower()
    if amount <= 0:
        raise ValueError(f"{field_name} must be greater than 0")

    if unit == "s":
        return timedelta(seconds=amount)
    if unit == "m":
        return timedelta(minutes=amount)
    if unit == "h":
        return timedelta(hours=amount)
    if unit == "d":
        return timedelta(days=amount)
    if unit == "w":
        return timedelta(weeks=amount)
    raise ValueError(f"{field_name} uses an unsupported duration unit")


def normalize_client_traffic_exemption_duration(value: str | None, *, field_name: str) -> str:
    normalized = str(value or "").strip().lower() or "always"
    parsed = parse_client_traffic_exemption_duration(normalized, field_name=field_name)
    if parsed is None:
        return "always"
    return normalized


def normalize_client_traffic_exemption_expiration(
    expires_at_value,
    *,
    duration: str,
    now: datetime,
    field_name: str,
) -> datetime | None:
    if duration == "always":
        return None

    parsed = parse_datetime_text(expires_at_value)
    if parsed is not None:
        return parsed

    duration_delta = parse_client_traffic_exemption_duration(duration, field_name=field_name)
    if duration_delta is None:
        return None
    return now + duration_delta


def is_client_traffic_exemption_expired(exemption, *, now: datetime | None = None) -> bool:
    expires_at = parse_datetime_text(exemption.get("expires_at"))
    if expires_at is None:
        return False
    check_time = now or datetime.now().astimezone()
    return expires_at <= check_time


def client_traffic_exemption_remaining_seconds(exemption, *, now: datetime | None = None) -> int | None:
    expires_at = parse_datetime_text(exemption.get("expires_at"))
    if expires_at is None:
        return None
    check_time = now or datetime.now().astimezone()
    return max(0, int((expires_at - check_time).total_seconds()))


def is_client_block_expired(block, *, now: datetime | None = None) -> bool:
    return is_client_traffic_exemption_expired(block, now=now)


def client_block_remaining_seconds(block, *, now: datetime | None = None) -> int | None:
    return client_traffic_exemption_remaining_seconds(block, now=now)


def summarize_domain(value: str | None) -> str:
    normalized = normalize_host(value or "")
    if not normalized:
        return ""
    try:
        ipaddress.ip_address(normalized)
        return normalized
    except ValueError:
        pass

    labels = [label for label in normalized.split(".") if label]
    if len(labels) <= 2:
        return normalized
    if len(labels[-1]) == 2 and labels[-2] in COMMON_SECOND_LEVEL_DOMAIN_LABELS and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def is_ip_address_text(value: str | None) -> bool:
    normalized = normalize_host(value or "")
    if not normalized:
        return False
    try:
        ipaddress.ip_address(normalized)
    except ValueError:
        return False
    return True


def default_router_config():
    routing_defaults = default_routing_fields()
    return {
        "default_action": routing_defaults["default_action"],
        "ignored_failure_hosts": list(routing_defaults["ignored_failure_hosts"]),
        "default_client_traffic_limit": {
            "enabled": False,
            "max_past_hour_mb": None,
            "max_past_3h_mb": None,
            "note": "",
        },
        "default_authenticated_client_traffic_limit": {
            "enabled": False,
            "max_past_hour_mb": None,
            "max_past_3h_mb": None,
            "note": "",
        },
        "client_auth": {
            "enabled": False,
            "allow_anonymous": True,
            "realm": DEFAULT_CLIENT_AUTH_REALM,
            "credentials": [],
        },
        "client_blocks": [],
        "client_traffic_limits": [],
        "client_traffic_exemptions": [],
        "auto_proxy_failures": {
            "enabled": False,
        },
        "upstream_retry": {
            "enabled": True,
            "attempts": UPSTREAM_RETRY_ATTEMPTS,
            "initial_delay_seconds": UPSTREAM_RETRY_INITIAL_DELAY_SECONDS,
            "max_delay_seconds": UPSTREAM_RETRY_MAX_DELAY_SECONDS,
        },
        "https_interception": {
            "enabled": False,
            "mode": "allowlist",
            "trust_policy": "adaptive",
            "host_patterns": [],
            "bypass_patterns": [],
        },
        "upstream": {
            "enabled": False,
            "type": "http",
            "host": "127.0.0.1",
            "port": HTTPS_DEFAULT_PORT,
        },
        "proxies": [],
        "rules": list(routing_defaults["rules"]),
        "routing_profiles": [],
    }


def normalize_routing_profile_signature(payload, *, field_name: str):
    if payload is None:
        payload = {}
    if not isinstance(payload, dict):
        raise ValueError(f"{field_name} must be an object")

    vpn_keys_payload = payload.get("vpn_keys") or []
    if not isinstance(vpn_keys_payload, list):
        raise ValueError(f"{field_name} vpn_keys must be an array")
    vpn_labels_payload = payload.get("vpn_labels") or []
    if not isinstance(vpn_labels_payload, list):
        raise ValueError(f"{field_name} vpn_labels must be an array")

    signature = {
        "internet_key": str(payload.get("internet_key") or "").strip(),
        "internet_label": str(payload.get("internet_label") or "").strip(),
        "route_interface": str(payload.get("route_interface") or "").strip(),
        "route_gateway": str(payload.get("route_gateway") or "").strip(),
        "vpn_keys": sorted({str(item).strip() for item in vpn_keys_payload if str(item).strip()}),
        "vpn_labels": sorted({str(item).strip() for item in vpn_labels_payload if str(item).strip()}),
    }
    if not (
        signature["internet_key"]
        or signature["route_interface"]
        or signature["route_gateway"]
        or signature["vpn_keys"]
    ):
        raise ValueError(f"{field_name} must identify at least one internet or VPN property")
    return signature


def normalize_routing_target_payload(payload, *, field_prefix: str, default_config, now: datetime):
    default_action = str(payload.get("default_action", default_config["default_action"])).strip().lower()
    if default_action not in DEFAULT_ROUTE_ACTIONS:
        raise ValueError(
            f"{field_prefix} default_action must be one of: {', '.join(sorted(DEFAULT_ROUTE_ACTIONS))}"
        )

    rules_payload = payload.get("rules") or []
    if not isinstance(rules_payload, list):
        raise ValueError(f"{field_prefix} rules must be an array")

    normalized_rules = []
    for index, rule_payload in enumerate(rules_payload, start=1):
        if not isinstance(rule_payload, dict):
            raise ValueError(f"{field_prefix} rule #{index} must be an object")

        pattern = normalize_rule_pattern(str(rule_payload.get("pattern", "")))
        if not pattern:
            continue

        match_type = str(rule_payload.get("match", "suffix")).strip().lower()
        if match_type not in RULE_MATCH_TYPES:
            raise ValueError(
                f"{field_prefix} rule #{index} match must be one of: {', '.join(sorted(RULE_MATCH_TYPES))}"
            )

        action = str(rule_payload.get("action", "proxy")).strip().lower()
        if action not in RULE_ROUTE_ACTIONS:
            raise ValueError(
                f"{field_prefix} rule #{index} action must be one of: {', '.join(sorted(RULE_ROUTE_ACTIONS))}"
            )

        note = str(rule_payload.get("note", "")).strip()
        source = normalize_rule_source(rule_payload.get("source"), note)
        duration = normalize_rule_duration(
            rule_payload.get("duration"),
            source=source,
            note=note,
        )
        expires_at = normalize_rule_expiration(
            rule_payload.get("expires_at"),
            duration=duration,
            source=source,
            note=note,
            now=now,
        )
        if expires_at is not None and expires_at <= now:
            continue

        normalized_rule = {
            "pattern": pattern,
            "match": match_type,
            "action": action,
            "enabled": bool(rule_payload.get("enabled", True)),
            "note": note,
            "source": source,
            "duration": duration,
            "expires_at": expires_at.isoformat() if expires_at is not None else None,
        }
        proxy_id = normalize_upstream_proxy_id(rule_payload.get("proxy_id"))
        if action == "proxy" and proxy_id:
            normalized_rule["proxy_id"] = proxy_id
        normalized_rules.append(normalized_rule)

    normalized_rules = prioritize_router_rules(normalized_rules)

    ignored_failure_hosts_payload = payload.get("ignored_failure_hosts") or []
    if not isinstance(ignored_failure_hosts_payload, list):
        raise ValueError(f"{field_prefix} ignored_failure_hosts must be an array")
    ignored_failure_hosts = []
    for item in ignored_failure_hosts_payload:
        normalized_item = summarize_domain(str(item)) or normalize_host(str(item))
        if normalized_item and normalized_item not in ignored_failure_hosts:
            ignored_failure_hosts.append(normalized_item)

    return {
        "default_action": default_action,
        "ignored_failure_hosts": ignored_failure_hosts,
        "rules": normalized_rules,
    }


def normalize_router_config(payload):
    if payload is None:
        payload = {}
    if not isinstance(payload, dict):
        raise ValueError("router config payload must be a JSON object")

    default_config = default_router_config()
    upstream_payload = payload.get("upstream") or {}
    if upstream_payload is None:
        upstream_payload = {}
    if not isinstance(upstream_payload, dict):
        raise ValueError("router upstream must be an object")

    proxies_payload = payload.get("proxies")
    if proxies_payload is None:
        proxies_payload = []
    if not isinstance(proxies_payload, list):
        raise ValueError("router proxies must be an array")

    auto_proxy_failures_payload = payload.get("auto_proxy_failures") or {}
    if auto_proxy_failures_payload is None:
        auto_proxy_failures_payload = {}
    if not isinstance(auto_proxy_failures_payload, dict):
        raise ValueError("router auto_proxy_failures must be an object")

    upstream_retry_payload = payload.get("upstream_retry") or {}
    if upstream_retry_payload is None:
        upstream_retry_payload = {}
    if not isinstance(upstream_retry_payload, dict):
        raise ValueError("router upstream_retry must be an object")

    https_interception_payload = payload.get("https_interception") or {}
    if https_interception_payload is None:
        https_interception_payload = {}
    if not isinstance(https_interception_payload, dict):
        raise ValueError("router https_interception must be an object")

    default_client_traffic_limit_payload = payload.get("default_client_traffic_limit") or {}
    default_authenticated_client_traffic_limit_payload = (
        payload.get("default_authenticated_client_traffic_limit") or {}
    )

    client_auth_payload = payload.get("client_auth") or {}
    if client_auth_payload is None:
        client_auth_payload = {}
    if not isinstance(client_auth_payload, dict):
        raise ValueError("router client_auth must be an object")

    client_traffic_limits_payload = payload.get("client_traffic_limits") or []
    if not isinstance(client_traffic_limits_payload, list):
        raise ValueError("router client_traffic_limits must be an array")

    client_blocks_payload = payload.get("client_blocks") or []
    if not isinstance(client_blocks_payload, list):
        raise ValueError("router client_blocks must be an array")

    client_traffic_exemptions_payload = payload.get("client_traffic_exemptions") or []
    if not isinstance(client_traffic_exemptions_payload, list):
        raise ValueError("router client_traffic_exemptions must be an array")

    upstream_type = str(upstream_payload.get("type", default_config["upstream"]["type"])).strip().lower()
    if upstream_type not in UPSTREAM_PROXY_TYPES:
        raise ValueError(f"router upstream type must be one of: {', '.join(sorted(UPSTREAM_PROXY_TYPES))}")

    https_interception_mode = str(
        https_interception_payload.get(
            "mode",
            default_config["https_interception"]["mode"],
        )
    ).strip().lower()
    if https_interception_mode not in HTTPS_INTERCEPTION_MODES:
        raise ValueError(
            "router https_interception mode must be one of: "
            f"{', '.join(sorted(HTTPS_INTERCEPTION_MODES))}"
        )
    https_interception_trust_policy = str(
        https_interception_payload.get(
            "trust_policy",
            default_config["https_interception"]["trust_policy"],
        )
    ).strip().lower()
    if https_interception_trust_policy not in HTTPS_INTERCEPTION_TRUST_POLICIES:
        raise ValueError(
            "router https_interception trust_policy must be one of: "
            f"{', '.join(sorted(HTTPS_INTERCEPTION_TRUST_POLICIES))}"
        )

    upstream_host = str(upstream_payload.get("host", default_config["upstream"]["host"])).strip()
    upstream_port_raw = upstream_payload.get("port", default_config["upstream"]["port"])
    try:
        upstream_port = int(upstream_port_raw)
    except (TypeError, ValueError) as exc:
        raise ValueError("router upstream port must be an integer") from exc
    ensure_valid_port(upstream_port, "router upstream port")

    now = datetime.now().astimezone()
    normalized_routing_defaults = normalize_routing_target_payload(
        payload,
        field_prefix="router",
        default_config=default_config,
        now=now,
    )

    upstream_enabled = bool(upstream_payload.get("enabled", default_config["upstream"]["enabled"]))
    if upstream_enabled and not upstream_host:
        raise ValueError("router upstream host is required when the upstream proxy is enabled")

    normalized_proxies = []
    seen_proxy_ids = set()
    if proxies_payload:
        for index, proxy_payload in enumerate(proxies_payload, start=1):
            proxy = normalize_upstream_proxy_entry(proxy_payload, index=index)
            if proxy is None:
                continue
            if proxy["id"] in seen_proxy_ids:
                raise ValueError(f"router proxies entry #{index} uses duplicate id '{proxy['id']}'")
            seen_proxy_ids.add(proxy["id"])
            normalized_proxies.append(proxy)
    else:
        legacy_proxy = legacy_upstream_proxy_entry(upstream_payload, default_config=default_config)
        if legacy_proxy is not None:
            normalized_proxies.append(legacy_proxy)
            seen_proxy_ids.add(legacy_proxy["id"])

    normalized_proxies.sort(key=lambda item: (int(item.get("priority", 1)), item.get("id", "")))
    enabled_proxies = [proxy for proxy in normalized_proxies if proxy.get("enabled", True)]
    first_enabled_proxy = enabled_proxies[0] if enabled_proxies else None
    if first_enabled_proxy is not None:
        upstream_enabled = True
        upstream_type = first_enabled_proxy["type"]
        upstream_host = first_enabled_proxy["host"]
        upstream_port = first_enabled_proxy["port"]

    upstream_retry_attempts = normalize_positive_int(
        upstream_retry_payload.get(
            "attempts",
            default_config["upstream_retry"]["attempts"],
        ),
        field_name="router upstream_retry attempts",
        minimum=1,
        maximum=UPSTREAM_RETRY_ATTEMPTS_LIMIT,
    )
    upstream_retry_initial_delay_seconds = normalize_positive_int(
        upstream_retry_payload.get(
            "initial_delay_seconds",
            default_config["upstream_retry"]["initial_delay_seconds"],
        ),
        field_name="router upstream_retry initial_delay_seconds",
        minimum=0,
        maximum=UPSTREAM_RETRY_DELAY_SECONDS_LIMIT,
    )
    upstream_retry_max_delay_seconds = normalize_positive_int(
        upstream_retry_payload.get(
            "max_delay_seconds",
            default_config["upstream_retry"]["max_delay_seconds"],
        ),
        field_name="router upstream_retry max_delay_seconds",
        minimum=0,
        maximum=UPSTREAM_RETRY_DELAY_SECONDS_LIMIT,
    )
    if upstream_retry_max_delay_seconds < upstream_retry_initial_delay_seconds:
        raise ValueError("router upstream_retry max_delay_seconds must be greater than or equal to initial_delay_seconds")

    normalized_default_client_traffic_limit = normalize_default_traffic_limit(
        default_client_traffic_limit_payload,
        default_payload=default_config["default_client_traffic_limit"],
        config_key="default_client_traffic_limit",
    )
    normalized_default_authenticated_client_traffic_limit = normalize_default_traffic_limit(
        default_authenticated_client_traffic_limit_payload,
        default_payload=default_config["default_authenticated_client_traffic_limit"],
        config_key="default_authenticated_client_traffic_limit",
    )

    client_auth_credentials_payload = client_auth_payload.get("credentials") or []
    if not isinstance(client_auth_credentials_payload, list):
        raise ValueError("router client_auth credentials must be an array")

    normalized_client_auth_credentials = []
    seen_auth_usernames = set()
    for index, credential_payload in enumerate(client_auth_credentials_payload, start=1):
        if not isinstance(credential_payload, dict):
            raise ValueError(f"router client_auth credential #{index} must be an object")
        username = normalize_client_auth_username(str(credential_payload.get("username", "")))
        if not username:
            continue
        if username in seen_auth_usernames:
            raise ValueError(f"router client_auth credential #{index} uses duplicate username '{username}'")
        seen_auth_usernames.add(username)

        password_text = credential_payload.get("password")
        if password_text is not None and str(password_text):
            password_hash = hash_client_auth_password(str(password_text))
        else:
            password_hash = normalize_client_auth_password_hash(credential_payload.get("password_hash"))
        if not password_hash:
            continue

        normalized_client_auth_credentials.append(
            {
                "username": username,
                "password_hash": password_hash,
                "label": str(credential_payload.get("label", "")).strip(),
                "enabled": bool(credential_payload.get("enabled", True)),
            }
        )

    normalized_client_traffic_limits = []
    for index, limit_payload in enumerate(client_traffic_limits_payload, start=1):
        if not isinstance(limit_payload, dict):
            raise ValueError(f"router client_traffic_limits entry #{index} must be an object")

        client_target = normalize_client_limit_target(str(limit_payload.get("client", "")))
        if not client_target:
            continue

        max_past_hour_mb = normalize_traffic_limit_mb(
            limit_payload.get("max_past_hour_mb"),
            field_name=f"router client_traffic_limits entry #{index} max_past_hour_mb",
        )
        max_past_3h_mb = normalize_traffic_limit_mb(
            limit_payload.get("max_past_3h_mb"),
            field_name=f"router client_traffic_limits entry #{index} max_past_3h_mb",
        )
        enabled = bool(limit_payload.get("enabled", True))
        validate_traffic_limit_definition(
            enabled=enabled,
            max_past_hour_mb=max_past_hour_mb,
            max_past_3h_mb=max_past_3h_mb,
            field_prefix=f"router client_traffic_limits entry #{index}",
        )

        normalized_client_traffic_limits.append(
            {
                "client": client_target,
                "enabled": enabled,
                "max_past_hour_mb": max_past_hour_mb,
                "max_past_3h_mb": max_past_3h_mb,
                "note": str(limit_payload.get("note", "")).strip(),
            }
        )

    normalized_client_blocks = []
    for index, block_payload in enumerate(client_blocks_payload, start=1):
        if not isinstance(block_payload, dict):
            raise ValueError(f"router client_blocks entry #{index} must be an object")

        client_target = normalize_client_limit_target(str(block_payload.get("client", "")))
        if not client_target:
            continue

        duration = normalize_client_traffic_exemption_duration(
            block_payload.get("duration"),
            field_name=f"router client_blocks entry #{index} duration",
        )
        expires_at = normalize_client_traffic_exemption_expiration(
            block_payload.get("expires_at"),
            duration=duration,
            now=now,
            field_name=f"router client_blocks entry #{index} duration",
        )
        if expires_at is not None and expires_at <= now:
            continue

        normalized_client_blocks.append(
            {
                "client": client_target,
                "enabled": bool(block_payload.get("enabled", True)),
                "duration": duration,
                "expires_at": expires_at.isoformat() if expires_at is not None else None,
                "note": str(block_payload.get("note", "")).strip(),
            }
        )

    normalized_client_traffic_exemptions = []
    for index, exemption_payload in enumerate(client_traffic_exemptions_payload, start=1):
        if not isinstance(exemption_payload, dict):
            raise ValueError(f"router client_traffic_exemptions entry #{index} must be an object")

        client_target = normalize_client_limit_target(str(exemption_payload.get("client", "")))
        if not client_target:
            continue

        duration = normalize_client_traffic_exemption_duration(
            exemption_payload.get("duration"),
            field_name=f"router client_traffic_exemptions entry #{index} duration",
        )
        expires_at = normalize_client_traffic_exemption_expiration(
            exemption_payload.get("expires_at"),
            duration=duration,
            now=now,
            field_name=f"router client_traffic_exemptions entry #{index} duration",
        )
        if expires_at is not None and expires_at <= now:
            continue

        normalized_client_traffic_exemptions.append(
            {
                "client": client_target,
                "enabled": bool(exemption_payload.get("enabled", True)),
                "duration": duration,
                "expires_at": expires_at.isoformat() if expires_at is not None else None,
                "note": str(exemption_payload.get("note", "")).strip(),
            }
        )

    routing_profiles_payload = payload.get("routing_profiles") or []
    if not isinstance(routing_profiles_payload, list):
        raise ValueError("router routing_profiles must be an array")

    normalized_routing_profiles = []
    enabled_profile_signatures = {}
    seen_profile_ids = set()
    for index, profile_payload in enumerate(routing_profiles_payload, start=1):
        if not isinstance(profile_payload, dict):
            raise ValueError(f"router routing_profiles entry #{index} must be an object")
        profile_id = str(profile_payload.get("id") or "").strip() or uuid.uuid4().hex
        if profile_id == DEFAULT_ROUTING_PROFILE_ID:
            raise ValueError(
                f"router routing_profiles entry #{index} id '{DEFAULT_ROUTING_PROFILE_ID}' is reserved"
            )
        if profile_id in seen_profile_ids:
            raise ValueError(f"router routing_profiles entry #{index} uses duplicate id '{profile_id}'")
        seen_profile_ids.add(profile_id)
        normalized_profile = {
            "id": profile_id,
            "name": str(profile_payload.get("name") or f"Profile {index}").strip() or f"Profile {index}",
            "enabled": bool(profile_payload.get("enabled", True)),
            "signature": normalize_routing_profile_signature(
                profile_payload.get("signature"),
                field_name=f"router routing_profiles entry #{index} signature",
            ),
        }
        normalized_profile.update(
            normalize_routing_target_payload(
                profile_payload,
                field_prefix=f"router routing_profiles entry #{index}",
                default_config=default_routing_fields(),
                now=now,
            )
        )
        if normalized_profile["enabled"]:
            signature_key = routing_profile_identity_key(normalized_profile["signature"])
            existing_profile = enabled_profile_signatures.get(signature_key)
            if existing_profile is not None:
                raise ValueError(
                    "router routing_profiles cannot contain duplicate enabled signatures "
                    f"('{existing_profile}' and '{normalized_profile['name']}')"
                )
            enabled_profile_signatures[signature_key] = normalized_profile["name"]
        normalized_routing_profiles.append(normalized_profile)

    if not enabled_proxies:
        routing_targets = [normalized_routing_defaults] + normalized_routing_profiles
        for target in routing_targets:
            if target["default_action"] == "proxy" or any(rule["action"] == "proxy" for rule in target["rules"]):
                raise ValueError("router must have at least one enabled proxy before any rule or default action can use proxy")

    known_proxy_ids = {proxy["id"] for proxy in normalized_proxies}
    for target in [normalized_routing_defaults] + normalized_routing_profiles:
        for rule in target["rules"]:
            proxy_id = rule.get("proxy_id")
            if proxy_id and proxy_id not in known_proxy_ids:
                raise ValueError(f"router rule references unknown proxy_id '{proxy_id}'")

    return {
        "default_action": normalized_routing_defaults["default_action"],
        "ignored_failure_hosts": normalized_routing_defaults["ignored_failure_hosts"],
        "default_client_traffic_limit": normalized_default_client_traffic_limit,
        "default_authenticated_client_traffic_limit": normalized_default_authenticated_client_traffic_limit,
        "client_auth": {
            "enabled": bool(client_auth_payload.get("enabled", default_config["client_auth"]["enabled"])),
            "allow_anonymous": bool(
                client_auth_payload.get("allow_anonymous", default_config["client_auth"]["allow_anonymous"])
            ),
            "realm": str(client_auth_payload.get("realm", default_config["client_auth"]["realm"])).strip()
            or DEFAULT_CLIENT_AUTH_REALM,
            "credentials": normalized_client_auth_credentials,
        },
        "client_blocks": normalized_client_blocks,
        "client_traffic_limits": normalized_client_traffic_limits,
        "client_traffic_exemptions": normalized_client_traffic_exemptions,
        "auto_proxy_failures": {
            "enabled": bool(
                auto_proxy_failures_payload.get(
                    "enabled",
                    default_config["auto_proxy_failures"]["enabled"],
                )
            ),
        },
        "upstream_retry": {
            "enabled": bool(
                upstream_retry_payload.get(
                    "enabled",
                    default_config["upstream_retry"]["enabled"],
                )
            ),
            "attempts": upstream_retry_attempts,
            "initial_delay_seconds": upstream_retry_initial_delay_seconds,
            "max_delay_seconds": upstream_retry_max_delay_seconds,
        },
        "https_interception": {
            "enabled": bool(
                https_interception_payload.get(
                    "enabled",
                    default_config["https_interception"]["enabled"],
                )
            ),
            "mode": https_interception_mode,
            "trust_policy": https_interception_trust_policy,
            "host_patterns": normalize_host_pattern_list(
                https_interception_payload.get(
                    "host_patterns",
                    default_config["https_interception"]["host_patterns"],
                ),
                field_name="router https_interception host_patterns",
            ),
            "bypass_patterns": normalize_host_pattern_list(
                https_interception_payload.get(
                    "bypass_patterns",
                    default_config["https_interception"]["bypass_patterns"],
                ),
                field_name="router https_interception bypass_patterns",
            ),
        },
        "upstream": {
            "enabled": upstream_enabled,
            "type": upstream_type,
            "host": upstream_host,
            "port": upstream_port,
        },
        "proxies": normalized_proxies,
        "rules": normalized_routing_defaults["rules"],
        "routing_profiles": normalized_routing_profiles,
    }


def rule_matches_host(rule, host: str) -> bool:
    normalized_host = normalize_host(host)
    pattern = rule["pattern"]
    match_type = rule["match"]

    if match_type == "exact":
        return normalized_host == pattern
    if match_type == "contains":
        return pattern in normalized_host
    return normalized_host == pattern or normalized_host.endswith(f".{pattern}")


def describe_route_decision(route_decision) -> str:
    if route_decision["action"] == "proxy" and route_decision["upstream"] is not None:
        upstream = route_decision["upstream"]
        return f"proxy:{upstream['type']}://{upstream['host']}:{upstream['port']}"
    if route_decision["action"] == "block":
        return "reject:block"
    return "direct"


def build_auto_proxy_probe_route_label(upstream) -> str:
    return (
        f"{AUTO_PROXY_PROBE_ROUTE_LABEL_PREFIX}"
        f"{upstream['type']}://{upstream['host']}:{upstream['port']}"
    )


def is_auto_proxy_probe_route_label(route_label: str | None) -> bool:
    return str(route_label or "").startswith(AUTO_PROXY_PROBE_ROUTE_LABEL_PREFIX)


def split_nmcli_terse_fields(line: str) -> list[str]:
    fields = []
    current = []
    escaped = False
    for character in line:
        if escaped:
            current.append(character)
            escaped = False
            continue
        if character == "\\":
            escaped = True
            continue
        if character == ":":
            fields.append("".join(current))
            current = []
            continue
        current.append(character)
    fields.append("".join(current))
    return fields


def format_client_address(address) -> str:
    if isinstance(address, tuple) and len(address) >= 2:
        return f"{address[0]}:{address[1]}"
    return str(address)


def truncate_for_log(value: str, limit: int = MAX_DEBUG_VALUE_LENGTH) -> str:
    if len(value) <= limit:
        return value

    extra = len(value) - limit
    return f"{value[:limit]}... <truncated {extra} chars>"


def redact_header_value(header_name: str, value: str) -> str:
    if header_name.lower() in SENSITIVE_HEADER_NAMES:
        return "<redacted>"
    return truncate_for_log(value)


def format_headers_for_log(headers) -> str:
    items = []
    for key, value in headers.items():
        items.append(f"{key}={redact_header_value(key, value)}")
    return ", ".join(items) if items else "<none>"


def headers_for_record(headers) -> list[dict[str, str]]:
    if headers is None:
        return []
    if hasattr(headers, "items"):
        iterable = headers.items()
    else:
        iterable = headers

    items = []
    for key, value in iterable:
        name = str(key or "")
        if not name:
            continue
        items.append(
            {
                "name": name,
                "value": redact_header_value(name, str(value or "")),
            }
        )
    return items


def header_value(headers, name: str) -> str:
    expected = str(name or "").strip().lower()
    if not expected or headers is None:
        return ""
    if hasattr(headers, "items"):
        iterable = headers.items()
    else:
        iterable = headers
    for key, value in iterable:
        if str(key or "").strip().lower() == expected:
            return str(value or "")
    return ""


_SENSITIVE_TEXT_FIELD_PATTERN = re.compile(
    r'(?i)("?(?:access_token|api_key|authorization|auth|code|key|password|passwd|pwd|secret|sig|signature|token)"?\s*[:=]\s*)'
    r'("?)[^"&\s,}]+("?)'
)
_BEARER_TOKEN_PATTERN = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")


def redact_text_for_record(value: str) -> str:
    text = str(value or "")
    text = _BEARER_TOKEN_PATTERN.sub("Bearer <redacted>", text)
    return _SENSITIVE_TEXT_FIELD_PATTERN.sub(r"\1\2<redacted>\3", text)


def is_textual_content_type(content_type: str | None) -> bool:
    normalized = str(content_type or "").split(";", 1)[0].strip().lower()
    if not normalized:
        return False
    if normalized.startswith("text/"):
        return True
    return normalized in {
        "application/graphql",
        "application/javascript",
        "application/json",
        "application/ld+json",
        "application/problem+json",
        "application/x-www-form-urlencoded",
        "application/xml",
        "image/svg+xml",
    } or normalized.endswith("+json") or normalized.endswith("+xml")


def _content_type_charset(content_type: str | None) -> str:
    for part in str(content_type or "").split(";")[1:]:
        key, separator, value = part.strip().partition("=")
        if separator and key.strip().lower() == "charset":
            return value.strip().strip("\"'")
    return ""


def _looks_like_binary_text(text: str) -> bool:
    if not text:
        return False
    probe = text[:4096]
    replacement_count = probe.count("\ufffd")
    control_count = sum(1 for char in probe if ord(char) < 32 and char not in "\r\n\t")
    suspicious_count = replacement_count + control_count
    return suspicious_count > max(4, len(probe) // 50)


def _content_encoding_tokens(content_encoding: str | None) -> list[str]:
    tokens = []
    for item in str(content_encoding or "").split(","):
        token = item.strip().lower()
        if token and token not in {"identity", "none"}:
            tokens.append(token)
    return tokens


def _optional_module(name: str):
    try:
        return importlib.import_module(name)
    except ImportError:
        return None


def _decompress_zlib_stream(data: bytes, *, wbits: int, preview_limit: int) -> bytes:
    decompressor = zlib.decompressobj(wbits)
    return decompressor.decompress(data, max(0, int(preview_limit)) + 1)


def _decompress_brotli(data: bytes, *, preview_limit: int) -> tuple[bytes | None, str | None]:
    brotli_module = _optional_module("brotli")
    if brotli_module is None:
        return None, "unsupported content-encoding: br"
    try:
        if hasattr(brotli_module, "Decompressor"):
            decompressor = brotli_module.Decompressor()
            if hasattr(decompressor, "process"):
                return bytes(decompressor.process(data))[: max(0, int(preview_limit)) + 1], None
        return bytes(brotli_module.decompress(data))[: max(0, int(preview_limit)) + 1], None
    except Exception as exc:  # pragma: no cover - depends on optional brotli implementation
        return None, f"could not decode br body: {exc}"


def _decompress_zstandard(data: bytes, *, preview_limit: int) -> tuple[bytes | None, str | None]:
    zstandard_module = _optional_module("zstandard")
    if zstandard_module is None:
        return None, "unsupported content-encoding: zstd"
    try:
        decompressor = zstandard_module.ZstdDecompressor()
        with decompressor.stream_reader(io.BytesIO(data)) as reader:
            return reader.read(max(0, int(preview_limit)) + 1), None
    except Exception as exc:  # pragma: no cover - depends on optional zstandard implementation
        return None, f"could not decode zstd body: {exc}"


def _decode_content_encoded_preview(
    body: bytes,
    *,
    content_encoding: str | None,
    preview_limit: int,
) -> tuple[bytes | None, bool, str | None]:
    decoded = body
    decoded_any = False
    for encoding in reversed(_content_encoding_tokens(content_encoding)):
        try:
            if encoding in {"gzip", "x-gzip"}:
                decoded = _decompress_zlib_stream(decoded, wbits=16 + zlib.MAX_WBITS, preview_limit=preview_limit)
            elif encoding == "deflate":
                try:
                    decoded = _decompress_zlib_stream(decoded, wbits=zlib.MAX_WBITS, preview_limit=preview_limit)
                except zlib.error:
                    decoded = _decompress_zlib_stream(decoded, wbits=-zlib.MAX_WBITS, preview_limit=preview_limit)
            elif encoding == "br":
                decoded_body, error = _decompress_brotli(decoded, preview_limit=preview_limit)
                if error:
                    return None, decoded_any, error
                decoded = decoded_body or b""
            elif encoding in {"zstd", "zstandard"}:
                decoded_body, error = _decompress_zstandard(decoded, preview_limit=preview_limit)
                if error:
                    return None, decoded_any, error
                decoded = decoded_body or b""
            else:
                return None, decoded_any, f"unsupported content-encoding: {encoding}"
        except zlib.error as exc:
            return None, decoded_any, f"could not decode {encoding} body: {exc}"
        decoded_any = True
    return decoded, decoded_any, None


def _decode_text_preview(preview_bytes: bytes, *, content_type: str | None, textual_hint: bool) -> str | None:
    charsets = []
    charset = _content_type_charset(content_type)
    if charset:
        charsets.append(charset)
    charsets.append("utf-8")

    for charset_name in dict.fromkeys(charsets):
        try:
            text = preview_bytes.decode(charset_name)
        except (LookupError, UnicodeDecodeError):
            continue
        if _looks_like_binary_text(text):
            return None
        return text

    if not textual_hint:
        return None

    text = preview_bytes.decode(charsets[0], errors="replace")
    if _looks_like_binary_text(text):
        return None
    return text


def body_preview_for_record(
    body: bytes | None,
    *,
    content_type: str | None = None,
    content_encoding: str | None = None,
    total_bytes: int | None = None,
    preview_limit: int = HTTPS_TRAFFIC_BODY_PREVIEW_BYTES,
):
    body_bytes = body or b""
    full_size = len(body_bytes) if total_bytes is None else max(0, int(total_bytes or 0))
    effective_preview_limit = max(0, int(preview_limit))
    preview = {
        "captured_bytes": 0,
        "total_bytes": full_size,
        "truncated": full_size > len(body_bytes),
        "content_type": str(content_type or ""),
        "content_encoding": str(content_encoding or ""),
        "decoded": False,
        "decode_error": None,
        "text": None,
        "omitted_reason": None,
    }
    if not body_bytes:
        preview["text"] = ""
        return preview

    decoded_bytes = body_bytes
    decoded_any = False
    decode_error = None
    if _content_encoding_tokens(content_encoding):
        decoded_body, decoded_any, decode_error = _decode_content_encoded_preview(
            body_bytes,
            content_encoding=content_encoding,
            preview_limit=effective_preview_limit,
        )
        if decoded_body is None:
            preview["decode_error"] = decode_error
            preview["omitted_reason"] = decode_error or "encoded body"
            return preview
        decoded_bytes = decoded_body

    preview_bytes = decoded_bytes[:effective_preview_limit]
    preview["captured_bytes"] = len(preview_bytes)
    preview["decoded"] = decoded_any
    preview["decode_error"] = decode_error
    preview["truncated"] = bool(preview["truncated"] or len(decoded_bytes) > len(preview_bytes))
    if not preview_bytes:
        preview["text"] = ""
        return preview

    textual = is_textual_content_type(content_type)
    if not textual:
        decoded_probe = _decode_text_preview(preview_bytes, content_type=content_type, textual_hint=False)
        textual = decoded_probe is not None
    decoded_text = _decode_text_preview(preview_bytes, content_type=content_type, textual_hint=textual)
    if decoded_text is None:
        preview["omitted_reason"] = "binary content"
        return preview

    preview["text"] = redact_text_for_record(decoded_text)
    return preview


def is_sensitive_query_parameter(name: str) -> bool:
    normalized = str(name or "").strip().lower()
    return normalized in SENSITIVE_QUERY_PARAMETER_NAMES or "token" in normalized or "secret" in normalized


def sanitize_target_path_for_record(target_path: str) -> str:
    parsed = urlsplit(target_path or "/")
    if not parsed.query:
        return target_path or "/"

    redacted_items = []
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        redacted_items.append((key, "redacted" if is_sensitive_query_parameter(key) else value))

    return urlunsplit(("", "", parsed.path or "/", urlencode(redacted_items, doseq=True), parsed.fragment))


def build_request_destination(scheme: str, host: str, port: int, target_path: str) -> str:
    default_port = 443 if scheme == "https" else 80
    authority = host if int(port) == default_port else f"{host}:{int(port)}"
    return f"{scheme}://{authority}{sanitize_target_path_for_record(target_path)}"


def resolve_debug_log_path(path_text: str | None) -> Path | None:
    if path_text:
        return Path(path_text).expanduser()
    return Path("/tmp") / f"proxy-router-debug-{datetime.now().strftime('%Y%m%d-%H%M%S')}.log"


def resolve_usage_log_path(path_text: str | None) -> Path | None:
    if not path_text:
        return DEFAULT_USAGE_LOG_PATH
    return Path(path_text).expanduser()


def resolve_failure_log_path(path_text: str | None) -> Path | None:
    if not path_text:
        return DEFAULT_FAILURE_LOG_PATH
    return Path(path_text).expanduser()


def resolve_https_traffic_log_path(path_text: str | None) -> Path | None:
    if not path_text:
        return DEFAULT_HTTPS_TRAFFIC_LOG_PATH
    return Path(path_text).expanduser()


def resolve_error_log_path(path_text: str | None) -> Path | None:
    if not path_text:
        return DEFAULT_ERROR_LOG_PATH
    return Path(path_text).expanduser()


def resolve_router_config_path(path_text: str | None) -> Path:
    if not path_text:
        return DEFAULT_ROUTER_CONFIG_PATH
    return Path(path_text).expanduser()


def resolve_https_intercept_ca_cert_path(path_text: str | None) -> Path:
    if not path_text:
        return DEFAULT_HTTPS_INTERCEPT_CA_CERT_PATH
    return Path(path_text).expanduser()


def resolve_https_intercept_ca_key_path(path_text: str | None) -> Path:
    if not path_text:
        return DEFAULT_HTTPS_INTERCEPT_CA_KEY_PATH
    return Path(path_text).expanduser()


def resolve_https_intercept_cert_cache_dir(path_text: str | None) -> Path:
    if not path_text:
        return DEFAULT_HTTPS_INTERCEPT_CERT_CACHE_DIR
    return Path(path_text).expanduser()


def format_mb(byte_count: int) -> str:
    value_in_mb = byte_count / BYTES_IN_MB
    if value_in_mb > 1024:
        return f"{value_in_mb / 1024:.2f} GB"
    return f"{value_in_mb:.2f} MB"


def format_duration_seconds(total_seconds: int | None) -> str:
    if total_seconds is None:
        return "a while"

    remaining = max(1, int(total_seconds))
    days, remainder = divmod(remaining, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    if seconds and not hours and not days:
        parts.append(f"{seconds}s")
    return " ".join(parts) or "under a minute"


def build_client_traffic_limit_message(evaluation) -> str:
    exceeded = []
    for window in evaluation.get("exceeded_windows", []):
        exceeded.append(
            f"{window['label']}: used {format_mb(window['used_bytes'])} of {format_mb(window['limit_bytes'])}"
        )
    retry_after = format_duration_seconds(evaluation.get("retry_after_seconds"))
    return "Client traffic limit reached. " + "; ".join(exceeded) + f". Try again in about {retry_after}."


def build_proxy_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=Path(sys.argv[0]).name,
        description="Start proxy listeners on this computer so a phone or another device on the same Wi-Fi can use them.",
        epilog=(
            "Examples:\n"
            "  proxy-router\n"
            "  proxy-router --mixed-port 1080\n"
            "  proxy-router --type mixed --type https\n"
            "  proxy-router --allow-client 192.168.1.50\n"
            "  proxy-router --type https --cert-file cert.pem --key-file key.pem\n\n"
            "  proxy-router usage-analyze\n"
            "  proxy-router usage-analyze /tmp/proxy-router-usage.log\n\n"
            "Notes:\n"
            "  - Phone Wi-Fi settings usually support only an HTTP proxy.\n"
            "  - The mixed listener accepts both HTTP and SOCKS5 on one port.\n"
            "  - HTTPS mode here means a TLS-wrapped HTTP proxy server.\n"
            "  - SOCKS5 is useful for apps or tools that support it directly, even on the mixed port.\n"
            "  - On shared Wi-Fi, prefer --allow-client with your phone IP.\n"
            "  - Usage data is written to /tmp/proxy-router-usage.log by default."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--type",
        action="append",
        choices=["mixed", "http", "https", "socks5"],
        dest="proxy_types",
        help="Proxy type to start. Repeat to start more than one. Default: mixed. Legacy http/socks5 selections also use the mixed port.",
    )
    parser.add_argument(
        "--bind",
        default="0.0.0.0",
        help="IP address to listen on. Default: 0.0.0.0 (all IPv4 interfaces).",
    )
    parser.add_argument(
        "--mixed-port",
        type=int,
        default=MIXED_DEFAULT_PORT,
        help=f"TCP port for the mixed HTTP + SOCKS5 proxy listener. Default: {MIXED_DEFAULT_PORT}",
    )
    parser.add_argument(
        "--https-port",
        type=int,
        default=HTTPS_DEFAULT_PORT,
        help=f"TCP port for the HTTPS proxy. Default: {HTTPS_DEFAULT_PORT}",
    )
    parser.add_argument(
        "--http-port",
        type=int,
        help="Legacy compatibility alias for the mixed port. If set together with --socks5-port they must match.",
    )
    parser.add_argument(
        "--socks5-port",
        type=int,
        help="Legacy compatibility alias for the mixed port. If set together with --http-port they must match.",
    )
    parser.add_argument(
        "--allow-client",
        action="append",
        default=[],
        metavar="IP_OR_CIDR",
        help="Allow only the given client IP or CIDR. Repeat to allow multiple entries.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT_SECONDS,
        help=f"Upstream connect/read timeout in seconds. Default: {DEFAULT_TIMEOUT_SECONDS}",
    )
    parser.add_argument(
        "--cert-file",
        help="Certificate file for --type https.",
    )
    parser.add_argument(
        "--key-file",
        help="Private key file for --type https.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print per-request and tunnel logs in addition to the default connection logs.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Keep startup output, but suppress runtime console connection logs.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable detailed redacted debugging and save it to a log file. Implies --verbose.",
    )
    parser.add_argument(
        "--debug-log-file",
        help="Debug log file path. Implies --debug. Default: /tmp/proxy-router-debug-<timestamp>.log",
    )
    parser.add_argument(
        "--usage-log-file",
        default=str(DEFAULT_USAGE_LOG_PATH),
        help=f"Usage log file path for transfer summaries. Default: {DEFAULT_USAGE_LOG_PATH}",
    )
    parser.add_argument(
        "--failure-log-file",
        default=str(DEFAULT_FAILURE_LOG_PATH),
        help=f"Failure log file path for failed requests. Default: {DEFAULT_FAILURE_LOG_PATH}",
    )
    parser.add_argument(
        "--https-traffic-log-file",
        default=str(DEFAULT_HTTPS_TRAFFIC_LOG_PATH),
        help=f"JSONL log file path for intercepted HTTPS request/response summaries. Default: {DEFAULT_HTTPS_TRAFFIC_LOG_PATH}",
    )
    parser.add_argument(
        "--router-config-file",
        default=str(DEFAULT_ROUTER_CONFIG_PATH),
        help=f"Router config file path used by the dashboard API. Default: {DEFAULT_ROUTER_CONFIG_PATH}",
    )
    parser.add_argument(
        "--dashboard-bind",
        default=DASHBOARD_DEFAULT_BIND,
        help=f"Bind address for the dashboard API server. Default: {DASHBOARD_DEFAULT_BIND}",
    )
    parser.add_argument(
        "--dashboard-port",
        type=int,
        default=DASHBOARD_DEFAULT_PORT,
        help=f"TCP port for the dashboard API server. Default: {DASHBOARD_DEFAULT_PORT}",
    )
    parser.add_argument(
        "--no-dashboard",
        action="store_true",
        help="Disable the dashboard API server.",
    )
    return parser


def build_usage_analyze_parser(prog_name: str) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=f"{prog_name} usage-analyze",
        description="Analyze transfer totals recorded by proxy-router.",
    )
    parser.add_argument(
        "log_file",
        nargs="?",
        default=str(DEFAULT_USAGE_LOG_PATH),
        help=f"Usage log file to analyze. Default: {DEFAULT_USAGE_LOG_PATH}",
    )
    parser.add_argument(
        "--client",
        help="Only include records for the given client IP.",
    )
    parser.add_argument(
        "--type",
        dest="proxy_type",
        choices=["http", "https", "socks5"],
        help="Only include records for one proxy type.",
    )
    return parser


def detect_local_ipv4_addresses_from_procfs():
    fib_trie_path = Path("/proc/net/fib_trie")
    try:
        lines = fib_trie_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []

    addresses = []
    pending_candidate = None
    for raw_line in lines:
        stripped = raw_line.strip()
        if not stripped:
            continue

        if stripped.startswith(("|-- ", "+-- ")):
            candidate_text = stripped[4:].strip()
            try:
                candidate_ip = ipaddress.ip_address(candidate_text)
            except ValueError:
                pending_candidate = None
                continue

            pending_candidate = candidate_text if candidate_ip.version == 4 else None
            continue

        if pending_candidate and stripped.startswith("/32 host LOCAL"):
            addresses.append(pending_candidate)
            pending_candidate = None

    return addresses


def detect_candidate_client_ips():
    candidates = []

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("1.1.1.1", 80))
            candidates.append(probe.getsockname()[0])
    except OSError:
        pass

    try:
        hostname = socket.gethostname()
        for family, _, _, _, sockaddr in socket.getaddrinfo(hostname, None, socket.AF_INET):
            if family == socket.AF_INET:
                candidates.append(sockaddr[0])
    except OSError:
        pass

    candidates.extend(detect_local_ipv4_addresses_from_procfs())

    preferred = []
    fallback = []
    seen = set()

    for candidate in candidates:
        if not candidate or candidate.startswith("127.") or candidate in seen:
            continue

        seen.add(candidate)

        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            continue

        if address.is_private:
            preferred.append(candidate)
        else:
            fallback.append(candidate)

    return preferred or fallback


def parse_allowed_networks(values):
    networks = []
    for value in values:
        try:
            if "/" in value:
                networks.append(ipaddress.ip_network(value, strict=False))
            else:
                networks.append(ipaddress.ip_network(f"{value}/32", strict=False))
        except ValueError as exc:
            raise SystemExit(f"Error: invalid --allow-client value '{value}': {exc}") from exc
    return networks


def ensure_valid_port(port: int, label: str):
    if not (1 <= port <= 65535):
        raise SystemExit(f"Error: {label} must be between 1 and 65535.")


def ensure_client_allowed(client_ip: str, allowed_networks) -> bool:
    if not allowed_networks:
        return True

    return any(ipaddress.ip_address(client_ip) in network for network in allowed_networks)


def split_host_port(value: str, default_port: int):
    value = value.strip()
    if not value:
        raise ValueError("missing host")

    if value.startswith("["):
        end = value.find("]")
        if end == -1:
            raise ValueError("invalid IPv6 host")
        host = value[1:end]
        rest = value[end + 1 :]
        if not rest:
            return host, default_port
        if not rest.startswith(":"):
            raise ValueError("invalid host:port")
        return host, int(rest[1:])

    if value.count(":") == 1:
        host, port_text = value.rsplit(":", 1)
        if port_text.isdigit():
            return host, int(port_text)

    return value, default_port


def summarize_usage_records(records):
    summary = empty_usage_summary()
    for record in records:
        uploaded_bytes = int(record.get("uploaded_bytes", 0))
        downloaded_bytes = int(record.get("downloaded_bytes", 0))
        add_usage_to_summary(
            summary,
            uploaded_bytes=uploaded_bytes,
            downloaded_bytes=downloaded_bytes,
            total_bytes=int(record.get("total_bytes", uploaded_bytes + downloaded_bytes)),
            duration_ms=record.get("duration_ms"),
            upstream_setup_ms=record.get("upstream_setup_ms"),
            relay_ms=record.get("relay_ms"),
        )
    return summary


def print_usage_summary(label: str, summary):
    print(f"{label}:")
    print(f"  Records: {summary['count']}")
    print(f"  Upload:   {format_mb(summary['uploaded_bytes'])} ({summary['uploaded_bytes']} bytes)")
    print(f"  Download: {format_mb(summary['downloaded_bytes'])} ({summary['downloaded_bytes']} bytes)")
    print(f"  Total:    {format_mb(summary['total_bytes'])} ({summary['total_bytes']} bytes)")
    duration_samples = int(summary.get("duration_sample_count", 0))
    if duration_samples:
        print(
            f"  Duration: avg {summary.get('duration_ms_avg')} ms, "
            f"max {summary.get('duration_ms_max')} ms ({duration_samples} samples)"
        )
        throughput_bps = summary.get("throughput_bps")
        if throughput_bps is not None:
            print(f"  Throughput: {format_mb(int(throughput_bps))}/s ({int(throughput_bps)} B/s)")
    upstream_samples = int(summary.get("upstream_setup_sample_count", 0))
    if upstream_samples:
        print(
            f"  Upstream setup: avg {summary.get('upstream_setup_ms_avg')} ms, "
            f"max {summary.get('upstream_setup_ms_max')} ms ({upstream_samples} samples)"
        )


def load_jsonl_records(
    log_file: Path | None,
    *,
    log_invalid: bool = False,
    allow_missing: bool = False,
    debug_label: str = "jsonl",
):
    records = []
    invalid_lines = 0

    if log_file is None:
        return records, invalid_lines

    try:
        with log_file.open("r", encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, start=1):
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    records.append(json.loads(stripped))
                except json.JSONDecodeError:
                    invalid_lines += 1
                    if log_invalid:
                        debug_log(
                            debug_label,
                            f"skipping invalid JSON line {line_number} from {log_file}",
                            level="WARNING",
                        )
    except FileNotFoundError:
        if allow_missing:
            return records, invalid_lines
        raise

    return records, invalid_lines


def load_usage_records(log_file: Path, *, log_invalid: bool = True, allow_missing: bool = False):
    try:
        return load_jsonl_records(
            log_file,
            log_invalid=log_invalid,
            allow_missing=allow_missing,
            debug_label="usage-analyze",
        )
    except FileNotFoundError as exc:
        raise SystemExit(f"Error: usage log file not found: {log_file}") from exc


def load_failure_records(log_file: Path | None, *, log_invalid: bool = False, allow_missing: bool = True):
    return load_jsonl_records(
        log_file,
        log_invalid=log_invalid,
        allow_missing=allow_missing,
        debug_label="failure-log",
    )


def first_query_value(query: dict[str, list[str]], key: str) -> str | None:
    values = query.get(key)
    if not values:
        return None
    return values[0]


def normalize_history_filter(value: str | None) -> str | None:
    if value in {None, "", "all"}:
        return None
    return value


def parse_usage_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def summarize_failures_by_host(failures, ignored_hosts):
    ignored_set = {normalize_host(host) for host in ignored_hosts}
    visible_groups = {}
    ignored_groups = {}

    for failure in failures:
        host = normalize_host(failure.get("host") or "")
        domain = summarize_domain(host)
        group_key = domain or host or failure.get("destination", "unknown")
        target_groups = ignored_groups if group_key in ignored_set else visible_groups
        group = target_groups.setdefault(
            group_key,
            {
                "group_key": group_key,
                "domain": domain or None,
                "host": host or None,
                "latest_timestamp": failure["timestamp"],
                "latest_error": failure["error"],
                "latest_destination": failure["destination"],
                "route_label": failure.get("route_label", "direct"),
                "count": 0,
                "clients": set(),
                "methods": set(),
                "hosts": set(),
            },
        )
        group["count"] += 1
        group["clients"].add(failure["client"])
        group["methods"].add(failure["method"])
        if host:
            group["hosts"].add(host)
        if failure["timestamp"] > group["latest_timestamp"]:
            group["latest_timestamp"] = failure["timestamp"]
            group["latest_error"] = failure["error"]
            group["latest_destination"] = failure["destination"]
            group["route_label"] = failure.get("route_label", "direct")
            group["host"] = host or None

    def finalize(groups):
        items = []
        for group in groups.values():
            host_list = sorted(group["hosts"])
            items.append(
                {
                    "group_key": group["group_key"],
                    "domain": group["domain"] or group["group_key"],
                    "host": group["host"],
                    "latest_timestamp": group["latest_timestamp"],
                    "latest_error": group["latest_error"],
                    "latest_destination": group["latest_destination"],
                    "route_label": group["route_label"],
                    "count": group["count"],
                    "client_count": len(group["clients"]),
                    "method_list": sorted(group["methods"]),
                    "host_count": len(host_list),
                    "host_list_preview": host_list[:3],
                }
            )
        items.sort(key=lambda item: (-item["count"], item["latest_timestamp"]), reverse=False)
        items.sort(key=lambda item: item["latest_timestamp"], reverse=True)
        return items

    visible_items = finalize(visible_groups)
    ignored_items = finalize(ignored_groups)
    return {
        "visible_items": visible_items,
        "ignored_items": ignored_items,
        "visible_total": len(visible_items),
        "ignored_total": len(ignored_items),
    }


def config_rule_matches_failure(config, failure) -> bool:
    host = normalize_host(failure.get("host") or "")
    if not host:
        return False
    for rule in config.get("rules", []):
        if not rule.get("enabled", True):
            continue
        if rule_matches_host(rule, host):
            return True
    return False


def resolve_history_timezone(timezone_name: str | None = None, timezone_offset_minutes=None):
    normalized_name = str(timezone_name or "").strip()
    if normalized_name and ZoneInfo is not None:
        try:
            return ZoneInfo(normalized_name)
        except ZoneInfoNotFoundError:
            pass

    try:
        offset_minutes = int(timezone_offset_minutes)
    except (TypeError, ValueError):
        offset_minutes = None
    if offset_minutes is not None and -14 * 60 <= offset_minutes <= 14 * 60:
        return timezone(timedelta(minutes=offset_minutes))

    return datetime.now().astimezone().tzinfo or timezone.utc


def bucket_datetime(value: datetime, bucket_seconds: int, history_timezone=None) -> datetime:
    if value.tzinfo is None:
        value = value.replace(tzinfo=history_timezone or datetime.now().astimezone().tzinfo)
    elif history_timezone is not None:
        value = value.astimezone(history_timezone)

    normalized_bucket_seconds = max(1, int(bucket_seconds))
    if normalized_bucket_seconds >= 86400 and normalized_bucket_seconds % 86400 == 0:
        return value.replace(hour=0, minute=0, second=0, microsecond=0)

    if normalized_bucket_seconds >= 3600 and normalized_bucket_seconds % 3600 == 0:
        bucket_hours = max(1, normalized_bucket_seconds // 3600)
        return value.replace(
            hour=(value.hour // bucket_hours) * bucket_hours,
            minute=0,
            second=0,
            microsecond=0,
        )

    if normalized_bucket_seconds >= 60 and normalized_bucket_seconds % 60 == 0:
        bucket_minutes = max(1, normalized_bucket_seconds // 60)
        return value.replace(
            minute=(value.minute // bucket_minutes) * bucket_minutes,
            second=0,
            microsecond=0,
        )

    midnight = value.replace(hour=0, minute=0, second=0, microsecond=0)
    seconds_since_midnight = int((value - midnight).total_seconds())
    bucket_offset = seconds_since_midnight // normalized_bucket_seconds * normalized_bucket_seconds
    return midnight + timedelta(seconds=bucket_offset)


def add_usage_to_summary(
    summary,
    *,
    uploaded_bytes: int,
    downloaded_bytes: int,
    total_bytes: int,
    duration_ms=None,
    upstream_setup_ms=None,
    relay_ms=None,
):
    summary["count"] += 1
    summary["uploaded_bytes"] += uploaded_bytes
    summary["downloaded_bytes"] += downloaded_bytes
    summary["total_bytes"] += total_bytes
    add_performance_to_summary(
        summary,
        total_bytes=total_bytes,
        duration_ms=duration_ms,
        upstream_setup_ms=upstream_setup_ms,
        relay_ms=relay_ms,
    )


def build_history_period_totals(now: datetime):
    start_of_day = now.replace(hour=0, minute=0, second=0, microsecond=0)
    start_of_week = (start_of_day - timedelta(days=start_of_day.weekday())).replace(
        hour=0,
        minute=0,
        second=0,
        microsecond=0,
    )
    start_of_month = start_of_day.replace(day=1)
    start_of_year = start_of_day.replace(month=1, day=1)
    return [
        {
            "key": "day",
            "title": "Today",
            "start_at": start_of_day.isoformat(),
            "summary": empty_usage_summary(),
        },
        {
            "key": "week",
            "title": "This week",
            "start_at": start_of_week.isoformat(),
            "summary": empty_usage_summary(),
        },
        {
            "key": "month",
            "title": "This month",
            "start_at": start_of_month.isoformat(),
            "summary": empty_usage_summary(),
        },
        {
            "key": "year",
            "title": "This year",
            "start_at": start_of_year.isoformat(),
            "summary": empty_usage_summary(),
        },
    ]


def summarize_history_records(
    records,
    *,
    invalid_lines: int,
    range_key: str,
    proxy_type: str | None = None,
    client: str | None = None,
    upstream_proxy_id: str | None = None,
    timezone_name: str | None = None,
    timezone_offset_minutes=None,
    now: datetime | None = None,
):
    config = HISTORY_RANGE_OPTIONS.get(range_key, HISTORY_RANGE_OPTIONS[HISTORY_DEFAULT_RANGE])
    history_timezone = resolve_history_timezone(timezone_name, timezone_offset_minutes)
    now = (now or datetime.now(history_timezone)).astimezone(history_timezone)
    window = config["window"]
    cutoff = now - window if window is not None else None

    summary = empty_usage_summary()
    buckets = {}
    destinations = {}
    period_totals = build_history_period_totals(now)
    period_starts = {
        item["key"]: parse_usage_timestamp(item["start_at"]) for item in period_totals
    }
    period_totals_by_key = {item["key"]: item for item in period_totals}
    client_period_totals = {}
    available_proxy_types = set()
    available_clients = set()
    available_upstream_proxies = set()
    selected_timestamps = []

    for record in records:
        record_proxy_type = str(record.get("proxy_type", "unknown") or "unknown")
        record_client = str(record.get("client", "unknown") or "unknown")
        record_upstream_proxy_id = str(record.get("upstream_proxy_id") or "").strip()
        available_proxy_types.add(record_proxy_type)
        available_clients.add(record_client)
        if record_upstream_proxy_id:
            available_upstream_proxies.add(record_upstream_proxy_id)

        if proxy_type is not None and record_proxy_type != proxy_type:
            continue
        if client is not None and record_client != client:
            continue
        if upstream_proxy_id is not None and record_upstream_proxy_id != upstream_proxy_id:
            continue

        timestamp = parse_usage_timestamp(record.get("timestamp"))
        if timestamp is None:
            continue
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=datetime.now().astimezone().tzinfo)
        timestamp = timestamp.astimezone(history_timezone)

        uploaded_bytes = int(record.get("uploaded_bytes", 0))
        downloaded_bytes = int(record.get("downloaded_bytes", 0))
        total_bytes = int(record.get("total_bytes", uploaded_bytes + downloaded_bytes))
        duration_ms = record.get("duration_ms")
        upstream_setup_ms = record.get("upstream_setup_ms")
        relay_ms = record.get("relay_ms")

        client_period_summary = client_period_totals.setdefault(
            record_client,
            {
                "client": record_client,
                "summary": empty_usage_summary(),
                "period_totals": {
                    item["key"]: empty_usage_summary()
                    for item in period_totals
                },
                "proxy_types": set(),
                "last_seen_at": None,
                "_last_seen_dt": None,
            },
        )
        client_period_summary["proxy_types"].add(record_proxy_type)
        last_seen_dt = client_period_summary.get("_last_seen_dt")
        if last_seen_dt is None or timestamp > last_seen_dt:
            client_period_summary["_last_seen_dt"] = timestamp
            client_period_summary["last_seen_at"] = timestamp.isoformat()
        add_usage_to_summary(
            client_period_summary["summary"],
            uploaded_bytes=uploaded_bytes,
            downloaded_bytes=downloaded_bytes,
            total_bytes=total_bytes,
            duration_ms=duration_ms,
            upstream_setup_ms=upstream_setup_ms,
            relay_ms=relay_ms,
        )

        for period_key, period_start in period_starts.items():
            if period_start is not None and timestamp >= period_start:
                add_usage_to_summary(
                    period_totals_by_key[period_key]["summary"],
                    uploaded_bytes=uploaded_bytes,
                    downloaded_bytes=downloaded_bytes,
                    total_bytes=total_bytes,
                    duration_ms=duration_ms,
                    upstream_setup_ms=upstream_setup_ms,
                    relay_ms=relay_ms,
                )
                add_usage_to_summary(
                    client_period_summary["period_totals"][period_key],
                    uploaded_bytes=uploaded_bytes,
                    downloaded_bytes=downloaded_bytes,
                    total_bytes=total_bytes,
                    duration_ms=duration_ms,
                    upstream_setup_ms=upstream_setup_ms,
                    relay_ms=relay_ms,
                )

        if cutoff is not None and timestamp < cutoff:
            continue

        add_usage_to_summary(
            summary,
            uploaded_bytes=uploaded_bytes,
            downloaded_bytes=downloaded_bytes,
            total_bytes=total_bytes,
            duration_ms=duration_ms,
            upstream_setup_ms=upstream_setup_ms,
            relay_ms=relay_ms,
        )
        selected_timestamps.append(timestamp)

        bucket_start = bucket_datetime(timestamp, config["bucket_seconds"], history_timezone)
        bucket_key = bucket_start.isoformat()
        bucket_summary = buckets.setdefault(
            bucket_key,
            {
                "start_at": bucket_key,
                "label": bucket_start.strftime(config["label_format"]),
                "count": 0,
                "uploaded_bytes": 0,
                "downloaded_bytes": 0,
                "total_bytes": 0,
            },
        )
        add_usage_to_summary(
            bucket_summary,
            uploaded_bytes=uploaded_bytes,
            downloaded_bytes=downloaded_bytes,
            total_bytes=total_bytes,
            duration_ms=duration_ms,
            upstream_setup_ms=upstream_setup_ms,
            relay_ms=relay_ms,
        )

        destination = record.get("destination", "unknown")
        destination_summary = destinations.setdefault(
            destination,
            {
                "destination": destination,
                "count": 0,
                "uploaded_bytes": 0,
                "downloaded_bytes": 0,
                "total_bytes": 0,
            },
        )
        add_usage_to_summary(
            destination_summary,
            uploaded_bytes=uploaded_bytes,
            downloaded_bytes=downloaded_bytes,
            total_bytes=total_bytes,
            duration_ms=duration_ms,
            upstream_setup_ms=upstream_setup_ms,
            relay_ms=relay_ms,
        )

    series = []
    if selected_timestamps:
        if cutoff is not None:
            start_bucket = bucket_datetime(cutoff, config["bucket_seconds"], history_timezone)
        else:
            start_bucket = bucket_datetime(min(selected_timestamps), config["bucket_seconds"], history_timezone)
        end_bucket = bucket_datetime(max(selected_timestamps), config["bucket_seconds"], history_timezone)
        cursor = start_bucket
        while cursor <= end_bucket:
            bucket_key = cursor.isoformat()
            series.append(
                buckets.get(
                    bucket_key,
                    {
                        "start_at": bucket_key,
                        "label": cursor.strftime(config["label_format"]),
                        "count": 0,
                        "uploaded_bytes": 0,
                        "downloaded_bytes": 0,
                        "total_bytes": 0,
                    },
                )
            )
            cursor += timedelta(seconds=config["bucket_seconds"])

    top_destinations = sorted(
        destinations.values(),
        key=lambda item: (-item["total_bytes"], -item["count"], item["destination"]),
    )[:HISTORY_TOP_DESTINATIONS_LIMIT]
    client_period_totals_rows = []
    for item in client_period_totals.values():
        item["proxy_types"] = sorted(item["proxy_types"])
        item.pop("_last_seen_dt", None)
        client_period_totals_rows.append(item)
    client_period_totals_rows.sort(
        key=lambda item: (
            -int((item.get("period_totals") or {}).get("year", {}).get("total_bytes", 0)),
            -int((item.get("period_totals") or {}).get("month", {}).get("total_bytes", 0)),
            -int((item.get("period_totals") or {}).get("week", {}).get("total_bytes", 0)),
            -int((item.get("period_totals") or {}).get("day", {}).get("total_bytes", 0)),
            -int((item.get("summary") or {}).get("total_bytes", 0)),
            str(item.get("client") or ""),
        )
    )

    return {
        "range": range_key if range_key in HISTORY_RANGE_OPTIONS else HISTORY_DEFAULT_RANGE,
        "range_title": config["title"],
        "proxy_type": proxy_type or "all",
        "client": client or "all",
        "upstream_proxy_id": upstream_proxy_id or "all",
        "timezone": str(timezone_name or getattr(history_timezone, "key", "") or history_timezone.tzname(now) or ""),
        "summary": summary,
        "series": series,
        "period_totals": period_totals,
        "client_period_totals": client_period_totals_rows,
        "top_destinations": top_destinations,
        "invalid_lines": invalid_lines,
        "available_proxy_types": sorted(available_proxy_types),
        "available_clients": sorted(available_clients),
        "available_upstream_proxies": sorted(available_upstream_proxies),
        "has_log_data": bool(records),
        "matched_records": summary["count"],
        "time_range": {
            "from": min(selected_timestamps).isoformat() if selected_timestamps else None,
            "to": max(selected_timestamps).isoformat() if selected_timestamps else None,
        },
    }
