from __future__ import annotations

import ipaddress
import json
import socket
import uuid
from datetime import datetime, timedelta
from pathlib import Path

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
    }


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
        summary["count"] += 1
        summary["uploaded_bytes"] += int(record.get("uploaded_bytes", 0))
        summary["downloaded_bytes"] += int(record.get("downloaded_bytes", 0))
        summary["total_bytes"] += int(record.get("total_bytes", 0))
    return totals


def empty_client_usage_summary():
    return {
        "count": 0,
        "uploaded_bytes": 0,
        "downloaded_bytes": 0,
        "total_bytes": 0,
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


def normalize_client_limit_target(value: str) -> str:
    target = str(value).strip()
    if not target:
        return ""

    try:
        return str(ipaddress.ip_address(target))
    except ValueError:
        pass

    try:
        return str(ipaddress.ip_network(target, strict=False))
    except ValueError as exc:
        raise ValueError(f"invalid client IP or CIDR '{value}'") from exc


def client_limit_target_specificity(target: str) -> int:
    if "/" in target:
        return ipaddress.ip_network(target, strict=False).prefixlen
    return ipaddress.ip_address(target).max_prefixlen


def client_ip_matches_limit_target(client_ip: str, target: str) -> bool:
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
        "client_traffic_limits": [],
        "client_traffic_exemptions": [],
        "auto_proxy_failures": {
            "enabled": False,
        },
        "upstream": {
            "enabled": False,
            "type": "http",
            "host": "127.0.0.1",
            "port": HTTPS_DEFAULT_PORT,
        },
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

        normalized_rules.append(
            {
                "pattern": pattern,
                "match": match_type,
                "action": action,
                "enabled": bool(rule_payload.get("enabled", True)),
                "note": note,
                "source": source,
                "duration": duration,
                "expires_at": expires_at.isoformat() if expires_at is not None else None,
            }
        )

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

    auto_proxy_failures_payload = payload.get("auto_proxy_failures") or {}
    if auto_proxy_failures_payload is None:
        auto_proxy_failures_payload = {}
    if not isinstance(auto_proxy_failures_payload, dict):
        raise ValueError("router auto_proxy_failures must be an object")

    default_client_traffic_limit_payload = payload.get("default_client_traffic_limit") or {}
    if default_client_traffic_limit_payload is None:
        default_client_traffic_limit_payload = {}
    if not isinstance(default_client_traffic_limit_payload, dict):
        raise ValueError("router default_client_traffic_limit must be an object")

    client_traffic_limits_payload = payload.get("client_traffic_limits") or []
    if not isinstance(client_traffic_limits_payload, list):
        raise ValueError("router client_traffic_limits must be an array")

    client_traffic_exemptions_payload = payload.get("client_traffic_exemptions") or []
    if not isinstance(client_traffic_exemptions_payload, list):
        raise ValueError("router client_traffic_exemptions must be an array")

    upstream_type = str(upstream_payload.get("type", default_config["upstream"]["type"])).strip().lower()
    if upstream_type not in UPSTREAM_PROXY_TYPES:
        raise ValueError(f"router upstream type must be one of: {', '.join(sorted(UPSTREAM_PROXY_TYPES))}")

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

    normalized_default_client_traffic_limit = {
        "enabled": bool(
            default_client_traffic_limit_payload.get(
                "enabled",
                default_config["default_client_traffic_limit"]["enabled"],
            )
        ),
        "max_past_hour_mb": normalize_traffic_limit_mb(
            default_client_traffic_limit_payload.get(
                "max_past_hour_mb",
                default_config["default_client_traffic_limit"]["max_past_hour_mb"],
            ),
            field_name="router default_client_traffic_limit max_past_hour_mb",
        ),
        "max_past_3h_mb": normalize_traffic_limit_mb(
            default_client_traffic_limit_payload.get(
                "max_past_3h_mb",
                default_config["default_client_traffic_limit"]["max_past_3h_mb"],
            ),
            field_name="router default_client_traffic_limit max_past_3h_mb",
        ),
        "note": str(
            default_client_traffic_limit_payload.get(
                "note",
                default_config["default_client_traffic_limit"]["note"],
            )
        ).strip(),
    }
    validate_traffic_limit_definition(
        enabled=normalized_default_client_traffic_limit["enabled"],
        max_past_hour_mb=normalized_default_client_traffic_limit["max_past_hour_mb"],
        max_past_3h_mb=normalized_default_client_traffic_limit["max_past_3h_mb"],
        field_prefix="router default_client_traffic_limit",
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

    if not upstream_enabled:
        routing_targets = [normalized_routing_defaults] + normalized_routing_profiles
        for target in routing_targets:
            if target["default_action"] == "proxy" or any(rule["action"] == "proxy" for rule in target["rules"]):
                raise ValueError("router upstream must be enabled before any rule or default action can use proxy")

    return {
        "default_action": normalized_routing_defaults["default_action"],
        "ignored_failure_hosts": normalized_routing_defaults["ignored_failure_hosts"],
        "default_client_traffic_limit": normalized_default_client_traffic_limit,
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
        "upstream": {
            "enabled": upstream_enabled,
            "type": upstream_type,
            "host": upstream_host,
            "port": upstream_port,
        },
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


def redact_header_value(header_name: str, value: str) -> str:
    if header_name.lower() in SENSITIVE_HEADER_NAMES:
        return "<redacted>"
    return truncate_for_log(value)


def format_headers_for_log(headers) -> str:
    items = []
    for key, value in headers.items():
        items.append(f"{key}={redact_header_value(key, value)}")
    return ", ".join(items) if items else "<none>"


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


def resolve_router_config_path(path_text: str | None) -> Path:
    if not path_text:
        return DEFAULT_ROUTER_CONFIG_PATH
    return Path(path_text).expanduser()


def format_mb(byte_count: int) -> str:
    return f"{byte_count / BYTES_IN_MB:.2f} MB"


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
    summary = {
        "count": 0,
        "uploaded_bytes": 0,
        "downloaded_bytes": 0,
        "total_bytes": 0,
    }
    for record in records:
        summary["count"] += 1
        summary["uploaded_bytes"] += int(record.get("uploaded_bytes", 0))
        summary["downloaded_bytes"] += int(record.get("downloaded_bytes", 0))
        summary["total_bytes"] += int(record.get("total_bytes", 0))
    return summary


def print_usage_summary(label: str, summary):
    print(f"{label}:")
    print(f"  Records: {summary['count']}")
    print(f"  Upload:   {format_mb(summary['uploaded_bytes'])} ({summary['uploaded_bytes']} bytes)")
    print(f"  Download: {format_mb(summary['downloaded_bytes'])} ({summary['downloaded_bytes']} bytes)")
    print(f"  Total:    {format_mb(summary['total_bytes'])} ({summary['total_bytes']} bytes)")


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


def bucket_datetime(value: datetime, bucket_seconds: int) -> datetime:
    bucket_epoch = int(value.timestamp()) // bucket_seconds * bucket_seconds
    return datetime.fromtimestamp(bucket_epoch, tz=value.tzinfo)


def summarize_history_records(
    records,
    *,
    invalid_lines: int,
    range_key: str,
    proxy_type: str | None = None,
    client: str | None = None,
):
    config = HISTORY_RANGE_OPTIONS.get(range_key, HISTORY_RANGE_OPTIONS[HISTORY_DEFAULT_RANGE])
    now = datetime.now().astimezone()
    window = config["window"]
    cutoff = now - window if window is not None else None

    summary = empty_usage_summary()
    buckets = {}
    destinations = {}
    available_proxy_types = set()
    selected_timestamps = []

    for record in records:
        record_proxy_type = record.get("proxy_type", "unknown")
        available_proxy_types.add(record_proxy_type)

        if proxy_type is not None and record_proxy_type != proxy_type:
            continue
        if client is not None and record.get("client") != client:
            continue

        timestamp = parse_usage_timestamp(record.get("timestamp"))
        if timestamp is None:
            continue
        if cutoff is not None and timestamp < cutoff:
            continue

        uploaded_bytes = int(record.get("uploaded_bytes", 0))
        downloaded_bytes = int(record.get("downloaded_bytes", 0))
        total_bytes = int(record.get("total_bytes", uploaded_bytes + downloaded_bytes))

        summary["count"] += 1
        summary["uploaded_bytes"] += uploaded_bytes
        summary["downloaded_bytes"] += downloaded_bytes
        summary["total_bytes"] += total_bytes
        selected_timestamps.append(timestamp)

        bucket_start = bucket_datetime(timestamp, config["bucket_seconds"])
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
        bucket_summary["count"] += 1
        bucket_summary["uploaded_bytes"] += uploaded_bytes
        bucket_summary["downloaded_bytes"] += downloaded_bytes
        bucket_summary["total_bytes"] += total_bytes

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
        destination_summary["count"] += 1
        destination_summary["uploaded_bytes"] += uploaded_bytes
        destination_summary["downloaded_bytes"] += downloaded_bytes
        destination_summary["total_bytes"] += total_bytes

    series = []
    if selected_timestamps:
        if cutoff is not None:
            start_bucket = bucket_datetime(cutoff, config["bucket_seconds"])
        else:
            start_bucket = bucket_datetime(min(selected_timestamps), config["bucket_seconds"])
        end_bucket = bucket_datetime(max(selected_timestamps), config["bucket_seconds"])
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

    return {
        "range": range_key if range_key in HISTORY_RANGE_OPTIONS else HISTORY_DEFAULT_RANGE,
        "range_title": config["title"],
        "proxy_type": proxy_type or "all",
        "client": client or "all",
        "summary": summary,
        "series": series,
        "top_destinations": top_destinations,
        "invalid_lines": invalid_lines,
        "available_proxy_types": sorted(available_proxy_types),
        "has_log_data": bool(records),
        "matched_records": summary["count"],
        "time_range": {
            "from": min(selected_timestamps).isoformat() if selected_timestamps else None,
            "to": max(selected_timestamps).isoformat() if selected_timestamps else None,
        },
    }
