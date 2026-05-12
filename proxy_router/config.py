from __future__ import annotations

import json
import secrets
import shutil
import socket
import struct
import subprocess
import threading
import uuid
from datetime import datetime
from pathlib import Path

from .constants import *
from .util import *


class RuleSuggestionConflictError(ValueError):
    def __init__(self, message: str, *, rule: dict | None = None, conflicts: list[dict] | None = None):
        super().__init__(message)
        self.rule = rule or {}
        self.conflicts = conflicts or []


def normalize_rule_suggestion_rule(payload) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("rule suggestion rule must be an object")

    pattern = normalize_rule_pattern(str(payload.get("pattern", "")))
    if not pattern:
        raise ValueError("rule suggestion pattern is required")

    match_type = str(payload.get("match", "suffix")).strip().lower()
    if match_type not in RULE_MATCH_TYPES:
        raise ValueError(f"rule suggestion match must be one of: {', '.join(sorted(RULE_MATCH_TYPES))}")

    action = str(payload.get("action", "proxy")).strip().lower()
    if action not in RULE_ROUTE_ACTIONS:
        raise ValueError(f"rule suggestion action must be one of: {', '.join(sorted(RULE_ROUTE_ACTIONS))}")

    duration = str(payload.get("duration", "always")).strip().lower()
    if duration not in RULE_DURATION_SECONDS:
        raise ValueError(f"rule suggestion duration must be one of: {', '.join(RULE_DURATION_ORDER)}")

    normalized = {
        "pattern": pattern,
        "match": match_type,
        "action": action,
        "enabled": True,
        "note": str(payload.get("note", "")).strip(),
        "source": "manual",
        "duration": duration,
        "expires_at": None,
    }
    proxy_id = normalize_upstream_proxy_id(payload.get("proxy_id"))
    if action == "proxy" and proxy_id:
        normalized["proxy_id"] = proxy_id
    return normalized


def normalize_rule_suggestion_status(value: str | None) -> str:
    normalized = str(value or "pending").strip().lower()
    return normalized if normalized in {"pending", "approved", "rejected"} else "pending"


def sanitize_rule_suggestion(item) -> dict | None:
    if not isinstance(item, dict):
        return None
    suggestion_id = str(item.get("id") or "").strip()
    if not suggestion_id:
        return None
    try:
        rule = normalize_rule_suggestion_rule(item.get("rule") or {})
    except ValueError:
        return None
    status = normalize_rule_suggestion_status(item.get("status"))
    return {
        "id": suggestion_id,
        "status": status,
        "requested_at": str(item.get("requested_at") or "").strip(),
        "resolved_at": str(item.get("resolved_at") or "").strip() or None,
        "requester": str(item.get("requester") or "").strip(),
        "requester_username": str(item.get("requester_username") or "").strip(),
        "requester_label": str(item.get("requester_label") or "").strip(),
        "requester_ip": str(item.get("requester_ip") or "").strip(),
        "profile_id": str(item.get("profile_id") or DEFAULT_ROUTING_PROFILE_ID).strip() or DEFAULT_ROUTING_PROFILE_ID,
        "profile_name": str(item.get("profile_name") or "Shared").strip() or "Shared",
        "rule": rule,
        "request_note": str(item.get("request_note") or "").strip(),
        "conflict_confirmed": bool(item.get("conflict_confirmed", False)),
        "conflicts": list(item.get("conflicts") or []),
        "admin_message": str(item.get("admin_message") or "").strip(),
    }


class RuleSuggestionManager:
    def __init__(self, state_file: Path, router_config, *, change_callback=None):
        self.state_file = state_file
        self.router_config = router_config
        self._change_callback = change_callback
        self._lock = threading.Lock()
        self._suggestions = []
        self._load()

    def _notify_change(self):
        if callable(self._change_callback):
            self._change_callback("rule-suggestions")

    def _load(self):
        try:
            content = self.state_file.read_text(encoding="utf-8")
        except FileNotFoundError:
            self._suggestions = []
            return
        if not content.strip():
            self._suggestions = []
            return
        payload = json.loads(content)
        raw_items = payload.get("suggestions") if isinstance(payload, dict) else payload
        self._suggestions = [
            suggestion
            for suggestion in (sanitize_rule_suggestion(item) for item in (raw_items or []))
            if suggestion is not None
        ]

    def _write_locked(self):
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        payload = {"suggestions": self._suggestions}
        self.state_file.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def snapshot(self, *, client: str | None = None, include_current_conflicts: bool = False) -> list[dict]:
        normalized_client = str(client or "").strip()
        with self._lock:
            suggestions = json.loads(json.dumps(self._suggestions))
        if normalized_client:
            suggestions = [item for item in suggestions if item.get("requester") == normalized_client]
        suggestions.sort(key=lambda item: str(item.get("requested_at") or ""), reverse=True)
        if include_current_conflicts:
            for item in suggestions:
                if item.get("status") != "pending":
                    item["current_conflicts"] = []
                    continue
                try:
                    item["current_conflicts"] = self.router_config.rule_issues_for_candidate(
                        item.get("profile_id"),
                        item.get("rule") or {},
                    )
                except ValueError as exc:
                    item["current_conflicts"] = []
                    item["current_error"] = str(exc)
        return suggestions

    def clear_history(self, *, client: str | None = None) -> dict:
        normalized_client = str(client or "").strip()
        with self._lock:
            before_count = len(self._suggestions)
            if normalized_client:
                self._suggestions = [
                    item for item in self._suggestions if item.get("requester") != normalized_client
                ]
            else:
                self._suggestions = []
            removed_count = before_count - len(self._suggestions)
            remaining_count = len(self._suggestions)
            if removed_count:
                self._write_locked()
        if removed_count:
            self._notify_change()
        return {
            "removed": removed_count,
            "remaining": remaining_count,
        }

    def delete(self, suggestion_id: str, *, client: str | None = None) -> dict:
        normalized_id = str(suggestion_id or "").strip()
        if not normalized_id:
            raise KeyError(normalized_id)
        normalized_client = str(client or "").strip()
        with self._lock:
            suggestion_index = next(
                (
                    index
                    for index, item in enumerate(self._suggestions)
                    if item.get("id") == normalized_id
                ),
                None,
            )
            if suggestion_index is None:
                raise KeyError(normalized_id)
            suggestion = self._suggestions[suggestion_index]
            if normalized_client and suggestion.get("requester") != normalized_client:
                raise PermissionError("rule suggestion belongs to another requester")
            deleted = self._suggestions.pop(suggestion_index)
            remaining_count = len(self._suggestions)
            self._write_locked()
        self._notify_change()
        return {
            "suggestion": json.loads(json.dumps(deleted)),
            "remaining": remaining_count,
        }

    def submit(
        self,
        *,
        requester_identity: dict,
        requester_ip: str,
        profile: dict,
        rule_payload,
        request_note: str,
        confirm_conflicts: bool = False,
    ) -> dict:
        requester = str((requester_identity or {}).get("id") or "").strip()
        if not requester.startswith("user:"):
            raise PermissionError("only authenticated users can suggest routing rules")

        rule = normalize_rule_suggestion_rule(rule_payload)
        profile_id = str((profile or {}).get("id") or DEFAULT_ROUTING_PROFILE_ID).strip() or DEFAULT_ROUTING_PROFILE_ID
        profile_name = str((profile or {}).get("name") or "Shared").strip() or "Shared"
        conflicts = self.router_config.rule_issues_for_candidate(profile_id, rule)
        if conflicts and not confirm_conflicts:
            raise RuleSuggestionConflictError(
                "rule suggestion conflicts with existing routing rules",
                rule=rule,
                conflicts=conflicts,
            )

        suggestion = {
            "id": uuid.uuid4().hex,
            "status": "pending",
            "requested_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "resolved_at": None,
            "requester": requester,
            "requester_username": str((requester_identity or {}).get("username") or "").strip(),
            "requester_label": str((requester_identity or {}).get("label") or "").strip(),
            "requester_ip": str(requester_ip or "").strip(),
            "profile_id": profile_id,
            "profile_name": profile_name,
            "rule": rule,
            "request_note": str(request_note or "").strip(),
            "conflict_confirmed": bool(conflicts and confirm_conflicts),
            "conflicts": conflicts,
            "admin_message": "",
        }
        with self._lock:
            self._suggestions.append(suggestion)
            self._write_locked()
        self._notify_change()
        return json.loads(json.dumps(suggestion))

    def approve(self, suggestion_id: str) -> dict:
        normalized_id = str(suggestion_id or "").strip()
        with self._lock:
            suggestion = next((item for item in self._suggestions if item.get("id") == normalized_id), None)
            if suggestion is None:
                raise KeyError(normalized_id)
            if suggestion.get("status") != "pending":
                raise ValueError("only pending rule suggestions can be approved")
            pending = json.loads(json.dumps(suggestion))

        conflicts = self.router_config.rule_issues_for_candidate(pending.get("profile_id"), pending.get("rule") or {})
        if conflicts:
            raise RuleSuggestionConflictError(
                "rule suggestion still conflicts with existing routing rules",
                rule=pending.get("rule") or {},
                conflicts=conflicts,
            )

        approved_rule = dict(pending.get("rule") or {})
        if not str(approved_rule.get("note") or "").strip():
            requester = pending.get("requester") or "authenticated user"
            request_note = str(pending.get("request_note") or "").strip()
            approved_rule["note"] = request_note or f"suggested by {requester}"
        saved_config = self.router_config.add_manual_rule(pending.get("profile_id"), approved_rule)

        with self._lock:
            suggestion = next((item for item in self._suggestions if item.get("id") == normalized_id), None)
            if suggestion is None:
                raise KeyError(normalized_id)
            suggestion["status"] = "approved"
            suggestion["resolved_at"] = datetime.now().astimezone().isoformat(timespec="seconds")
            suggestion["admin_message"] = ""
            self._write_locked()
            saved_suggestion = json.loads(json.dumps(suggestion))
        self._notify_change()
        return {"suggestion": saved_suggestion, "router_config": saved_config}

    def reject(self, suggestion_id: str, *, message: str = "") -> dict:
        normalized_id = str(suggestion_id or "").strip()
        with self._lock:
            suggestion = next((item for item in self._suggestions if item.get("id") == normalized_id), None)
            if suggestion is None:
                raise KeyError(normalized_id)
            if suggestion.get("status") != "pending":
                raise ValueError("only pending rule suggestions can be rejected")
            suggestion["status"] = "rejected"
            suggestion["resolved_at"] = datetime.now().astimezone().isoformat(timespec="seconds")
            suggestion["admin_message"] = str(message or "").strip()
            self._write_locked()
            saved_suggestion = json.loads(json.dumps(suggestion))
        self._notify_change()
        return saved_suggestion


class NetworkProfileMonitor:
    def __init__(
        self,
        poll_interval_seconds: float = NETWORK_PROFILE_POLL_INTERVAL_SECONDS,
        *,
        change_callback=None,
    ):
        self.poll_interval_seconds = max(1.0, float(poll_interval_seconds))
        self._change_callback = change_callback
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._last_error = None
        now_text = datetime.now().astimezone().isoformat(timespec="seconds")
        self._state = {
            "internet_key": "",
            "internet_label": "",
            "vpn_keys": [],
            "vpn_labels": [],
            "route_interface": "",
            "route_gateway": "",
            "source": "unavailable",
            "signature": None,
            "signature_key": None,
            "detected_at": now_text,
            "last_changed_at": now_text,
            "available": False,
            "error": None,
        }
        try:
            self._state = self._detect_state()
        except Exception as exc:
            self._state = self._build_unavailable_state(error=repr(exc))
        self._thread = threading.Thread(
            target=self._run,
            name="network-profile-monitor",
            daemon=True,
        )
        self._thread.start()

    def shutdown(self):
        self._stop_event.set()
        self._thread.join(timeout=2)

    def snapshot(self) -> dict:
        with self._lock:
            return json.loads(json.dumps(self._state))

    def _change_marker(self, state: dict) -> tuple:
        return (
            bool(state.get("available")),
            str(state.get("signature_key") or ""),
            str(state.get("internet_label") or ""),
            str(state.get("route_interface") or ""),
            str(state.get("route_gateway") or ""),
            tuple(state.get("vpn_keys") or []),
            tuple(state.get("vpn_labels") or []),
            str(state.get("error") or ""),
        )

    def _run(self):
        while not self._stop_event.wait(self.poll_interval_seconds):
            try:
                detected = self._detect_state()
            except Exception as exc:
                detected = self._build_unavailable_state(error=repr(exc))
            with self._lock:
                previous_marker = self._change_marker(self._state)
                current_marker = self._change_marker(detected)
                if previous_marker != current_marker:
                    detected["last_changed_at"] = datetime.now().astimezone().isoformat(timespec="seconds")
                else:
                    detected["last_changed_at"] = self._state.get("last_changed_at")
                self._state = detected
            if previous_marker != current_marker and callable(self._change_callback):
                self._change_callback("network-profile")

    def _run_command(self, arguments: list[str]):
        executable = arguments[0]
        resolved = shutil.which(executable)
        if not resolved:
            raise FileNotFoundError(executable)
        completed = subprocess.run(
            [resolved, *arguments[1:]],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
        if completed.returncode != 0:
            stderr_text = completed.stderr.strip() or completed.stdout.strip() or f"exit {completed.returncode}"
            raise OSError(f"{executable} failed: {stderr_text}")
        return completed.stdout

    def _build_unavailable_state(self, *, error: str | None = None) -> dict:
        now_text = datetime.now().astimezone().isoformat(timespec="seconds")
        return {
            "internet_key": "",
            "internet_label": "",
            "vpn_keys": [],
            "vpn_labels": [],
            "route_interface": "",
            "route_gateway": "",
            "source": "unavailable",
            "signature": None,
            "signature_key": None,
            "detected_at": now_text,
            "last_changed_at": now_text,
            "available": False,
            "error": error,
        }

    def _detect_default_route(self) -> dict:
        try:
            stdout = self._run_command(["ip", "-j", "route", "show", "default"])
        except (FileNotFoundError, OSError, subprocess.SubprocessError):
            return self._detect_default_route_from_procfs()

        payload = json.loads(stdout or "[]")
        if not isinstance(payload, list):
            return self._detect_default_route_from_procfs()

        preferred = None
        for route in payload:
            if not isinstance(route, dict):
                continue
            if route.get("dst") != "default":
                continue
            if route.get("family") == "inet":
                preferred = route
                break
            if preferred is None:
                preferred = route

        if preferred is None:
            return self._detect_default_route_from_procfs()

        return {
            "interface": str(preferred.get("dev") or "").strip(),
            "gateway": str(preferred.get("gateway") or "").strip(),
        }

    def _detect_default_route_from_procfs(self) -> dict:
        route_file = Path("/proc/net/route")
        try:
            lines = route_file.read_text(encoding="utf-8").splitlines()
        except OSError:
            return {}

        for line in lines[1:]:
            parts = line.split()
            if len(parts) < 4:
                continue

            interface, destination_hex, gateway_hex, flags_hex = parts[:4]
            if destination_hex != "00000000":
                continue

            try:
                flags = int(flags_hex, 16)
            except ValueError:
                continue

            if not (flags & 0x2):
                continue

            gateway = ""
            if gateway_hex != "00000000":
                try:
                    gateway = socket.inet_ntoa(struct.pack("<L", int(gateway_hex, 16)))
                except (OSError, struct.error, ValueError):
                    gateway = ""

            return {
                "interface": interface.strip(),
                "gateway": gateway.strip(),
            }

        return {}

    def _detect_nmcli_connections(self) -> list[dict]:
        stdout = self._run_command(
            ["nmcli", "--terse", "--escape", "yes", "-f", "NAME,UUID,DEVICE,TYPE", "connection", "show", "--active"]
        )
        connections = []
        for line in stdout.splitlines():
            if not line.strip():
                continue
            fields = split_nmcli_terse_fields(line.rstrip("\n"))
            while len(fields) < 4:
                fields.append("")
            name, connection_uuid, device, connection_type = fields[:4]
            normalized_type = connection_type.strip().lower()
            is_vpn = normalized_type in VPN_CONNECTION_TYPES or normalized_type.endswith("vpn")
            connections.append(
                {
                    "name": name.strip(),
                    "uuid": connection_uuid.strip(),
                    "device": device.strip(),
                    "type": normalized_type,
                    "is_vpn": is_vpn,
                }
            )
        return connections

    def _detect_vpn_interfaces_from_sysfs(self) -> list[dict]:
        interfaces_path = Path("/sys/class/net")
        try:
            entries = list(interfaces_path.iterdir())
        except OSError:
            return []

        connections = []
        for entry in entries:
            interface_name = entry.name.strip()
            if not interface_name or interface_name == "lo":
                continue

            normalized_name = interface_name.lower()
            if not normalized_name.startswith(VPN_INTERFACE_PREFIXES):
                continue

            try:
                operstate = (entry / "operstate").read_text(encoding="utf-8").strip().lower()
            except OSError:
                operstate = ""
            if operstate and operstate not in {"up", "unknown", "dormant"}:
                continue

            connections.append(
                {
                    "name": interface_name,
                    "uuid": interface_name,
                    "device": interface_name,
                    "type": "vpn",
                    "is_vpn": True,
                }
            )

        return sorted(connections, key=lambda item: item["name"])

    def _detect_state(self) -> dict:
        route_info = {}
        route_error = None
        try:
            route_info = self._detect_default_route()
        except Exception as exc:
            route_error = str(exc)

        connections = []
        nmcli_error = None
        try:
            connections = self._detect_nmcli_connections()
        except Exception as exc:
            nmcli_error = str(exc)
            connections = self._detect_vpn_interfaces_from_sysfs()

        interface = route_info.get("interface", "")
        gateway = route_info.get("gateway", "")
        base_connection = None
        vpn_connections = []
        if connections:
            for connection in connections:
                if connection["is_vpn"]:
                    vpn_connections.append(connection)
                    continue
                if interface and connection.get("device") == interface:
                    base_connection = connection
            if base_connection is None:
                for connection in connections:
                    if not connection["is_vpn"]:
                        base_connection = connection
                        break

        internet_key = ""
        internet_label = ""
        source = "route"
        if base_connection is not None:
            internet_key = base_connection.get("uuid") or base_connection.get("name") or interface or gateway
            internet_label = base_connection.get("name") or base_connection.get("device") or interface or gateway
            source = "nmcli"
        elif interface or gateway:
            internet_key = interface or gateway
            internet_label = interface or gateway
            source = "route"

        vpn_keys = sorted(
            {
                connection.get("uuid") or connection.get("name") or connection.get("device")
                for connection in vpn_connections
                if connection.get("uuid") or connection.get("name") or connection.get("device")
            }
        )
        vpn_labels = sorted(
            {
                connection.get("name") or connection.get("device") or connection.get("uuid")
                for connection in vpn_connections
                if connection.get("name") or connection.get("device") or connection.get("uuid")
            }
        )

        if not (internet_key or interface or gateway or vpn_keys):
            error = nmcli_error or route_error
            return self._build_unavailable_state(error=error)

        signature = {
            "internet_key": internet_key,
            "internet_label": internet_label,
            "route_interface": interface,
            "route_gateway": gateway,
            "vpn_keys": vpn_keys,
            "vpn_labels": vpn_labels,
        }
        now_text = datetime.now().astimezone().isoformat(timespec="seconds")
        return {
            "internet_key": internet_key,
            "internet_label": internet_label,
            "vpn_keys": vpn_keys,
            "vpn_labels": vpn_labels,
            "route_interface": interface,
            "route_gateway": gateway,
            "source": source,
            "signature": signature,
            "signature_key": routing_profile_identity_key(signature),
            "detected_at": now_text,
            "last_changed_at": now_text,
            "available": True,
            "error": None,
        }


class RouterConfigManager:
    def __init__(self, config_file: Path, *, change_callback=None):
        self.config_file = config_file
        self._change_callback = change_callback
        self._lock = threading.Lock()
        self._config = default_router_config()
        self._network_monitor = NetworkProfileMonitor(change_callback=self._notify_change)
        self._load()

    def _notify_change(self, reason: str):
        if callable(self._change_callback):
            self._change_callback(reason)

    def shutdown(self):
        self._network_monitor.shutdown()

    def _load(self):
        try:
            content = self.config_file.read_text(encoding="utf-8")
        except FileNotFoundError:
            self._config = default_router_config()
            return

        if not content.strip():
            self._config = default_router_config()
            return

        self._config = normalize_router_config(json.loads(content))

    def _write_config_locked(self, normalized_config):
        self.config_file.parent.mkdir(parents=True, exist_ok=True)
        self.config_file.write_text(json.dumps(normalized_config, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        self._config = normalized_config

    def _public_config_locked(self):
        config = json.loads(json.dumps(self._config))
        admin_api = config.get("admin_api") or {}
        public_tokens = []
        for token in admin_api.get("tokens") or []:
            public_tokens.append(
                {
                    "id": token.get("id"),
                    "name": token.get("name"),
                    "enabled": bool(token.get("enabled", True)),
                    "created_at": token.get("created_at"),
                    "last_used_at": token.get("last_used_at"),
                    "last_used_by": token.get("last_used_by"),
                }
            )
        config["admin_api"] = {
            "enabled": bool(admin_api.get("enabled", False)),
            "tokens": public_tokens,
        }
        return config

    def _payload_has_admin_api_secrets(self, payload) -> bool:
        if not isinstance(payload, dict):
            return False
        admin_api = payload.get("admin_api")
        if not isinstance(admin_api, dict):
            return False
        for token in admin_api.get("tokens") or []:
            if not isinstance(token, dict):
                continue
            if str(token.get("token") or "").strip() or str(token.get("token_hash") or "").strip():
                return True
        return False

    def _merge_existing_admin_api_if_needed(self, payload):
        if not isinstance(payload, dict) or self._payload_has_admin_api_secrets(payload):
            return payload
        merged = json.loads(json.dumps(payload))
        with self._lock:
            merged["admin_api"] = json.loads(json.dumps(self._config.get("admin_api", default_router_config()["admin_api"])))
        return merged

    def _prune_expired_rules_locked(self) -> bool:
        now = datetime.now().astimezone()
        expired_found = False
        config = json.loads(json.dumps(self._config))
        config["rules"] = [
            rule
            for rule in config.get("rules", [])
            if not is_rule_expired(rule, now=now)
        ]
        if len(config["rules"]) != len(self._config.get("rules", [])):
            expired_found = True

        for index, profile in enumerate(config.get("routing_profiles", [])):
            original_rules = profile.get("rules", [])
            active_rules = [rule for rule in original_rules if not is_rule_expired(rule, now=now)]
            if len(active_rules) != len(original_rules):
                config["routing_profiles"][index]["rules"] = active_rules
                expired_found = True

        config["client_traffic_exemptions"] = [
            exemption
            for exemption in config.get("client_traffic_exemptions", [])
            if not is_client_traffic_exemption_expired(exemption, now=now)
        ]
        if len(config["client_traffic_exemptions"]) != len(self._config.get("client_traffic_exemptions", [])):
            expired_found = True

        config["client_blocks"] = [
            block
            for block in config.get("client_blocks", [])
            if not is_client_block_expired(block, now=now)
        ]
        if len(config["client_blocks"]) != len(self._config.get("client_blocks", [])):
            expired_found = True

        if not expired_found:
            return False

        normalized = normalize_router_config(config)
        self._write_config_locked(normalized)
        self._notify_change("router-config")
        return True

    def _default_profile_snapshot_locked(self):
        profile = default_routing_profile_entry()
        profile.update(
            {
                "name": "Shared",
                "default_action": self._config.get("default_action", profile["default_action"]),
                "ignored_failure_hosts": list(self._config.get("ignored_failure_hosts", [])),
                "rules": json.loads(json.dumps(self._config.get("rules", []))),
            }
        )
        return profile

    def _build_combined_profile_locked(self, shared_profile, matched_profile):
        if matched_profile is None:
            return json.loads(json.dumps(shared_profile))

        shared_ignored = list(shared_profile.get("ignored_failure_hosts", []))
        profile_ignored = list(matched_profile.get("ignored_failure_hosts", []))
        combined_ignored = []
        for item in [*shared_ignored, *profile_ignored]:
            normalized_item = summarize_domain(str(item)) or normalize_host(str(item))
            if normalized_item and normalized_item not in combined_ignored:
                combined_ignored.append(normalized_item)

        combined = json.loads(json.dumps(matched_profile))
        combined["default_action"] = matched_profile.get("default_action", shared_profile.get("default_action", "direct"))
        combined["ignored_failure_hosts"] = combined_ignored
        combined["rules"] = prioritize_router_rules(
            json.loads(json.dumps(matched_profile.get("rules", [])))
            + json.loads(json.dumps(shared_profile.get("rules", [])))
        )
        combined["shared_rules"] = json.loads(json.dumps(shared_profile.get("rules", [])))
        combined["profile_rules"] = json.loads(json.dumps(matched_profile.get("rules", [])))
        return combined

    def _find_profile_locked(self, profile_id: str | None):
        normalized_profile_id = str(profile_id or "").strip() or DEFAULT_ROUTING_PROFILE_ID
        if normalized_profile_id == DEFAULT_ROUTING_PROFILE_ID:
            return self._default_profile_snapshot_locked()
        for profile in self._config.get("routing_profiles", []):
            if profile.get("id") == normalized_profile_id:
                return json.loads(json.dumps(profile))
        return None

    def _find_mutable_profile_locked(self, config, profile_id: str | None):
        normalized_profile_id = str(profile_id or "").strip() or DEFAULT_ROUTING_PROFILE_ID
        if normalized_profile_id == DEFAULT_ROUTING_PROFILE_ID:
            return config
        for profile in config.get("routing_profiles", []):
            if profile.get("id") == normalized_profile_id:
                return profile
        return None

    def _match_profile_locked(self, network_state: dict | None):
        if not network_state or not network_state.get("available") or not network_state.get("signature"):
            return None
        active_signature_key = routing_profile_identity_key(network_state["signature"])
        for profile in self._config.get("routing_profiles", []):
            if not profile.get("enabled", True):
                continue
            if routing_profile_identity_key(profile.get("signature")) == active_signature_key:
                return json.loads(json.dumps(profile))
        return None

    def _resolve_effective_profile_locked(self, *, profile_id: str | None = None, network_state: dict | None = None):
        shared_profile = self._default_profile_snapshot_locked()
        requested_profile = self._find_profile_locked(profile_id) if profile_id is not None else None
        if requested_profile is not None:
            matched_profile = requested_profile if requested_profile.get("id") != DEFAULT_ROUTING_PROFILE_ID else None
            return {
                "profile": self._build_combined_profile_locked(shared_profile, matched_profile),
                "shared_profile": shared_profile,
                "matched_profile": matched_profile,
                "selected_profile": requested_profile,
                "network_state": network_state or self._network_monitor.snapshot(),
                "using_fallback": requested_profile.get("id") == DEFAULT_ROUTING_PROFILE_ID,
                "selection_reason": "selected",
            }

        current_network_state = network_state or self._network_monitor.snapshot()
        matched_profile = self._match_profile_locked(current_network_state)
        if matched_profile is not None:
            return {
                "profile": self._build_combined_profile_locked(shared_profile, matched_profile),
                "shared_profile": shared_profile,
                "matched_profile": matched_profile,
                "selected_profile": matched_profile,
                "network_state": current_network_state,
                "using_fallback": False,
                "selection_reason": "matched",
            }
        return {
            "profile": json.loads(json.dumps(shared_profile)),
            "shared_profile": shared_profile,
            "matched_profile": None,
            "selected_profile": shared_profile,
            "network_state": current_network_state,
            "using_fallback": True,
            "selection_reason": "default",
        }

    def snapshot(self):
        with self._lock:
            self._prune_expired_rules_locked()
            return json.loads(json.dumps(self._config))

    def public_snapshot(self):
        with self._lock:
            self._prune_expired_rules_locked()
            return self._public_config_locked()

    def runtime_snapshot(self):
        network_state = self._network_monitor.snapshot()
        with self._lock:
            self._prune_expired_rules_locked()
            resolution = self._resolve_effective_profile_locked(network_state=network_state)
            active_profile = resolution["profile"]
            matched_profile = resolution["matched_profile"]
            saved_profiles = [
                {
                    "id": profile.get("id"),
                    "name": profile.get("name"),
                    "enabled": bool(profile.get("enabled", True)),
                    "signature": json.loads(json.dumps(profile.get("signature") or default_routing_profile_signature())),
                }
                for profile in self._config.get("routing_profiles", [])
            ]

        return {
            "network": network_state,
            "active_profile": {
                "id": active_profile.get("id", DEFAULT_ROUTING_PROFILE_ID),
                "name": active_profile.get("name", "Shared"),
                "using_fallback": resolution["using_fallback"],
                "selection_reason": resolution["selection_reason"],
                "signature": json.loads(json.dumps(active_profile.get("signature") or default_routing_profile_signature())),
            },
            "shared_profile": {
                "id": shared_profile["id"],
                "name": shared_profile["name"],
            } if (shared_profile := resolution.get("shared_profile")) is not None else None,
            "matched_profile": (
                {
                    "id": matched_profile.get("id"),
                    "name": matched_profile.get("name"),
                }
                if matched_profile is not None
                else None
            ),
            "saved_profiles": saved_profiles,
        }

    def effective_routing_snapshot(self, profile_id: str | None = None):
        network_state = self._network_monitor.snapshot()
        with self._lock:
            self._prune_expired_rules_locked()
            resolution = self._resolve_effective_profile_locked(
                profile_id=profile_id,
                network_state=network_state,
            )
            return json.loads(json.dumps(resolution["profile"]))

    def routing_target_snapshot(self, profile_id: str | None = None):
        with self._lock:
            self._prune_expired_rules_locked()
            profile = self._find_profile_locked(profile_id)
            if profile is None:
                return None
            return json.loads(json.dumps(profile))

    def rule_issues_for_candidate(self, profile_id: str | None, rule) -> list[dict]:
        candidate_rule = normalize_rule_suggestion_rule(rule)
        with self._lock:
            self._prune_expired_rules_locked()
            config = json.loads(json.dumps(self._config))
            target_profile = self._find_mutable_profile_locked(config, profile_id)
            if target_profile is None:
                raise ValueError("routing profile for rule suggestion was not found")
            target_profile.setdefault("rules", []).append(candidate_rule)
            normalized = normalize_router_config(config)
        return find_router_rule_issues(normalized)

    def add_manual_rule(self, profile_id: str | None, rule) -> dict:
        candidate_rule = normalize_rule_suggestion_rule(rule)
        candidate_rule["source"] = "manual"
        with self._lock:
            self._prune_expired_rules_locked()
            config = json.loads(json.dumps(self._config))
            target_profile = self._find_mutable_profile_locked(config, profile_id)
            if target_profile is None:
                raise ValueError("routing profile for rule suggestion was not found")
            target_profile.setdefault("rules", []).append(candidate_rule)
            normalized = normalize_router_config(config)
            validate_router_rule_issues(normalized)
            self._write_config_locked(normalized)
            saved = json.loads(json.dumps(self._config))
        self._notify_change("router-config")
        return saved

    def update(self, payload):
        payload = self._merge_existing_admin_api_if_needed(payload)
        normalized = normalize_router_config(payload)
        validate_router_rule_issues(normalized)
        with self._lock:
            self._write_config_locked(normalized)
            saved = json.loads(json.dumps(self._config))
        self._notify_change("router-config")
        return saved

    def preview_update(self, payload):
        payload = self._merge_existing_admin_api_if_needed(payload)
        normalized = normalize_router_config(payload)
        issues = find_router_rule_issues(normalized)
        return {
            "ok": not bool(issues),
            "router_config": normalized,
            "issues": issues,
        }

    def admin_api_status(self) -> dict:
        with self._lock:
            self._prune_expired_rules_locked()
            config = self._public_config_locked().get("admin_api") or {}
            active_count = len([token for token in config.get("tokens") or [] if token.get("enabled", True)])
            return {
                "enabled": bool(config.get("enabled", False)),
                "requires_auth": bool(config.get("enabled", False) and active_count),
                "active_token_count": active_count,
                "tokens": config.get("tokens") or [],
            }

    def admin_api_requires_auth(self) -> bool:
        status = self.admin_api_status()
        return bool(status.get("requires_auth"))

    def verify_admin_api_token(self, token: str | None, *, client_ip: str | None = None) -> bool:
        token_text = str(token or "").strip()
        if not token_text:
            return False
        now_text = datetime.now().astimezone().isoformat(timespec="seconds")
        with self._lock:
            config = json.loads(json.dumps(self._config))
            admin_api = config.get("admin_api") or {}
            if not admin_api.get("enabled", False):
                return True
            changed = False
            for item in admin_api.get("tokens") or []:
                if not item.get("enabled", True):
                    continue
                if verify_client_auth_password(token_text, item.get("token_hash")):
                    item["last_used_at"] = now_text
                    item["last_used_by"] = str(client_ip or "").strip() or None
                    changed = True
                    break
            else:
                return False
            if changed:
                normalized = normalize_router_config(config)
                self._write_config_locked(normalized)
        if changed:
            self._notify_change("router-config")
        return True

    def create_admin_api_token(self, name: str | None = None) -> dict:
        token_text = secrets.token_urlsafe(32)
        now_text = datetime.now().astimezone().isoformat(timespec="seconds")
        token_record = {
            "id": uuid.uuid4().hex,
            "name": str(name or "MCP token").strip() or "MCP token",
            "token": token_text,
            "enabled": True,
            "created_at": now_text,
            "last_used_at": None,
            "last_used_by": None,
        }
        with self._lock:
            config = json.loads(json.dumps(self._config))
            admin_api = config.setdefault("admin_api", {"enabled": True, "tokens": []})
            admin_api["enabled"] = True
            admin_api.setdefault("tokens", []).append(token_record)
            normalized = normalize_router_config(config)
            self._write_config_locked(normalized)
            public_token = next(
                item
                for item in self._public_config_locked()["admin_api"]["tokens"]
                if item["id"] == token_record["id"]
            )
        self._notify_change("router-config")
        return {
            "token": token_text,
            "record": public_token,
            "status": self.admin_api_status(),
        }

    def delete_admin_api_token(self, token_id: str) -> dict:
        normalized_id = str(token_id or "").strip()
        if not normalized_id:
            raise KeyError(normalized_id)
        with self._lock:
            config = json.loads(json.dumps(self._config))
            admin_api = config.get("admin_api") or {}
            before = len(admin_api.get("tokens") or [])
            admin_api["tokens"] = [
                token for token in admin_api.get("tokens") or [] if str(token.get("id") or "") != normalized_id
            ]
            if len(admin_api["tokens"]) == before:
                raise KeyError(normalized_id)
            config["admin_api"] = admin_api
            normalized = normalize_router_config(config)
            self._write_config_locked(normalized)
        self._notify_change("router-config")
        return self.admin_api_status()

    def change_client_auth_password(self, username: str, *, current_password: str, new_password: str) -> dict:
        normalized_username = normalize_client_auth_username(username)
        if not normalized_username:
            raise PermissionError("authenticated user is required")
        if not str(current_password or ""):
            raise ValueError("current password is required")
        if not str(new_password or ""):
            raise ValueError("new password is required")

        with self._lock:
            config = json.loads(json.dumps(self._config))
            credentials = (config.get("client_auth") or {}).get("credentials") or []
            credential = next(
                (
                    item
                    for item in credentials
                    if str(item.get("username") or "") == normalized_username
                ),
                None,
            )
            if credential is None or not credential.get("enabled", True):
                raise PermissionError("authenticated credential was not found or is disabled")
            if not verify_client_auth_password(str(current_password), credential.get("password_hash")):
                raise PermissionError("current password is incorrect")

            credential["password_hash"] = hash_client_auth_password(str(new_password))
            normalized = normalize_router_config(config)
            validate_router_rule_issues(normalized)
            self._write_config_locked(normalized)
            saved = json.loads(json.dumps(self._config))
        self._notify_change("router-config")
        return saved

    def ignored_failure_hosts(self, profile_id: str | None = None):
        with self._lock:
            self._prune_expired_rules_locked()
            resolution = self._resolve_effective_profile_locked(profile_id=profile_id)
            return list(resolution["profile"].get("ignored_failure_hosts", []))

    def find_client_traffic_limit(self, client_ip: str):
        with self._lock:
            self._prune_expired_rules_locked()
            configured_exemptions = list(self._config.get("client_traffic_exemptions", []))
            configured_limits = list(self._config.get("client_traffic_limits", []))
            default_limit = dict(
                self._config.get(
                    "default_client_traffic_limit",
                    default_router_config()["default_client_traffic_limit"],
                )
            )
            default_authenticated_limit = dict(
                self._config.get(
                    "default_authenticated_client_traffic_limit",
                    default_router_config()["default_authenticated_client_traffic_limit"],
                )
            )

        matched_exemption = None
        matched_specificity = -1
        for exemption in configured_exemptions:
            if not exemption.get("enabled", True):
                continue
            target = exemption.get("client")
            if not target or not client_ip_matches_limit_target(client_ip, target):
                continue

            specificity = client_limit_target_specificity(target)
            if specificity > matched_specificity:
                matched_exemption = dict(exemption)
                matched_specificity = specificity

        if matched_exemption is not None:
            matched_exemption["scope"] = "exempt"
            matched_exemption["target"] = matched_exemption.get("client")
            matched_exemption["exempt"] = True
            return matched_exemption

        matched_limit = None
        matched_specificity = -1
        for limit in configured_limits:
            if not limit.get("enabled", True):
                continue
            target = limit.get("client")
            if not target or not client_ip_matches_limit_target(client_ip, target):
                continue

            specificity = client_limit_target_specificity(target)
            if specificity > matched_specificity:
                matched_limit = dict(limit)
                matched_specificity = specificity

        if matched_limit is None:
            if str(client_ip or "").startswith("user:") and default_authenticated_limit.get("enabled", False):
                matched_limit = default_authenticated_limit
                matched_limit["scope"] = "default_authenticated"
                matched_limit["target"] = "authenticated users"
            elif default_limit.get("enabled", False):
                matched_limit = default_limit
                matched_limit["scope"] = "default"
                matched_limit["target"] = "all devices"
            else:
                return None
        else:
            matched_limit["scope"] = "custom"
            matched_limit["target"] = matched_limit.get("client")

        matched_limit["max_past_hour_bytes"] = traffic_limit_mb_to_bytes(
            matched_limit.get("max_past_hour_mb")
        )
        matched_limit["max_past_3h_bytes"] = traffic_limit_mb_to_bytes(
            matched_limit.get("max_past_3h_mb")
        )
        return matched_limit

    def find_client_block(self, client_id: str):
        with self._lock:
            self._prune_expired_rules_locked()
            configured_blocks = list(self._config.get("client_blocks", []))

        matched_block = None
        matched_specificity = -1
        for block in configured_blocks:
            if not block.get("enabled", True):
                continue
            target = block.get("client")
            if not target or not client_ip_matches_limit_target(client_id, target):
                continue

            specificity = client_limit_target_specificity(target)
            if specificity > matched_specificity:
                matched_block = dict(block)
                matched_specificity = specificity

        if matched_block is None:
            return None

        matched_block["scope"] = "blocked"
        matched_block["target"] = matched_block.get("client")
        matched_block["blocked"] = True
        matched_block["remaining_seconds"] = client_block_remaining_seconds(matched_block)
        return matched_block

    def auto_proxy_failure_settings(self):
        with self._lock:
            settings = self._config.get("auto_proxy_failures", default_router_config()["auto_proxy_failures"])
            return {
                "enabled": bool(settings.get("enabled", False)),
                "initial_failure_threshold": DEFAULT_AUTO_PROXY_FAILURE_THRESHOLD,
                "repeat_failure_threshold": AUTO_PROXY_REPEAT_FAILURE_THRESHOLD,
                "stage_durations_seconds": auto_proxy_stage_durations_seconds(),
            }

    def upstream_retry_settings(self):
        with self._lock:
            settings = self._config.get("upstream_retry", default_router_config()["upstream_retry"])
            return {
                "enabled": bool(settings.get("enabled", True)),
                "attempts": int(settings.get("attempts", UPSTREAM_RETRY_ATTEMPTS)),
                "initial_delay_seconds": int(
                    settings.get("initial_delay_seconds", UPSTREAM_RETRY_INITIAL_DELAY_SECONDS)
                ),
                "max_delay_seconds": int(settings.get("max_delay_seconds", UPSTREAM_RETRY_MAX_DELAY_SECONDS)),
            }

    def client_auth_settings(self):
        with self._lock:
            settings = self._config.get("client_auth", default_router_config()["client_auth"])
            return json.loads(json.dumps(settings))

    def https_interception_settings(self):
        with self._lock:
            settings = self._config.get("https_interception", default_router_config()["https_interception"])
            return json.loads(json.dumps(settings))

    def is_failure_host_ignored(self, host: str | None) -> bool:
        if not host:
            return False
        normalized_host = normalize_host(host)
        normalized_domain = summarize_domain(host)
        with self._lock:
            resolution = self._resolve_effective_profile_locked()
            ignored = resolution["profile"].get("ignored_failure_hosts", [])
            return normalized_host in ignored or normalized_domain in ignored

    def auto_proxy_evaluation(self, host: str | None, *, profile_id: str | None = None):
        normalized_host = normalize_host(host or "")
        domain = None if is_ip_address_text(normalized_host) else summarize_domain(normalized_host)
        with self._lock:
            self._prune_expired_rules_locked()
            settings = self._config.get("auto_proxy_failures", default_router_config()["auto_proxy_failures"])
            resolution = self._resolve_effective_profile_locked(profile_id=profile_id)
            profile = resolution["profile"]
            ignored_hosts = profile.get("ignored_failure_hosts", [])
            handled = False
            for rule in profile.get("rules", []):
                if not rule.get("enabled", True):
                    continue
                if rule_matches_host(rule, normalized_host):
                    handled = True
                    break

            enabled = bool(settings.get("enabled", False))
            upstream_enabled = any(proxy.get("enabled", True) for proxy in self._config.get("proxies", []))
            ignored = bool(normalized_host) and (
                normalized_host in ignored_hosts or (domain and domain in ignored_hosts)
            )

        return {
            "host": normalized_host or None,
            "pattern": domain or normalized_host or None,
            "enabled": enabled,
            "upstream_enabled": upstream_enabled,
            "ignored": ignored,
            "handled": handled,
            "profile_id": profile.get("id", DEFAULT_ROUTING_PROFILE_ID),
            "profile_name": profile.get("name", "Shared"),
            "eligible": bool(
                normalized_host and (domain or normalized_host) and enabled and upstream_enabled and not ignored and not handled
            ),
        }

    def add_auto_proxy_rule(
        self,
        host: str | None,
        *,
        duration_seconds: int,
        stage_index: int,
        expires_at: datetime,
        profile_id: str | None = None,
        proxy_id: str | None = None,
    ):
        normalized_host = normalize_host(host or "")
        if not normalized_host:
            return {"status": "skipped", "reason": "missing-host"}
        if is_ip_address_text(normalized_host):
            return {"status": "skipped", "reason": "ip-address", "pattern": normalized_host}

        with self._lock:
            self._prune_expired_rules_locked()
            config = json.loads(json.dumps(self._config))
            settings = config.get("auto_proxy_failures", default_router_config()["auto_proxy_failures"])
            target_profile = self._find_mutable_profile_locked(config, profile_id)
            if target_profile is None:
                return {"status": "skipped", "reason": "missing-profile", "pattern": normalized_host}
            pattern = summarize_domain(normalized_host) or normalized_host
            shared_profile = {
                "ignored_failure_hosts": list(config.get("ignored_failure_hosts", [])),
                "rules": list(config.get("rules", [])),
            }
            ignored_hosts = []
            for item in [*shared_profile.get("ignored_failure_hosts", []), *target_profile.get("ignored_failure_hosts", [])]:
                normalized_item = summarize_domain(str(item)) or normalize_host(str(item))
                if normalized_item and normalized_item not in ignored_hosts:
                    ignored_hosts.append(normalized_item)

            if not settings.get("enabled", False):
                return {"status": "skipped", "reason": "disabled", "pattern": pattern}
            if not any(proxy.get("enabled", True) for proxy in config.get("proxies", [])):
                return {"status": "skipped", "reason": "upstream-disabled", "pattern": pattern}
            if normalized_host in ignored_hosts or pattern in ignored_hosts:
                return {"status": "skipped", "reason": "ignored", "pattern": pattern}
            selected_proxy_id = normalize_upstream_proxy_id(proxy_id)
            if selected_proxy_id and selected_proxy_id not in {proxy.get("id") for proxy in config.get("proxies", [])}:
                return {"status": "skipped", "reason": "missing-proxy", "pattern": pattern}

            for rule in target_profile.get("rules", []):
                if not rule.get("enabled", True):
                    continue
                if is_auto_proxy_rule(rule, pattern):
                    auto_rule_note = build_auto_proxy_rule_note(stage_index, duration_seconds, expires_at)
                    rule["note"] = auto_rule_note
                    rule["source"] = "auto"
                    rule["duration"] = format_auto_proxy_duration(duration_seconds)
                    rule["expires_at"] = expires_at.isoformat()
                    if selected_proxy_id:
                        rule["proxy_id"] = selected_proxy_id
                    else:
                        rule.pop("proxy_id", None)
                    normalized = normalize_router_config(config)
                    self._write_config_locked(normalized)
                    return {
                        "status": "updated",
                        "pattern": pattern,
                        "rule": dict(rule),
                        "profile_id": target_profile.get("id", DEFAULT_ROUTING_PROFILE_ID),
                    }
            effective_rules = list(target_profile.get("rules", []))
            if target_profile is not config:
                effective_rules.extend(shared_profile.get("rules", []))
            for rule in effective_rules:
                if not rule.get("enabled", True):
                    continue
                if rule_matches_host(rule, normalized_host):
                    return {"status": "skipped", "reason": "handled", "pattern": pattern}

            auto_rule_note = build_auto_proxy_rule_note(stage_index, duration_seconds, expires_at)
            rule = {
                "pattern": pattern,
                "match": "suffix",
                "action": "proxy",
                "enabled": True,
                "note": auto_rule_note,
                "source": "auto",
                "duration": format_auto_proxy_duration(duration_seconds),
                "expires_at": expires_at.isoformat(),
            }
            if selected_proxy_id:
                rule["proxy_id"] = selected_proxy_id
            target_profile.setdefault("rules", []).append(rule)
            normalized = normalize_router_config(config)
            self._write_config_locked(normalized)
            return {
                "status": "added",
                "pattern": pattern,
                "rule": rule,
                "profile_id": target_profile.get("id", DEFAULT_ROUTING_PROFILE_ID),
            }

    def remove_auto_proxy_rule(self, pattern: str | None, *, profile_id: str | None = None):
        normalized_pattern = normalize_rule_pattern(pattern or "")
        if not normalized_pattern:
            return {"status": "skipped", "reason": "missing-pattern"}

        with self._lock:
            self._prune_expired_rules_locked()
            config = json.loads(json.dumps(self._config))
            target_profile = self._find_mutable_profile_locked(config, profile_id)
            if target_profile is None:
                return {"status": "skipped", "reason": "missing-profile", "pattern": normalized_pattern}
            removed_rule = None
            kept_rules = []
            for rule in target_profile.get("rules", []):
                if removed_rule is None and is_auto_proxy_rule(rule, normalized_pattern):
                    removed_rule = dict(rule)
                    continue
                kept_rules.append(rule)

            if removed_rule is None:
                return {"status": "skipped", "reason": "missing-rule", "pattern": normalized_pattern}

            target_profile["rules"] = kept_rules
            normalized = normalize_router_config(config)
            self._write_config_locked(normalized)
            return {
                "status": "removed",
                "pattern": normalized_pattern,
                "rule": removed_rule,
                "profile_id": target_profile.get("id", DEFAULT_ROUTING_PROFILE_ID),
            }

    def upstream_proxies(
        self,
        *,
        client_id: str | None = None,
        client_ip: str | None = None,
        preferred_proxy_id: str | None = None,
    ):
        with self._lock:
            proxies = json.loads(json.dumps(self._config.get("proxies", [])))
        enabled = [proxy for proxy in proxies if proxy.get("enabled", True)]
        if client_id is not None or client_ip is not None:
            enabled = [
                proxy
                for proxy in enabled
                if proxy_allows_client(proxy, client_id, client_ip=client_ip)
            ]
        preferred_id = normalize_upstream_proxy_id(preferred_proxy_id)
        enabled.sort(
            key=lambda proxy: (
                0 if preferred_id and proxy.get("id") == preferred_id else 1,
                int(proxy.get("priority", 1)),
                str(proxy.get("id") or ""),
            )
        )
        return enabled

    def decide(self, host: str, *, client_id: str | None = None, client_ip: str | None = None):
        normalized_host = normalize_host(host)
        network_state = self._network_monitor.snapshot()
        with self._lock:
            self._prune_expired_rules_locked()
            config = self._config
            resolution = self._resolve_effective_profile_locked(network_state=network_state)
            profile = resolution["profile"]
            matched_rule = None
            action = profile["default_action"]
            for rule in profile["rules"]:
                if not rule["enabled"]:
                    continue
                if rule_matches_host(rule, normalized_host):
                    matched_rule = dict(rule)
                    action = rule["action"]
                    break

            preferred_proxy_id = matched_rule.get("proxy_id") if matched_rule else None
            upstream_candidates = [
                proxy
                for proxy in json.loads(json.dumps(config.get("proxies", [])))
                if proxy.get("enabled", True) and proxy_allows_client(proxy, client_id, client_ip=client_ip)
            ]
            preferred_proxy_id = normalize_upstream_proxy_id(preferred_proxy_id)
            upstream_candidates.sort(
                key=lambda proxy: (
                    0 if preferred_proxy_id and proxy.get("id") == preferred_proxy_id else 1,
                    int(proxy.get("priority", 1)),
                    str(proxy.get("id") or ""),
                )
            )
            upstream = dict(upstream_candidates[0]) if upstream_candidates else None

        return {
            "host": normalized_host,
            "action": action,
            "matched_rule": matched_rule,
            "upstream": upstream,
            "upstream_candidates": upstream_candidates,
            "preferred_proxy_id": preferred_proxy_id or None,
            "profile_id": profile.get("id", DEFAULT_ROUTING_PROFILE_ID),
            "profile_name": profile.get("name", "Shared"),
            "profile_signature": json.loads(
                json.dumps(profile.get("signature") or default_routing_profile_signature())
            ),
            "route_label": (
                UPSTREAM_PROXY_ROUTE_LABEL
                if action == "proxy" and upstream is None
                else describe_route_decision(
                    {
                        "action": action,
                        "upstream": upstream if action == "proxy" else None,
                    }
                )
            ),
        }
