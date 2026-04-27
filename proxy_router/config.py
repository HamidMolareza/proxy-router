from __future__ import annotations

import json
import shutil
import socket
import struct
import subprocess
import threading
from datetime import datetime
from pathlib import Path

from .constants import *
from .util import *

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

    def update(self, payload):
        normalized = normalize_router_config(payload)
        with self._lock:
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
            if not default_limit.get("enabled", False):
                return None
            matched_limit = default_limit
            matched_limit["scope"] = "default"
            matched_limit["target"] = "all devices"
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

    def auto_proxy_failure_settings(self):
        with self._lock:
            settings = self._config.get("auto_proxy_failures", default_router_config()["auto_proxy_failures"])
            return {
                "enabled": bool(settings.get("enabled", False)),
                "initial_failure_threshold": DEFAULT_AUTO_PROXY_FAILURE_THRESHOLD,
                "repeat_failure_threshold": AUTO_PROXY_REPEAT_FAILURE_THRESHOLD,
                "stage_durations_seconds": auto_proxy_stage_durations_seconds(),
            }

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
            upstream_enabled = bool(self._config.get("upstream", {}).get("enabled"))
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
            if not config.get("upstream", {}).get("enabled", False):
                return {"status": "skipped", "reason": "upstream-disabled", "pattern": pattern}
            if normalized_host in ignored_hosts or pattern in ignored_hosts:
                return {"status": "skipped", "reason": "ignored", "pattern": pattern}

            for rule in target_profile.get("rules", []):
                if not rule.get("enabled", True):
                    continue
                if is_auto_proxy_rule(rule, pattern):
                    auto_rule_note = build_auto_proxy_rule_note(stage_index, duration_seconds, expires_at)
                    rule["note"] = auto_rule_note
                    rule["source"] = "auto"
                    rule["duration"] = format_auto_proxy_duration(duration_seconds)
                    rule["expires_at"] = expires_at.isoformat()
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

    def decide(self, host: str):
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

            upstream = dict(config["upstream"]) if config["upstream"]["enabled"] else None

        return {
            "host": normalized_host,
            "action": action,
            "matched_rule": matched_rule,
            "upstream": upstream,
            "profile_id": profile.get("id", DEFAULT_ROUTING_PROFILE_ID),
            "profile_name": profile.get("name", "Shared"),
            "profile_signature": json.loads(
                json.dumps(profile.get("signature") or default_routing_profile_signature())
            ),
            "route_label": describe_route_decision(
                {
                    "action": action,
                    "upstream": upstream if action == "proxy" else None,
                }
            ),
        }
