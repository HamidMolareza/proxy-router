from __future__ import annotations

import json
import re

SING_BOX_DIRECT_OUTBOUND = "direct"
SING_BOX_BLOCK_OUTBOUND = "block"
SING_BOX_FAKE_DNS_CIDR = "198.18.0.0/16"


def _proxy_tag(proxy: dict) -> str:
    proxy_id = str(proxy.get("id") or proxy.get("name") or "default").strip().lower()
    proxy_id = re.sub(r"[^a-z0-9_-]+", "-", proxy_id).strip("-") or "default"
    return f"proxy-{proxy_id}"


def _enabled_proxies(config: dict) -> list[dict]:
    proxies = [
        dict(proxy)
        for proxy in config.get("proxies", [])
        if proxy.get("enabled", True)
    ]
    proxies.sort(key=lambda proxy: (int(proxy.get("priority", 1)), str(proxy.get("id") or "")))
    return proxies


def _proxy_outbound(proxy: dict) -> dict:
    proxy_type = str(proxy.get("type") or "http").strip().lower()
    outbound = {
        "type": "socks" if proxy_type == "socks5" else "http",
        "tag": _proxy_tag(proxy),
        "server": str(proxy.get("host") or ""),
        "server_port": int(proxy.get("port") or 0),
    }
    if proxy_type == "socks5":
        outbound["version"] = "5"
    return outbound


def _outbound_for_action(action: str, rule: dict | None, proxies: list[dict], default_proxy_tag: str | None) -> str:
    normalized_action = str(action or "direct").strip().lower()
    if normalized_action == "direct":
        return SING_BOX_DIRECT_OUTBOUND
    if normalized_action == "block":
        return SING_BOX_BLOCK_OUTBOUND
    if normalized_action != "proxy":
        return SING_BOX_DIRECT_OUTBOUND

    preferred_proxy_id = str((rule or {}).get("proxy_id") or "").strip()
    if preferred_proxy_id:
        for proxy in proxies:
            if str(proxy.get("id") or "") == preferred_proxy_id:
                return _proxy_tag(proxy)
    return default_proxy_tag or SING_BOX_BLOCK_OUTBOUND


def _route_match_for_rule(rule: dict) -> dict | None:
    pattern = str(rule.get("pattern") or "").strip()
    if not pattern:
        return None
    match_type = str(rule.get("match") or "suffix").strip().lower()
    if match_type == "cidr":
        return {"ip_cidr": [pattern]}
    if match_type == "exact":
        return {"domain": [pattern]}
    if match_type == "contains":
        return {"domain_keyword": [pattern]}
    return {"domain_suffix": [pattern]}


def build_sing_box_config(
    router_config,
    *,
    listen: str = "127.0.0.1",
    listen_port: int = 19090,
    profile_id: str | None = None,
    log_level: str = "warn",
) -> dict:
    config = router_config.snapshot()
    profile = router_config.effective_routing_snapshot(profile_id=profile_id)
    proxies = _enabled_proxies(config)
    default_proxy_tag = _proxy_tag(proxies[0]) if proxies else None

    outbounds = [
        {"type": "direct", "tag": SING_BOX_DIRECT_OUTBOUND},
        {"type": "block", "tag": SING_BOX_BLOCK_OUTBOUND},
    ]
    outbounds.extend(_proxy_outbound(proxy) for proxy in proxies)

    rules = [
        {"inbound": "vpn-tcp-in", "action": "sniff", "timeout": "1s"},
        {
            "ip_cidr": [SING_BOX_FAKE_DNS_CIDR],
            "action": "route",
            "outbound": default_proxy_tag or SING_BOX_BLOCK_OUTBOUND,
        },
    ]
    for rule in profile.get("rules", []):
        if not rule.get("enabled", True):
            continue
        match = _route_match_for_rule(rule)
        if match is None:
            continue
        rules.append(
            {
                **match,
                "action": "route",
                "outbound": _outbound_for_action(rule.get("action"), rule, proxies, default_proxy_tag),
            }
        )

    final_outbound = _outbound_for_action(profile.get("default_action", "direct"), None, proxies, default_proxy_tag)
    return {
        "log": {
            "level": str(log_level or "warn"),
            "timestamp": True,
        },
        "inbounds": [
            {
                "type": "redirect",
                "tag": "vpn-tcp-in",
                "listen": str(listen or "127.0.0.1"),
                "listen_port": int(listen_port),
            }
        ],
        "outbounds": outbounds,
        "route": {
            "rules": rules,
            "final": final_outbound,
            "auto_detect_interface": True,
        },
        "experimental": {
            "cache_file": {
                "enabled": True,
            }
        },
    }


def dump_sing_box_config(config: dict) -> str:
    return json.dumps(config, indent=2, sort_keys=True) + "\n"
