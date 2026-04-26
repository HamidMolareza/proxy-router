from __future__ import annotations

import re
from datetime import timedelta
from pathlib import Path

HTTP_DEFAULT_PORT = 8799
HTTPS_DEFAULT_PORT = 8700
SOCKS5_DEFAULT_PORT = 1180
MIXED_DEFAULT_PORT = HTTP_DEFAULT_PORT
DEFAULT_TIMEOUT_SECONDS = 30
BUFFER_SIZE = 64 * 1024
HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}
SOCKS_VERSION = 5
SOCKS_CMD_CONNECT = 1
SOCKS_ATYP_IPV4 = 1
SOCKS_ATYP_DOMAIN = 3
SOCKS_ATYP_IPV6 = 4
COLOR_RESET = "\033[0m"
COLOR_BOLD = "\033[1m"
COLOR_CYAN = "\033[36m"
COLOR_BLUE = "\033[34m"
COLOR_GREEN = "\033[32m"
COLOR_YELLOW = "\033[33m"
COLOR_RED = "\033[31m"
COLOR_MAGENTA = "\033[35m"
SENSITIVE_HEADER_NAMES = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
}
MAX_DEBUG_VALUE_LENGTH = 512
DEFAULT_USAGE_LOG_PATH = Path("/tmp/proxy-router-usage.log")
DEFAULT_FAILURE_LOG_PATH = Path("/tmp/proxy-router-failures.log")
DEFAULT_ROUTER_CONFIG_PATH = Path.home() / ".config" / "proxy-router" / "router-config.json"
DEFAULT_AUTO_PROXY_FAILURE_THRESHOLD = 2
AUTO_PROXY_REPEAT_FAILURE_THRESHOLD = 1
AUTO_PROXY_STAGE_DURATIONS = (
    timedelta(hours=1),
    timedelta(days=1),
    timedelta(days=7),
    timedelta(days=30),
    timedelta(days=90),
)
AUTO_PROXY_RULE_NOTE_PREFIX = "auto-proxy:"
AUTO_PROXY_PROBE_ROUTE_LABEL_PREFIX = "proxy:auto-probe:"
AUTO_PROXY_STATE_FILE_SUFFIX = "-auto-proxy-state.json"
RULE_SOURCES = {"manual", "auto"}
RULE_DURATION_SECONDS = {
    "1h": 3600,
    "1d": 86400,
    "7d": 7 * 86400,
    "30d": 30 * 86400,
    "90d": 90 * 86400,
    "always": None,
}
RULE_DURATION_ORDER = ("1h", "1d", "7d", "30d", "90d", "always")
AUTO_PROXY_NOTE_PATTERN = re.compile(
    r"^auto-proxy:\s+stage\s+\d+/\d+\s+for\s+([^\s]+)\s+until\s+(.+?)\s*$",
    re.IGNORECASE,
)
BYTES_IN_MB = 1_000_000
DASHBOARD_DEFAULT_BIND = "127.0.0.1"
DASHBOARD_DEFAULT_PORT = 8798
RECENT_REQUEST_LIMIT = 25
RECENT_FAILURE_LIMIT = 200
FAILURE_PAGE_SIZE = 10
HISTORY_DEFAULT_RANGE = "24h"
HISTORY_RANGE_OPTIONS = {
    "1h": {
        "window": timedelta(hours=1),
        "bucket_seconds": 300,
        "label_format": "%H:%M",
        "title": "Last hour",
    },
    "24h": {
        "window": timedelta(hours=24),
        "bucket_seconds": 3600,
        "label_format": "%H:%M",
        "title": "Last 24 hours",
    },
    "7d": {
        "window": timedelta(days=7),
        "bucket_seconds": 86400,
        "label_format": "%m-%d",
        "title": "Last 7 days",
    },
    "all": {
        "window": None,
        "bucket_seconds": 86400,
        "label_format": "%Y-%m-%d",
        "title": "All time",
    },
}
HISTORY_TOP_DESTINATIONS_LIMIT = 8
DEFAULT_ROUTE_ACTIONS = {"direct", "proxy"}
RULE_ROUTE_ACTIONS = {"direct", "proxy", "block"}
RULE_MATCH_TYPES = {"exact", "suffix", "contains"}
UPSTREAM_PROXY_TYPES = {"http", "socks5"}
CLIENT_TRAFFIC_WINDOW_CONFIG = {
    "1h": {
        "window": timedelta(hours=1),
        "label": "past hour",
        "config_field": "max_past_hour_mb",
    },
    "3h": {
        "window": timedelta(hours=3),
        "label": "past 3 hours",
        "config_field": "max_past_3h_mb",
    },
}
CLIENT_TRAFFIC_MAX_WINDOW = max(
    item["window"] for item in CLIENT_TRAFFIC_WINDOW_CONFIG.values()
)
CLIENT_TRAFFIC_ROUTE_LABEL = "reject:client-traffic-limit"
CLIENT_TRAFFIC_EXEMPTION_DURATION_PATTERN = re.compile(r"^\s*(\d+)\s*([smhdw])\s*$", re.IGNORECASE)
COMMON_SECOND_LEVEL_DOMAIN_LABELS = {
    "ac",
    "co",
    "com",
    "edu",
    "gov",
    "mil",
    "net",
    "org",
    "sch",
}
DEFAULT_ROUTING_PROFILE_ID = "default"
NETWORK_PROFILE_POLL_INTERVAL_SECONDS = 3.0
VPN_CONNECTION_TYPES = {"tun", "tap", "vpn", "wireguard"}
