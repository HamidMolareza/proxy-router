from __future__ import annotations

import re
from datetime import timedelta
from pathlib import Path

HTTP_DEFAULT_PORT = 8799
HTTPS_DEFAULT_PORT = 8700
SOCKS5_DEFAULT_PORT = 1180
MIXED_DEFAULT_PORT = HTTP_DEFAULT_PORT
DEFAULT_TIMEOUT_SECONDS = 30
UPSTREAM_RETRY_ATTEMPTS = 4
UPSTREAM_RETRY_INITIAL_DELAY_SECONDS = 1
UPSTREAM_RETRY_MAX_DELAY_SECONDS = 5
UPSTREAM_RETRY_ATTEMPTS_LIMIT = 20
UPSTREAM_RETRY_DELAY_SECONDS_LIMIT = 60
RETRYABLE_HTTP_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}
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
SOCKS_AUTH_NO_AUTH = 0x00
SOCKS_AUTH_USERNAME_PASSWORD = 0x02
SOCKS_AUTH_NO_ACCEPTABLE = 0xFF
SOCKS_ATYP_IPV4 = 1
SOCKS_ATYP_DOMAIN = 3
SOCKS_ATYP_IPV6 = 4
DEFAULT_CLIENT_AUTH_REALM = "proxy-router"
CLIENT_AUTH_USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.@+-]{1,80}$")
CLIENT_AUTH_PBKDF2_ITERATIONS = 260000
CLIENT_AUTH_PBKDF2_SALT_BYTES = 16
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
DEFAULT_HTTPS_TRAFFIC_LOG_PATH = Path("/tmp/proxy-router-https-traffic.log")
DEFAULT_ERROR_LOG_PATH = Path("/tmp/proxy-router-errors.log")
DEFAULT_ROUTER_CONFIG_PATH = Path.home() / ".config" / "proxy-router" / "router-config.json"
DEFAULT_HTTPS_INTERCEPT_DIR = Path.home() / ".config" / "proxy-router" / "https-interception"
DEFAULT_HTTPS_INTERCEPT_CA_CERT_PATH = DEFAULT_HTTPS_INTERCEPT_DIR / "proxy-router-ca.crt"
DEFAULT_HTTPS_INTERCEPT_CA_KEY_PATH = DEFAULT_HTTPS_INTERCEPT_DIR / "proxy-router-ca.key"
DEFAULT_HTTPS_INTERCEPT_CERT_CACHE_DIR = DEFAULT_HTTPS_INTERCEPT_DIR / "certs"
DEFAULT_HTTPS_INTERCEPT_CA_COMMON_NAME = "proxy-router Local HTTPS Interception CA"
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
RULE_SUGGESTIONS_STATE_FILE_SUFFIX = "-rule-suggestions.json"
HTTPS_INTERCEPTION_STATE_FILE_SUFFIX = "-https-interception-state.json"
HTTPS_DISCOVERY_STATE_FILE_SUFFIX = "-https-discovery-state.json"
HTTPS_INTERCEPTION_TRUST_POLICIES = {"adaptive"}
HTTPS_INTERCEPTION_ADAPTIVE_BYPASS_DURATION = timedelta(hours=1)
HTTPS_INTERCEPTION_CLIENT_BYPASS_FAILURE_THRESHOLD = 3
HTTPS_DISCOVERY_PROBE_COOLDOWN = timedelta(hours=6)
HTTPS_DISCOVERY_PROBE_TIMEOUT_SECONDS = 6
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
CLIENT_PORTAL_PRIMARY_HOST = "proxy.router"
CLIENT_PORTAL_HOST_ALIASES = (
    CLIENT_PORTAL_PRIMARY_HOST,
    "proxy-router.invalid",
)
RECENT_REQUEST_LIMIT = 25
RECENT_FAILURE_LIMIT = 200
HTTPS_TRAFFIC_BODY_PREVIEW_BYTES = 64 * 1024
HTTPS_TRAFFIC_QUERY_LIMIT = 200
HTTPS_TRAFFIC_MAX_QUERY_LIMIT = 1000
FAILURE_PAGE_SIZE = 10
DASHBOARD_LIVE_HEARTBEAT_SECONDS = 30.0
DASHBOARD_LIVE_EVENT_BACKLOG = 256
UPSTREAM_STATUS_PROBE_TIMEOUT_SECONDS = 3
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
UPSTREAM_PROXY_ACCESS_MODES = {"public", "authenticated", "private"}
HTTPS_INTERCEPTION_MODES = {"allowlist", "all"}
HTTPS_INTERCEPTION_DEFAULT_PORTS = {443}
SENSITIVE_QUERY_PARAMETER_NAMES = {
    "access_token",
    "api_key",
    "auth",
    "authorization",
    "code",
    "key",
    "password",
    "passwd",
    "pwd",
    "secret",
    "sig",
    "signature",
    "token",
}
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
CLIENT_BLOCK_ROUTE_LABEL = "reject:client-access-block"
UPSTREAM_PROXY_ROUTE_LABEL = "reject:upstream-proxy-unavailable"
UPSTREAM_PROXY_LIMIT_ROUTE_LABEL = "reject:upstream-proxy-limit"
PROXY_TRAFFIC_WINDOW_CONFIG = {
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
    "7d": {
        "window": timedelta(days=7),
        "label": "past week",
        "config_field": "max_past_week_mb",
    },
}
PROXY_TRAFFIC_MAX_WINDOW = max(
    item["window"] for item in PROXY_TRAFFIC_WINDOW_CONFIG.values()
)
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
VPN_INTERFACE_PREFIXES = ("tun", "tap", "wg", "ppp", "tailscale", "zt", "utun", "vpn")
