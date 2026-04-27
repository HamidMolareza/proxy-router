from __future__ import annotations

import base64
import errno
import hashlib
import html
import http.client
import json
import select
import socket
import socketserver
import ssl
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit

from .constants import *
from .output import debug_exception, debug_log, log_event
from .records import UsageHistoryCache
from .util import *


def encode_websocket_text_frame(payload_text: str) -> bytes:
    payload = payload_text.encode("utf-8")
    payload_length = len(payload)
    if payload_length < 126:
        header = bytes([0x81, payload_length])
    elif payload_length < 65536:
        header = bytes([0x81, 126]) + payload_length.to_bytes(2, "big")
    else:
        header = bytes([0x81, 127]) + payload_length.to_bytes(8, "big")
    return header + payload


def build_client_live_update_message(server, client_ip: str, range_key: str, event_summary, *, initial: bool = False):
    revision = 0 if initial else int(event_summary.get("revision", 0))
    return {
        "type": "client_snapshot",
        "revision": revision,
        "initial": initial,
        "reasons": [] if initial else list(event_summary.get("reasons") or []),
        "snapshot": build_client_portal_snapshot(server, client_ip, range_key=range_key),
    }


def is_retryable_upstream_error(exc: Exception) -> bool:
    if isinstance(exc, (TimeoutError, socket.timeout, socket.gaierror, ConnectionError, http.client.HTTPException)):
        return True

    if isinstance(exc, OSError):
        if exc.errno in {
            errno.ECONNABORTED,
            errno.ECONNREFUSED,
            errno.ECONNRESET,
            errno.EHOSTUNREACH,
            errno.ENETDOWN,
            errno.ENETUNREACH,
            errno.ETIMEDOUT,
        }:
            return True
        return exc.errno is None

    return False


def can_retry_http_request(method: str, body) -> bool:
    if str(method or "").upper() in RETRYABLE_HTTP_METHODS:
        return True
    return body in {None, b""}


def retry_upstream_operation(operation, *, on_retry, should_retry=is_retryable_upstream_error):
    attempts = max(1, int(UPSTREAM_RETRY_ATTEMPTS))
    delay_seconds = float(UPSTREAM_RETRY_INITIAL_DELAY_SECONDS)
    for attempt in range(1, attempts + 1):
        try:
            return operation(attempt)
        except Exception as exc:
            if attempt >= attempts or not should_retry(exc):
                raise
            on_retry(attempt, attempts, delay_seconds, exc)
            time.sleep(delay_seconds)
            delay_seconds = min(delay_seconds * 2, float(UPSTREAM_RETRY_MAX_DELAY_SECONDS))

    raise RuntimeError("unreachable retry state")


class PreconnectedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host, port=None, *, preconnected_socket, timeout=None):
        super().__init__(host, port=port, timeout=timeout)
        self._preconnected_socket = preconnected_socket

    def connect(self):
        self.sock = self._preconnected_socket


class PreconnectedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host, port=None, *, preconnected_socket, timeout=None, context=None):
        super().__init__(host, port=port, timeout=timeout, context=context)
        self._preconnected_socket = preconnected_socket

    def connect(self):
        raw_socket = self._preconnected_socket
        self.sock = self._context.wrap_socket(raw_socket, server_hostname=self.host)


def recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks = []
    remaining = size
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise OSError("connection closed while reading from socket")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def create_socks5_proxy_connection(proxy_host: str, proxy_port: int, target_host: str, target_port: int, timeout: int):
    upstream = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
    upstream.settimeout(timeout)
    try:
        upstream.sendall(bytes([SOCKS_VERSION, 0x01, 0x00]))
        method_reply = recv_exact(upstream, 2)
        if method_reply[0] != SOCKS_VERSION or method_reply[1] != 0x00:
            raise OSError("SOCKS5 upstream rejected no-auth handshake")

        address_bytes = target_host.encode("idna")
        if len(address_bytes) > 255:
            raise ValueError("destination host is too long for SOCKS5")

        request = bytearray([SOCKS_VERSION, SOCKS_CMD_CONNECT, 0x00, SOCKS_ATYP_DOMAIN, len(address_bytes)])
        request.extend(address_bytes)
        request.extend(int(target_port).to_bytes(2, "big"))
        upstream.sendall(request)

        header = recv_exact(upstream, 4)
        if header[0] != SOCKS_VERSION:
            raise OSError("invalid SOCKS5 upstream reply")
        if header[1] != 0x00:
            raise OSError(f"SOCKS5 upstream connect failed with reply code 0x{header[1]:02x}")

        atyp = header[3]
        if atyp == SOCKS_ATYP_IPV4:
            remaining = 4 + 2
        elif atyp == SOCKS_ATYP_IPV6:
            remaining = 16 + 2
        elif atyp == SOCKS_ATYP_DOMAIN:
            length_bytes = recv_exact(upstream, 1)
            remaining = length_bytes[0] + 2
        else:
            raise OSError("invalid SOCKS5 upstream address type")

        recv_exact(upstream, remaining)

        upstream.settimeout(None)
        return upstream
    except Exception:
        upstream.close()
        raise


def create_http_proxy_tunnel(proxy_host: str, proxy_port: int, target_host: str, target_port: int, timeout: int):
    connection = http.client.HTTPConnection(proxy_host, proxy_port, timeout=timeout)
    try:
        connection.set_tunnel(target_host, target_port)
        connection.connect()
        if connection.sock is None:
            raise OSError("HTTP upstream proxy did not return a connected tunnel")
        connection.sock.settimeout(None)
        return connection
    except Exception:
        connection.close()
        raise


def sanitize_http_header_value(value) -> str:
    text = str(value).replace("\r", " ").replace("\n", " ").strip()
    return " ".join(text.split())


def tunnel_bidirectional(left_socket, right_socket):
    left_socket.setblocking(False)
    right_socket.setblocking(False)
    sockets = [left_socket, right_socket]
    stats = {
        "left_to_right_bytes": 0,
        "right_to_left_bytes": 0,
    }

    while True:
        readable, _, exceptional = select.select(sockets, [], sockets, 1.0)
        if exceptional:
            return stats

        for current in readable:
            try:
                data = current.recv(BUFFER_SIZE)
            except OSError:
                return stats

            if not data:
                return stats

            target = right_socket if current is left_socket else left_socket
            try:
                target.sendall(data)
            except OSError:
                return stats

            if current is left_socket:
                stats["left_to_right_bytes"] += len(data)
            else:
                stats["right_to_left_bytes"] += len(data)


class ClientTracker:
    def __init__(self, proxy_label: str, runtime):
        self.runtime = runtime
        self.proxy_label = proxy_label
        self._lock = threading.Lock()
        self._active_by_ip = {}

    def connected(self, client_ip: str):
        self.runtime.dashboard_state.client_connected(self.proxy_label, client_ip)
        self.runtime.notify_dashboard_update("connections")
        with self._lock:
            self._active_by_ip[client_ip] = self._active_by_ip.get(client_ip, 0) + 1
            active_count = self._active_by_ip[client_ip]
            total_count = sum(self._active_by_ip.values())
        log_event(
            self.proxy_label,
            f"client connected: {client_ip} (active for IP: {active_count}, total: {total_count})",
        )

    def disconnected(self, client_ip: str):
        self.runtime.dashboard_state.client_disconnected(self.proxy_label, client_ip)
        self.runtime.notify_dashboard_update("connections")
        with self._lock:
            current = self._active_by_ip.get(client_ip, 0)
            if current <= 1:
                self._active_by_ip.pop(client_ip, None)
                active_count = 0
            else:
                self._active_by_ip[client_ip] = current - 1
                active_count = self._active_by_ip[client_ip]
            total_count = sum(self._active_by_ip.values())
        log_event(
            self.proxy_label,
            f"client disconnected: {client_ip} (active for IP: {active_count}, total: {total_count})",
        )


class ThreadedHTTPProxyServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        server_address,
        handler_class,
        *,
        allowed_networks,
        timeout_seconds,
        verbose,
        debug,
        proxy_label,
        router_config,
        runtime,
    ):
        super().__init__(server_address, handler_class)
        self.allowed_networks = allowed_networks
        self.timeout_seconds = timeout_seconds
        self.verbose = verbose
        self.debug = debug
        self.proxy_label = proxy_label
        self.client_tracker = ClientTracker(proxy_label, runtime)
        self.router_config = router_config
        self.runtime = runtime
        self.history_cache = UsageHistoryCache(runtime.usage_log_path)


class ThreadedTLSHTTPProxyServer(ThreadedHTTPProxyServer):
    def __init__(
        self,
        server_address,
        handler_class,
        *,
        ssl_context,
        allowed_networks,
        timeout_seconds,
        verbose,
        debug,
        proxy_label,
        router_config,
        runtime,
    ):
        self.ssl_context = ssl_context
        super().__init__(
            server_address,
            handler_class,
            allowed_networks=allowed_networks,
            timeout_seconds=timeout_seconds,
            verbose=verbose,
            debug=debug,
            proxy_label=proxy_label,
            router_config=router_config,
            runtime=runtime,
        )

    def get_request(self):
        raw_socket, client_address = super().get_request()
        try:
            return self.ssl_context.wrap_socket(raw_socket, server_side=True), client_address
        except ssl.SSLError:
            raw_socket.close()
            raise


class ProtocolServerView:
    def __init__(self, server, proxy_label: str):
        self._server = server
        self.allowed_networks = server.allowed_networks
        self.timeout_seconds = server.timeout_seconds
        self.verbose = server.verbose
        self.debug = server.debug
        self.proxy_label = proxy_label
        self.client_tracker = server.client_trackers[proxy_label]
        self.router_config = server.router_config
        self.runtime = server.runtime
        self.history_cache = server.history_cache


class ThreadedMixedProxyServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True
    address_family = socket.AF_INET

    def __init__(self, server_address, *, allowed_networks, timeout_seconds, verbose, debug, router_config, runtime):
        super().__init__(server_address, socketserver.BaseRequestHandler)
        self.allowed_networks = allowed_networks
        self.timeout_seconds = timeout_seconds
        self.verbose = verbose
        self.debug = debug
        self.router_config = router_config
        self.runtime = runtime
        self.history_cache = UsageHistoryCache(runtime.usage_log_path)
        self.client_trackers = {
            "http": ClientTracker("http", runtime),
            "socks5": ClientTracker("socks5", runtime),
        }
        self._protocol_views = {
            "http": ProtocolServerView(self, "http"),
            "socks5": ProtocolServerView(self, "socks5"),
        }

    def finish_request(self, request, client_address):
        protocol = self.detect_protocol(request)
        handler_class = Socks5RequestHandler if protocol == "socks5" else ProxyRequestHandler
        handler_class(request, client_address, self._protocol_views[protocol])

    def detect_protocol(self, request) -> str:
        try:
            first_byte = request.recv(1, socket.MSG_PEEK)
        except OSError:
            return "http"

        if first_byte == bytes([SOCKS_VERSION]):
            return "socks5"

        return "http"


class ProxyRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "proxy-router/1.0"

    def _client_label(self) -> str:
        return format_client_address(self.client_address)

    def _debug(self, message: str, *, level: str = "DEBUG"):
        if self.server.debug:
            debug_log(self.server.proxy_label, f"{self._client_label()} - {message}", level=level)

    def handle(self):
        self.server.client_tracker.connected(self.client_address[0])
        try:
            super().handle()
        finally:
            self.server.client_tracker.disconnected(self.client_address[0])

    def log_message(self, fmt, *args):
        if self.server.verbose:
            log_event(
                self.server.proxy_label,
                f"{self.client_address[0]} - {fmt % args}",
            )

    def do_CONNECT(self):
        if not self._check_client_allowed():
            return

        request_started = time.monotonic()
        try:
            host, port = split_host_port(self.path, 443)
            if self._is_client_portal_connect_target(host, port):
                self._handle_client_portal_connect_request(host, port)
                return
            if not self._check_client_traffic_limit(
                method="CONNECT",
                destination=f"{host}:{port}",
                host=host,
                port=port,
            ):
                return
            route_decision = self._resolve_route(host, port)
            self._debug(f"request-line={truncate_for_log(self.requestline)}")
            self._debug(f"request-headers={format_headers_for_log(self.headers)}")
            self._log_http_event(f"CONNECT {host}:{port} via {route_decision['route_label']}")
            if route_decision["action"] in {"reject", "block"}:
                self._reject_routed_request(
                    method="CONNECT",
                    destination=f"{host}:{port}",
                    host=host,
                    port=port,
                    route_decision=route_decision,
                )
                return
            upstream_owner = None
            upstream = None
            try:
                upstream, upstream_owner = self._open_routed_stream(host, port, route_decision)
                local_bind = format_client_address(upstream.getsockname())
                remote_peer = format_client_address(upstream.getpeername())
                self._debug(
                    f"CONNECT upstream established target={host}:{port} route={route_decision['route_label']} "
                    f"local-bind={local_bind} remote-peer={remote_peer}"
                )
                self.send_response(200, "Connection Established")
                self.end_headers()
                stats = tunnel_bidirectional(self.connection, upstream)
                duration_ms = int((time.monotonic() - request_started) * 1000)
                self._debug(
                    "CONNECT tunnel closed "
                    f"duration_ms={duration_ms} "
                    f"client_to_upstream_bytes={stats['left_to_right_bytes']} "
                    f"upstream_to_client_bytes={stats['right_to_left_bytes']}"
                )
                self.server.runtime.record_usage(
                    proxy_label=self.server.proxy_label,
                    kind="connect",
                    client=self.client_address[0],
                    destination=f"{host}:{port}",
                    uploaded_bytes=stats["left_to_right_bytes"],
                    downloaded_bytes=stats["right_to_left_bytes"],
                    method="CONNECT",
                    route_label=route_decision["route_label"],
                    matched_rule=route_decision["matched_rule"],
                    profile_id=route_decision.get("profile_id"),
                )
                self.server.runtime.record_auto_proxy_success(host, route_decision)
            finally:
                if upstream_owner is not None:
                    upstream_owner.close()
                elif upstream is not None:
                    upstream.close()
        except Exception as exc:
            self._send_gateway_error(
                exc,
                context=f"CONNECT {host}:{port}" if "host" in locals() else "CONNECT",
                method="CONNECT",
                destination=f"{host}:{port}" if "host" in locals() else "CONNECT",
                host=host if "host" in locals() else None,
                port=port if "port" in locals() else None,
                route_decision=route_decision if "route_decision" in locals() else None,
            )

    def do_GET(self):
        self._forward_http_request()

    def do_HEAD(self):
        self._forward_http_request()

    def do_POST(self):
        self._forward_http_request()

    def do_PUT(self):
        self._forward_http_request()

    def do_PATCH(self):
        self._forward_http_request()

    def do_DELETE(self):
        self._forward_http_request()

    def do_OPTIONS(self):
        self._forward_http_request()

    def _prefers_html_error_response(self) -> bool:
        accept = self.headers.get("Accept", "")
        if "text/html" in accept or "application/xhtml+xml" in accept:
            return True

        sec_fetch_dest = self.headers.get("Sec-Fetch-Dest", "").strip().lower()
        return sec_fetch_dest == "document"

    def _send_body_response(
        self,
        code: int,
        reason: str,
        body: bytes | None,
        *,
        content_type: str,
        extra_headers: dict | None = None,
    ):
        try:
            self.send_response(code, reason)
            self.send_header("Content-Type", content_type)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            if extra_headers is not None:
                for key, value in extra_headers.items():
                    self.send_header(key, value)
            if body is not None:
                self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if body is not None and self.command != "HEAD":
                self.wfile.write(body)
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            log_event(
                self.server.proxy_label,
                f"{self._client_label()} - client disconnected before response could be sent",
            )

    def _build_client_traffic_limit_headers(self, evaluation, message: str) -> dict[str, str]:
        headers = {
            "X-Proxy-Error": "client-traffic-limit",
            "X-Proxy-Error-Message": sanitize_http_header_value(message),
            "X-Proxy-Client": self.client_address[0],
        }
        retry_after_seconds = evaluation.get("retry_after_seconds")
        if retry_after_seconds is not None:
            headers["Retry-After"] = str(retry_after_seconds)
            headers["X-Proxy-Retry-After"] = str(retry_after_seconds)
        return headers

    def _send_json_response(self, payload, *, status: int = 200):
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        self._send_body_response(
            status,
            "OK" if status == 200 else "Response",
            body,
            content_type="application/json; charset=utf-8",
        )

    def _is_websocket_upgrade(self) -> bool:
        upgrade = str(self.headers.get("Upgrade") or "").strip().lower()
        connection = str(self.headers.get("Connection") or "").strip().lower()
        return upgrade == "websocket" and "upgrade" in connection

    def _send_websocket_json(self, payload):
        body = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        self.connection.sendall(encode_websocket_text_frame(body))

    def _is_client_portal_connect_target(self, host: str, port: int) -> bool:
        if not self.server.runtime.self_endpoints.is_client_portal_host(host):
            return False
        return int(port) == 80 or int(port) in self.server.runtime.self_endpoints.proxy_listener_ports

    def _handle_client_portal_connect_request(self, host: str, port: int):
        self._debug(f"CONNECT client portal tunnel target={host}:{port}")
        self.send_response(200, "Connection Established")
        self.end_headers()

        try:
            self.close_connection = True
            self.raw_requestline = self.rfile.readline(65537)
            if len(self.raw_requestline) > 65536:
                self.requestline = ""
                self.request_version = ""
                self.command = ""
                self.send_error(414)
                return
            if not self.raw_requestline:
                return
            if not self.parse_request():
                return

            scheme, inner_host, inner_port, target_path = self._extract_target()
            if self._handle_client_portal_request(scheme, inner_host, inner_port, target_path):
                return
            self._send_body_response(
                404,
                "Not Found",
                b"Not Found\n",
                content_type="text/plain; charset=utf-8",
            )
        finally:
            self.close_connection = True

    def _handle_client_portal_live_websocket(self, *, range_key: str):
        websocket_key = str(self.headers.get("Sec-WebSocket-Key") or "").strip()
        if not websocket_key:
            self.send_error(400, "Missing Sec-WebSocket-Key header")
            return

        accept_seed = websocket_key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        accept_value = base64.b64encode(hashlib.sha1(accept_seed.encode("utf-8")).digest()).decode("ascii")

        self.send_response(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept_value)
        self.end_headers()

        try:
            self.connection.settimeout(DASHBOARD_LIVE_HEARTBEAT_SECONDS + 5.0)
        except OSError:
            pass

        client_ip = self.client_address[0]
        last_revision = self.server.runtime.live_updates.current_revision()
        self._send_websocket_json(
            build_client_live_update_message(
                self.server,
                client_ip,
                range_key,
                {"revision": last_revision},
                initial=True,
            )
        )

        while True:
            event_summary = self.server.runtime.live_updates.wait_for_changes(
                last_revision,
                timeout=DASHBOARD_LIVE_HEARTBEAT_SECONDS,
            )
            if event_summary is None:
                self._send_websocket_json(
                    {
                        "type": "heartbeat",
                        "revision": last_revision,
                    }
                )
                continue

            last_revision = int(event_summary["revision"])
            self._send_websocket_json(
                build_client_live_update_message(self.server, client_ip, range_key, event_summary)
            )

    def _handle_client_portal_request(self, scheme: str, host: str, port: int, target_path: str) -> bool:
        if self.command not in {"GET", "HEAD"} or scheme != "http":
            return False

        self_target_kind = self.server.runtime.self_endpoints.resolve_target_kind(host, port)
        is_alias_host = self.server.runtime.self_endpoints.is_client_portal_host(host)
        if not is_alias_host and self_target_kind != "listener":
            return False

        parsed = urlsplit(target_path or "/")
        route_path = parsed.path or "/"
        query = parse_qs(parsed.query)
        html_paths = {"/", "/index.html", "/client", "/client/"}
        json_paths = {"/api/client", "/api/client.json", "/client.json"}
        live_paths = {"/api/client/live", "/client.live"}

        if route_path == "/favicon.ico":
            self._send_body_response(204, "No Content", None, content_type="image/x-icon")
            return True

        range_key = first_query_value(query, "range") or HISTORY_DEFAULT_RANGE
        if route_path in live_paths:
            if not self._is_websocket_upgrade():
                self._send_body_response(
                    400,
                    "Bad Request",
                    b"Expected a WebSocket upgrade request\n",
                    content_type="text/plain; charset=utf-8",
                )
                return True
            try:
                self._handle_client_portal_live_websocket(range_key=range_key)
            except (BrokenPipeError, ConnectionResetError, socket.timeout, OSError):
                return True
            return True

        if route_path not in html_paths and route_path not in json_paths:
            if is_alias_host:
                self._send_body_response(
                    404,
                    "Not Found",
                    b"Not Found\n",
                    content_type="text/plain; charset=utf-8",
                )
                return True
            return False

        payload = build_client_portal_snapshot(
            self.server,
            self.client_address[0],
            range_key=range_key,
        )
        self._log_http_event(f"served client portal {route_path} for {self.client_address[0]}")
        if route_path in json_paths or str(first_query_value(query, "format") or "").strip().lower() == "json":
            self._send_json_response(payload)
            return True

        document = render_client_portal_html(payload)
        self._send_body_response(
            200,
            "OK",
            document.encode("utf-8"),
            content_type="text/html; charset=utf-8",
        )
        return True

    def _check_client_allowed(self) -> bool:
        if ensure_client_allowed(self.client_address[0], self.server.allowed_networks):
            return True

        self._debug(
            "client denied by allowlist "
            f"allowed={', '.join(str(network) for network in self.server.allowed_networks) or '<none>'}",
            level="WARNING",
        )
        self._safe_send_error_response(403, "Client IP is not allowed to use this proxy.")
        return False

    def _check_client_traffic_limit(self, *, method: str, destination: str, host: str | None, port: int | None) -> bool:
        evaluation = self.server.runtime.traffic_quota_manager.evaluate_client(self.client_address[0], self.server.router_config)
        if evaluation["allowed"]:
            return True

        self._reject_client_traffic_limit(
            method=method,
            destination=destination,
            host=host,
            port=port,
            evaluation=evaluation,
        )
        return False

    def _reject_client_traffic_limit(
        self,
        *,
        method: str,
        destination: str,
        host: str | None,
        port: int | None,
        evaluation,
    ):
        limit = evaluation.get("limit") or {}
        target_label = limit.get("client", self.client_address[0])
        message = build_client_traffic_limit_message(evaluation)
        log_event(
            self.server.proxy_label,
            f"{self._client_label()} - blocked by client traffic limit {target_label} for {destination}",
        )
        self.server.runtime.record_failure(
            proxy_label=self.server.proxy_label,
            client=self.client_address[0],
            method=method,
            destination=destination,
            host=host,
            port=port,
            error=message,
            context="client traffic limit",
            route_label=CLIENT_TRAFFIC_ROUTE_LABEL,
            matched_rule=None,
            profile_id=DEFAULT_ROUTING_PROFILE_ID,
        )
        extra_headers = self._build_client_traffic_limit_headers(evaluation, message)

        if method != "CONNECT" and self._prefers_html_error_response():
            document = render_client_traffic_limit_html(
                client_ip=self.client_address[0],
                evaluation=evaluation,
                destination=destination,
            )
            self._send_body_response(
                429,
                "Client Traffic Limit Reached",
                document.encode("utf-8"),
                content_type="text/html; charset=utf-8",
                extra_headers=extra_headers,
            )
            return

        self._send_body_response(
            429,
            "Client Traffic Limit Reached",
            (message + "\n").encode("utf-8"),
            content_type="text/plain; charset=utf-8",
            extra_headers=extra_headers,
        )

    def _forward_http_request(self):
        if not self._check_client_allowed():
            return

        request_started = time.monotonic()
        try:
            self._debug(f"request-line={truncate_for_log(self.requestline)}")
            self._debug(f"request-headers={format_headers_for_log(self.headers)}")
            scheme, host, port, target_path = self._extract_target()
            if self._handle_client_portal_request(scheme, host, port, target_path):
                return
            if not self._check_client_traffic_limit(
                method=self.command,
                destination=f"{scheme}://{host}:{port}{target_path}",
                host=host,
                port=port,
            ):
                return
            route_decision = self._resolve_route(host, port)
            body, outbound_headers, body_details, request_body_bytes = self._prepare_outbound_body_and_headers(
                host, port
            )
            self._log_http_event(
                f"{self.command} {scheme}://{host}:{port}{target_path} via {route_decision['route_label']}"
            )
            if route_decision["action"] in {"reject", "block"}:
                self._reject_routed_request(
                    method=self.command,
                    destination=f"{scheme}://{host}:{port}{target_path}",
                    host=host,
                    port=port,
                    route_decision=route_decision,
                )
                return
            self._debug(
                f"resolved-target scheme={scheme} host={host} port={port} path={truncate_for_log(target_path)}"
            )
            self._debug(f"outbound-headers={format_headers_for_log(outbound_headers)}")
            self._debug(body_details)
            connection, response = self._perform_upstream_request(
                scheme,
                host,
                port,
                target_path,
                body,
                outbound_headers,
                route_decision=route_decision,
            )
            self._write_response(
                connection,
                response,
                request_started=request_started,
                target_description=f"{scheme}://{host}:{port}{target_path}",
                target_host=host,
                target_port=port,
                request_body_bytes=request_body_bytes,
                method=self.command,
                route_decision=route_decision,
            )
        except Exception as exc:
            destination = "forward request"
            if {"scheme", "host", "port", "target_path"} <= locals().keys():
                destination = f"{scheme}://{host}:{port}{target_path}"
            self._send_gateway_error(
                exc,
                context="forward request",
                method=self.command,
                destination=destination,
                host=host if "host" in locals() else None,
                port=port if "port" in locals() else None,
                route_decision=route_decision if "route_decision" in locals() else None,
            )

    def _extract_target(self):
        self._debug(f"raw-path={truncate_for_log(self.path)}")
        parsed = urlsplit(self.path)

        if parsed.scheme and parsed.netloc:
            scheme = parsed.scheme.lower()
            host, port = split_host_port(parsed.netloc, 443 if scheme == "https" else 80)
            path = parsed.path or "/"
            if parsed.query:
                path = f"{path}?{parsed.query}"
            return scheme, host, port, path

        host_header = self.headers.get("Host", "").strip()
        if not host_header:
            raise ValueError("missing Host header")

        host, port = split_host_port(host_header, 80)
        self._debug(f"origin-form request using Host header {truncate_for_log(host_header)}")
        return "http", host, port, self.path or "/"

    def _read_request_body(self):
        content_length = self.headers.get("Content-Length")
        if not content_length:
            return None

        length = int(content_length)
        if length <= 0:
            return None

        return self.rfile.read(length)

    def _read_chunked_request_body(self):
        chunks = bytearray()

        while True:
            line = self.rfile.readline()
            if not line:
                raise ValueError("unexpected end of stream while reading chunk size")

            size_text = line.split(b";", 1)[0].strip()
            try:
                chunk_size = int(size_text, 16)
            except ValueError as exc:
                raise ValueError("invalid chunk size in request body") from exc

            if chunk_size == 0:
                while True:
                    trailer_line = self.rfile.readline()
                    if not trailer_line or trailer_line in {b"\r\n", b"\n"}:
                        return bytes(chunks)
                break

            chunks.extend(self.rfile.read(chunk_size))
            terminator = self.rfile.read(2)
            if terminator != b"\r\n":
                raise ValueError("invalid chunk terminator in request body")

    def _prepare_outbound_body_and_headers(self, host, port):
        outbound_headers = {
            key: value
            for key, value in self.headers.items()
            if key.lower() not in HOP_BY_HOP_HEADERS
        }
        outbound_headers["Host"] = host if port in {80, 443} else f"{host}:{port}"
        outbound_headers["Connection"] = "close"

        transfer_encoding = self.headers.get("Transfer-Encoding", "")
        if "chunked" in transfer_encoding.lower():
            body = self._read_chunked_request_body()
            outbound_headers.pop("Transfer-Encoding", None)
            outbound_headers.pop("transfer-encoding", None)
            outbound_headers["Content-Length"] = str(len(body))
            return (
                body,
                outbound_headers,
                f"request-body mode=chunked normalized_content_length={len(body)}",
                len(body),
            )

        body = self._read_request_body()
        body_length = len(body) if body is not None else 0
        content_length = self.headers.get("Content-Length", "<none>")
        return (
            body,
            outbound_headers,
            f"request-body mode=content-length header={content_length} bytes={body_length}",
            body_length,
        )

    def _resolve_route(self, host: str, port: int):
        self_target_kind = self.server.runtime.self_endpoints.resolve_target_kind(host, port)
        if self_target_kind == "dashboard":
            route_decision = {
                "host": normalize_host(host),
                "action": "direct",
                "matched_rule": None,
                "upstream": None,
                "profile_id": DEFAULT_ROUTING_PROFILE_ID,
                "profile_name": "Shared",
                "route_label": "self:dashboard-direct",
                "connect_host": self.server.runtime.self_endpoints.dashboard_connect_host,
                "connect_port": port,
            }
            self._debug(
                f"route host={host} port={port} matched=<self-dashboard> action={route_decision['route_label']}"
            )
            return route_decision

        if self_target_kind == "listener":
            route_decision = {
                "host": normalize_host(host),
                "action": "reject",
                "matched_rule": None,
                "upstream": None,
                "profile_id": DEFAULT_ROUTING_PROFILE_ID,
                "profile_name": "Shared",
                "route_label": "self:listener-block",
                "connect_host": host,
                "connect_port": port,
            }
            self._debug(
                f"route host={host} port={port} matched=<self-listener> action={route_decision['route_label']}"
            )
            return route_decision

        route_decision = self.server.router_config.decide(host)
        route_decision = self.server.runtime.apply_auto_proxy_probe_route(host, route_decision)
        matched_rule = route_decision["matched_rule"]
        route_decision["connect_host"] = host
        route_decision["connect_port"] = port
        if route_decision.get("auto_proxy_probe"):
            self._debug(f"route host={host} matched=<auto-probe> action={route_decision['route_label']}")
        elif matched_rule is None:
            self._debug(f"route host={host} matched=<default> action={route_decision['route_label']}")
        else:
            self._debug(
                "route "
                f"host={host} match={matched_rule['match']}:{matched_rule['pattern']} "
                f"action={route_decision['route_label']}"
            )
        return route_decision

    def _reject_routed_request(self, *, method: str, destination: str, host: str | None, port: int | None, route_decision):
        is_self_target = route_decision["route_label"] == "self:listener-block"
        if is_self_target:
            message = (
                "Refusing to proxy a request back into proxy-router itself. "
                "Use the dashboard port directly for the panel and do not target the proxy listener as an upstream."
            )
            log_message = f"{self._client_label()} - blocked self-targeted request for {destination}"
            response_code = 508
        else:
            rule = route_decision.get("matched_rule") or {}
            rule_label = f"{rule.get('match', 'rule')}:{rule.get('pattern', host or destination)}"
            message = f"Request blocked by proxy-router rule {rule_label}."
            log_message = f"{self._client_label()} - blocked routed request for {destination} via {rule_label}"
            response_code = 403
        log_event(self.server.proxy_label, log_message)
        self.server.runtime.record_failure(
            proxy_label=self.server.proxy_label,
            client=self.client_address[0],
            method=method,
            destination=destination,
            host=host,
            port=port,
            error=message,
            context="self-target protection",
            route_label=route_decision["route_label"],
            matched_rule=route_decision["matched_rule"],
            profile_id=route_decision.get("profile_id"),
        )
        if is_self_target and method in {"GET", "HEAD"} and self.server.runtime.self_endpoints.dashboard_url is not None:
            self.send_response(307, "Temporary Redirect")
            self.send_header("Location", self.server.runtime.self_endpoints.dashboard_url)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.end_headers()
            return
        self._safe_send_error_response(response_code, message)

    def _open_routed_stream(self, host: str, port: int, route_decision):
        def open_once(_attempt):
            return self._open_routed_stream_once(host, port, route_decision)

        return retry_upstream_operation(
            open_once,
            on_retry=lambda attempt, attempts, delay, exc: self._debug(
                "retrying upstream stream setup "
                f"attempt={attempt + 1}/{attempts} delay={delay:.2f}s "
                f"target={host}:{port} route={route_decision['route_label']} error={exc}",
                level="WARNING",
            ),
        )

    def _open_routed_stream_once(self, host: str, port: int, route_decision):
        connect_host = route_decision.get("connect_host", host)
        connect_port = route_decision.get("connect_port", port)
        if route_decision["action"] != "proxy":
            return socket.create_connection((connect_host, connect_port), timeout=self.server.timeout_seconds), None

        upstream = route_decision["upstream"]
        if upstream is None:
            raise OSError("router selected proxy, but no upstream proxy is configured")

        if upstream["type"] == "http":
            connection = create_http_proxy_tunnel(
                upstream["host"],
                upstream["port"],
                host,
                port,
                self.server.timeout_seconds,
            )
            self.server.runtime.record_upstream_route_success(
                route_decision,
                destination=f"{host}:{port}",
                proxy_label=self.server.proxy_label,
            )
            return connection.sock, connection

        upstream_socket = create_socks5_proxy_connection(
            upstream["host"],
            upstream["port"],
            host,
            port,
            self.server.timeout_seconds,
        )
        self.server.runtime.record_upstream_route_success(
            route_decision,
            destination=f"{host}:{port}",
            proxy_label=self.server.proxy_label,
        )
        return upstream_socket, None

    def _perform_upstream_request(self, scheme, host, port, target_path, body, outbound_headers, *, route_decision):
        should_retry = lambda exc: can_retry_http_request(self.command, body) and is_retryable_upstream_error(exc)

        return retry_upstream_operation(
            lambda _attempt: self._perform_upstream_request_once(
                scheme,
                host,
                port,
                target_path,
                body,
                outbound_headers,
                route_decision=route_decision,
            ),
            should_retry=should_retry,
            on_retry=lambda attempt, attempts, delay, exc: self._debug(
                "retrying upstream HTTP request "
                f"attempt={attempt + 1}/{attempts} delay={delay:.2f}s "
                f"method={self.command} target={host}:{port} route={route_decision['route_label']} error={exc}",
                level="WARNING",
            ),
        )

    def _perform_upstream_request_once(self, scheme, host, port, target_path, body, outbound_headers, *, route_decision):
        request_target = target_path
        connection_kwargs = {"timeout": self.server.timeout_seconds}
        connect_host = route_decision.get("connect_host", host)
        connect_port = route_decision.get("connect_port", port)
        connection = None
        if route_decision["action"] == "proxy":
            upstream = route_decision["upstream"]
            if upstream is None:
                raise OSError("router selected proxy, but no upstream proxy is configured")

            if upstream["type"] == "http":
                connection_class = http.client.HTTPConnection
                connection = connection_class(upstream["host"], upstream["port"], **connection_kwargs)
                default_port = 443 if scheme == "https" else 80
                authority = host if port == default_port else f"{host}:{port}"
                request_target = f"{scheme}://{authority}{target_path}"
            else:
                upstream_socket = create_socks5_proxy_connection(
                    upstream["host"],
                    upstream["port"],
                    host,
                    port,
                    self.server.timeout_seconds,
                )
                if scheme == "https":
                    connection = PreconnectedHTTPSConnection(
                        host,
                        port=port,
                        preconnected_socket=upstream_socket,
                        timeout=self.server.timeout_seconds,
                        context=ssl.create_default_context(),
                    )
                else:
                    connection = PreconnectedHTTPConnection(
                        host,
                        port=port,
                        preconnected_socket=upstream_socket,
                        timeout=self.server.timeout_seconds,
                    )
        else:
            connection_class = http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection
            if scheme == "https":
                connection_kwargs["context"] = ssl.create_default_context()
            connection = connection_class(connect_host, connect_port, **connection_kwargs)

        upstream_started = time.monotonic()
        self._debug(
            f"opening upstream request route={route_decision['route_label']} target={host}:{port} "
            f"request_target={truncate_for_log(request_target)} timeout={self.server.timeout_seconds}s"
        )
        try:
            connection.request(self.command, request_target, body=body, headers=outbound_headers)
            response = connection.getresponse()
            upstream_elapsed_ms = int((time.monotonic() - upstream_started) * 1000)
            self._debug(
                f"upstream response status={response.status} reason={truncate_for_log(response.reason)} "
                f"elapsed_ms={upstream_elapsed_ms}"
            )
            self._debug(f"upstream response headers={format_headers_for_log(response.headers)}")
            self.server.runtime.record_upstream_route_success(
                route_decision,
                destination=f"{host}:{port}",
                proxy_label=self.server.proxy_label,
            )
            return connection, response
        except Exception:
            if connection is not None:
                connection.close()
            raise

    def _write_response(
        self,
        connection,
        response,
        *,
        request_started: float,
        target_description: str,
        target_host: str | None,
        target_port: int | None,
        request_body_bytes: int,
        method: str,
        route_decision,
    ):
        bytes_written = 0
        try:
            if response.status == 403:
                self.server.runtime.record_failure(
                    proxy_label=self.server.proxy_label,
                    client=self.client_address[0],
                    method=method,
                    destination=target_description,
                    host=target_host,
                    port=target_port,
                    error=f"Upstream responded with HTTP 403 {response.reason or 'Forbidden'}",
                    context="upstream http 403",
                    route_label=route_decision["route_label"],
                    matched_rule=route_decision["matched_rule"],
                    profile_id=route_decision.get("profile_id"),
                )
            self.send_response(response.status, response.reason)
            for key, value in response.getheaders():
                if key.lower() in HOP_BY_HOP_HEADERS:
                    continue
                self.send_header(key, value)
            self.send_header("Connection", "close")
            self.end_headers()

            while True:
                chunk = response.read(BUFFER_SIZE)
                if not chunk:
                    break
                self.wfile.write(chunk)
                bytes_written += len(chunk)
            self.wfile.flush()
            total_elapsed_ms = int((time.monotonic() - request_started) * 1000)
            self._debug(
                f"response relayed target={truncate_for_log(target_description)} status={response.status} "
                f"bytes={bytes_written} total_elapsed_ms={total_elapsed_ms}"
            )
        except (BrokenPipeError, ConnectionResetError):
            log_event(
                self.server.proxy_label,
                f"{self._client_label()} - client disconnected while receiving upstream response",
            )
            self._debug(
                f"client disconnected while receiving upstream response bytes_sent={bytes_written}",
                level="INFO",
            )
        finally:
            self.server.runtime.record_usage(
                proxy_label=self.server.proxy_label,
                kind="http",
                client=self.client_address[0],
                destination=target_description,
                uploaded_bytes=request_body_bytes,
                downloaded_bytes=bytes_written,
                method=method,
                route_label=route_decision["route_label"],
                matched_rule=route_decision["matched_rule"],
                profile_id=route_decision.get("profile_id"),
            )
            if response.status != 403:
                self.server.runtime.record_auto_proxy_success(target_host, route_decision)
            response.close()
            connection.close()

    def _send_gateway_error(
        self,
        exc: Exception,
        *,
        context: str,
        method: str,
        destination: str,
        host: str | None,
        port: int | None,
        route_decision=None,
    ):
        log_event(
            self.server.proxy_label,
            f"{self._client_label()} - proxy error during {context}: {exc}",
        )
        debug_exception(self.server.proxy_label, f"{self._client_label()} - proxy error during {context}", exc)
        route_label = route_decision["route_label"] if route_decision is not None else "direct"
        matched_rule = route_decision["matched_rule"] if route_decision is not None else None
        profile_id = route_decision.get("profile_id") if route_decision is not None else DEFAULT_ROUTING_PROFILE_ID
        error_message = self._describe_upstream_error(exc)
        self.server.runtime.record_upstream_route_failure(
            route_decision,
            destination=destination,
            error=error_message,
            context=context,
            proxy_label=self.server.proxy_label,
        )
        self.server.runtime.record_failure(
            proxy_label=self.server.proxy_label,
            client=self.client_address[0],
            method=method,
            destination=destination,
            host=host,
            port=port,
            error=error_message,
            context=context,
            route_label=route_label,
            matched_rule=matched_rule,
            profile_id=profile_id,
        )
        self._safe_send_error_response(502, error_message)

    def _log_http_event(self, message: str):
        if self.server.verbose:
            log_event(
                self.server.proxy_label,
                f"{self._client_label()} - {message}",
            )

    def _safe_send_error_response(self, code: int, message: str):
        try:
            self.send_error(code, message)
        except (BrokenPipeError, ConnectionResetError):
            log_event(
                self.server.proxy_label,
                f"{self._client_label()} - client disconnected before error response could be sent",
            )

    def _describe_upstream_error(self, exc: Exception) -> str:
        if isinstance(exc, TimeoutError):
            return "Upstream connection timed out."

        if isinstance(exc, socket.gaierror):
            return "Failed to resolve the upstream host."

        if isinstance(exc, OSError):
            if exc.errno == errno.ENETUNREACH:
                return "Network is unreachable from this machine."
            if exc.errno == errno.EHOSTUNREACH:
                return "Upstream host is unreachable."
            if exc.errno == errno.ECONNREFUSED:
                return "Upstream server refused the connection."
            if exc.errno == errno.ECONNRESET:
                return "Upstream connection was reset."

        return f"Proxy error: {exc}"

class ThreadedSocks5Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True
    address_family = socket.AF_INET

    def __init__(
        self,
        server_address,
        handler_class,
        *,
        allowed_networks,
        timeout_seconds,
        verbose,
        debug,
        router_config,
        runtime,
    ):
        super().__init__(server_address, handler_class)
        self.allowed_networks = allowed_networks
        self.timeout_seconds = timeout_seconds
        self.verbose = verbose
        self.debug = debug
        self.proxy_label = "socks5"
        self.runtime = runtime
        self.client_tracker = ClientTracker(self.proxy_label, runtime)
        self.router_config = router_config

class Socks5RequestHandler(socketserver.BaseRequestHandler):
    def _client_label(self) -> str:
        return format_client_address(self.client_address)

    def _debug(self, message: str, *, level: str = "DEBUG"):
        if self.server.debug:
            debug_log(self.server.proxy_label, f"{self._client_label()} - {message}", level=level)

    def handle(self):
        client_ip = self.client_address[0]
        self.server.client_tracker.connected(client_ip)
        try:
            if not ensure_client_allowed(client_ip, self.server.allowed_networks):
                self._log("denied")
                self._debug(
                    "client denied by allowlist "
                    f"allowed={', '.join(str(network) for network in self.server.allowed_networks) or '<none>'}",
                    level="WARNING",
                )
                return

            self.request.settimeout(self.server.timeout_seconds)

            version = self._read_exact(1)[0]
            if version != SOCKS_VERSION:
                raise ValueError("unsupported SOCKS version")

            methods_count = self._read_exact(1)[0]
            methods = self._read_exact(methods_count)
            self._debug(f"handshake methods={list(methods)}")
            if 0 not in methods:
                self.request.sendall(bytes([SOCKS_VERSION, 0xFF]))
                return

            self.request.sendall(bytes([SOCKS_VERSION, 0x00]))

            version, command, _, address_type = self._read_exact(4)
            if version != SOCKS_VERSION:
                raise ValueError("unsupported SOCKS version")
            if command != SOCKS_CMD_CONNECT:
                self._send_reply(0x07)
                return

            destination_host = self._read_destination_host(address_type)
            destination_port = int.from_bytes(self._read_exact(2), "big")
            quota_evaluation = self.server.runtime.traffic_quota_manager.evaluate_client(
                self.client_address[0], self.server.router_config
            )
            if not quota_evaluation["allowed"]:
                message = build_client_traffic_limit_message(quota_evaluation)
                self.server.runtime.record_failure(
                    proxy_label=self.server.proxy_label,
                    client=self.client_address[0],
                    method="CONNECT",
                    destination=f"{destination_host}:{destination_port}",
                    host=destination_host,
                    port=destination_port,
                    error=message,
                    context="client traffic limit",
                    route_label=CLIENT_TRAFFIC_ROUTE_LABEL,
                    matched_rule=None,
                    profile_id=DEFAULT_ROUTING_PROFILE_ID,
                )
                self._send_reply(0x02)
                return
            self_target_kind = self.server.runtime.self_endpoints.resolve_target_kind(destination_host, destination_port)
            if self_target_kind == "dashboard":
                route_decision = {
                    "host": normalize_host(destination_host),
                    "action": "direct",
                    "matched_rule": None,
                    "upstream": None,
                    "profile_id": DEFAULT_ROUTING_PROFILE_ID,
                    "profile_name": "Shared",
                    "route_label": "self:dashboard-direct",
                    "connect_host": self.server.runtime.self_endpoints.dashboard_connect_host,
                    "connect_port": destination_port,
                }
                self._debug(
                    f"route host={destination_host} port={destination_port} "
                    f"matched=<self-dashboard> action={route_decision['route_label']}"
                )
            elif self_target_kind == "listener":
                route_decision = {
                    "host": normalize_host(destination_host),
                    "action": "reject",
                    "matched_rule": None,
                    "upstream": None,
                    "profile_id": DEFAULT_ROUTING_PROFILE_ID,
                    "profile_name": "Shared",
                    "route_label": "self:listener-block",
                    "connect_host": destination_host,
                    "connect_port": destination_port,
                }
                self._debug(
                    f"route host={destination_host} port={destination_port} "
                    f"matched=<self-listener> action={route_decision['route_label']}"
                )
            else:
                route_decision = self.server.router_config.decide(destination_host)
                route_decision = self.server.runtime.apply_auto_proxy_probe_route(
                    destination_host,
                    route_decision,
                )
                route_decision["connect_host"] = destination_host
                route_decision["connect_port"] = destination_port
                matched_rule = route_decision["matched_rule"]
                if route_decision.get("auto_proxy_probe"):
                    self._debug(
                        f"route host={destination_host} matched=<auto-probe> action={route_decision['route_label']}"
                    )
                elif matched_rule is None:
                    self._debug(
                        f"route host={destination_host} matched=<default> action={route_decision['route_label']}"
                    )
                else:
                    self._debug(
                        "route "
                        f"host={destination_host} match={matched_rule['match']}:{matched_rule['pattern']} "
                        f"action={route_decision['route_label']}"
                    )
            self._debug(f"CONNECT destination={destination_host}:{destination_port}")
            if route_decision["action"] in {"reject", "block"}:
                if route_decision["route_label"] == "self:listener-block":
                    message = (
                        "Refusing to proxy a SOCKS5 request back into proxy-router itself. "
                        "Use the dashboard port directly for the panel and do not target the proxy listener as an upstream."
                    )
                    reply_code = 0x01
                    context = "self-target protection"
                else:
                    rule = route_decision.get("matched_rule") or {}
                    rule_label = f"{rule.get('match', 'rule')}:{rule.get('pattern', destination_host)}"
                    message = f"SOCKS5 request blocked by proxy-router rule {rule_label}."
                    reply_code = 0x02
                    context = "router block rule"
                self.server.runtime.record_failure(
                    proxy_label=self.server.proxy_label,
                    client=self.client_address[0],
                    method="CONNECT",
                    destination=f"{destination_host}:{destination_port}",
                    host=destination_host,
                    port=destination_port,
                    error=message,
                    context=context,
                    route_label=route_decision["route_label"],
                    matched_rule=route_decision["matched_rule"],
                    profile_id=route_decision.get("profile_id"),
                )
                self._send_reply(reply_code)
                return
            upstream_owner = None
            upstream = None
            try:
                upstream, upstream_owner = self._open_routed_stream(
                    destination_host,
                    destination_port,
                    route_decision,
                )

                bind_host, bind_port = upstream.getsockname()[:2]
                self._send_success_reply(bind_host, bind_port)
                self._log(f"connect {destination_host}:{destination_port} via {route_decision['route_label']}")
                self.server.runtime.record_upstream_route_success(
                    route_decision,
                    destination=f"{destination_host}:{destination_port}",
                    proxy_label=self.server.proxy_label,
                )
                stats = tunnel_bidirectional(self.request, upstream)
                self._debug(
                    "tunnel closed "
                    f"client_to_upstream_bytes={stats['left_to_right_bytes']} "
                    f"upstream_to_client_bytes={stats['right_to_left_bytes']}"
                )
                self.server.runtime.record_usage(
                    proxy_label=self.server.proxy_label,
                    kind="connect",
                    client=self.client_address[0],
                    destination=f"{destination_host}:{destination_port}",
                    uploaded_bytes=stats["left_to_right_bytes"],
                    downloaded_bytes=stats["right_to_left_bytes"],
                    method="CONNECT",
                    route_label=route_decision["route_label"],
                    matched_rule=route_decision["matched_rule"],
                    profile_id=route_decision.get("profile_id"),
                )
                self.server.runtime.record_auto_proxy_success(destination_host, route_decision)
            finally:
                if upstream_owner is not None:
                    upstream_owner.close()
                elif upstream is not None:
                    upstream.close()
        except (OSError, ValueError) as exc:
            if self._is_closed_socket_error(exc):
                self._debug(f"client disconnected before SOCKS5 reply could be sent: {exc}", level="INFO")
                return
            debug_exception(self.server.proxy_label, f"{self._client_label()} - SOCKS5 handler error", exc)
            self.server.runtime.record_upstream_route_failure(
                route_decision if "route_decision" in locals() else None,
                destination=(
                    f"{destination_host}:{destination_port}"
                    if "destination_host" in locals()
                    else "SOCKS5 CONNECT"
                ),
                error=str(exc),
                context="SOCKS5 CONNECT",
                proxy_label=self.server.proxy_label,
            )
            self.server.runtime.record_failure(
                proxy_label=self.server.proxy_label,
                client=self.client_address[0],
                method="CONNECT",
                destination=(
                    f"{destination_host}:{destination_port}"
                    if "destination_host" in locals()
                    else "SOCKS5 CONNECT"
                ),
                host=destination_host if "destination_host" in locals() else None,
                port=destination_port if "destination_port" in locals() else None,
                error=str(exc),
                context="SOCKS5 CONNECT",
                route_label=route_decision["route_label"] if "route_decision" in locals() else "direct",
                matched_rule=route_decision["matched_rule"] if "route_decision" in locals() else None,
                profile_id=route_decision.get("profile_id") if "route_decision" in locals() else DEFAULT_ROUTING_PROFILE_ID,
            )
            self._send_reply(0x01)
        finally:
            self.server.client_tracker.disconnected(client_ip)

    def _open_routed_stream(self, destination_host: str, destination_port: int, route_decision):
        def open_once(_attempt):
            return self._open_routed_stream_once(destination_host, destination_port, route_decision)

        return retry_upstream_operation(
            open_once,
            on_retry=lambda attempt, attempts, delay, exc: self._debug(
                "retrying SOCKS5 upstream stream setup "
                f"attempt={attempt + 1}/{attempts} delay={delay:.2f}s "
                f"target={destination_host}:{destination_port} route={route_decision['route_label']} error={exc}",
                level="WARNING",
            ),
        )

    def _open_routed_stream_once(self, destination_host: str, destination_port: int, route_decision):
        if route_decision["action"] == "proxy":
            proxy = route_decision["upstream"]
            if proxy is None:
                raise OSError("router selected proxy, but no upstream proxy is configured")
            if proxy["type"] == "http":
                upstream_owner = create_http_proxy_tunnel(
                    proxy["host"],
                    proxy["port"],
                    destination_host,
                    destination_port,
                    self.server.timeout_seconds,
                )
                return upstream_owner.sock, upstream_owner
            return (
                create_socks5_proxy_connection(
                    proxy["host"],
                    proxy["port"],
                    destination_host,
                    destination_port,
                    self.server.timeout_seconds,
                ),
                None,
            )

        return (
            socket.create_connection(
                (
                    route_decision.get("connect_host", destination_host),
                    route_decision.get("connect_port", destination_port),
                ),
                timeout=self.server.timeout_seconds,
            ),
            None,
        )

    def _read_exact(self, size: int) -> bytes:
        remaining = size
        chunks = []
        while remaining > 0:
            chunk = self.request.recv(remaining)
            if not chunk:
                raise OSError("connection closed")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def _read_destination_host(self, address_type: int) -> str:
        if address_type == SOCKS_ATYP_IPV4:
            return socket.inet_ntoa(self._read_exact(4))
        if address_type == SOCKS_ATYP_IPV6:
            return socket.inet_ntop(socket.AF_INET6, self._read_exact(16))
        if address_type == SOCKS_ATYP_DOMAIN:
            length = self._read_exact(1)[0]
            return self._read_exact(length).decode("utf-8")
        raise ValueError("unsupported address type")

    def _send_success_reply(self, bind_host: str, bind_port: int):
        try:
            packed_host = socket.inet_aton(bind_host)
            address_type = SOCKS_ATYP_IPV4
        except OSError:
            packed_host = socket.inet_pton(socket.AF_INET6, bind_host)
            address_type = SOCKS_ATYP_IPV6

        reply = bytearray([SOCKS_VERSION, 0x00, 0x00, address_type])
        reply.extend(packed_host)
        reply.extend(bind_port.to_bytes(2, "big"))
        try:
            self.request.sendall(reply)
        except (BrokenPipeError, ConnectionResetError, OSError) as exc:
            if self._is_closed_socket_error(exc):
                self._debug(f"client disconnected before SOCKS5 success reply: {exc}", level="INFO")
                return
            raise

    def _send_reply(self, reply_code: int):
        try:
            self.request.sendall(bytes([SOCKS_VERSION, reply_code, 0x00, SOCKS_ATYP_IPV4, 0, 0, 0, 0, 0, 0]))
        except (BrokenPipeError, ConnectionResetError, OSError) as exc:
            if self._is_closed_socket_error(exc):
                self._debug(f"client disconnected before SOCKS5 error reply: {exc}", level="INFO")
                return
            raise

    def _is_closed_socket_error(self, exc: Exception) -> bool:
        if isinstance(exc, (BrokenPipeError, ConnectionResetError)):
            return True
        if not isinstance(exc, OSError):
            return False
        message = str(exc).strip().lower()
        return message in {"connection closed", "broken pipe"} or "connection reset" in message

    def _log(self, message: str):
        if self.server.verbose:
            sys.stderr.write(f"[socks5] {self.client_address[0]} - {message}\n")

@dataclass
class RunningServer:
    proxy_type: str
    bind_ip: str
    port: int
    compatibility: str
    server: socketserver.BaseServer
    thread: threading.Thread


@dataclass
class RunningDashboard:
    bind_ip: str
    port: int
    server: socketserver.BaseServer
    thread: threading.Thread


def build_client_portal_snapshot(server, client_ip: str, *, range_key: str):
    normalized_range = range_key if range_key in HISTORY_RANGE_OPTIONS else HISTORY_DEFAULT_RANGE
    dashboard_snapshot = server.runtime.dashboard_state.snapshot()
    client_totals = next(
        (
            item
            for item in dashboard_snapshot.get("totals_by_client", [])
            if item.get("client") == client_ip
        ),
        None,
    )
    if client_totals is None:
        empty_totals = empty_client_usage_summary()
        client_totals = {
            "client": client_ip,
            "count": empty_totals["count"],
            "active_connections": 0,
            "uploaded_bytes": empty_totals["uploaded_bytes"],
            "downloaded_bytes": empty_totals["downloaded_bytes"],
            "total_bytes": empty_totals["total_bytes"],
            "proxy_types": [],
            "last_seen_at": empty_totals["last_seen_at"],
        }

    history = server.history_cache.build_history_payload(
        range_key=normalized_range,
        client=client_ip,
    )
    recent_requests = server.history_cache.recent_records(limit=12, client=client_ip)
    recent_failures = [
        item
        for item in dashboard_snapshot.get("recent_failures", [])
        if item.get("client") == client_ip
    ][:12]
    quota = server.runtime.traffic_quota_manager.evaluate_client(client_ip, server.router_config)
    router_runtime = server.router_config.runtime_snapshot()
    active_profile = router_runtime.get("active_profile") or {}
    return {
        "requested_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "client": client_ip,
        "portal_url": server.runtime.self_endpoints.client_portal_url(),
        "history": history,
        "totals": client_totals,
        "recent_requests": recent_requests,
        "recent_failures": recent_failures,
        "quota": quota,
        "active_profile": {
            "id": active_profile.get("id") or DEFAULT_ROUTING_PROFILE_ID,
            "name": active_profile.get("name") or "Shared",
        },
    }


def render_client_traffic_limit_html(*, client_ip: str, evaluation, destination: str) -> str:
    limit = evaluation.get("limit") or {}
    rows = []
    for window in evaluation.get("exceeded_windows", []):
        rows.append(
            "<tr>"
            f"<td>{html.escape(window['label'].title())}</td>"
            f"<td>{html.escape(format_mb(window['used_bytes']))}</td>"
            f"<td>{html.escape(format_mb(window['limit_bytes']))}</td>"
            "</tr>"
        )
    retry_after_text = format_duration_seconds(evaluation.get("retry_after_seconds"))
    limit_note = html.escape(limit.get("note", "")) if limit.get("note") else ""
    limit_scope = "Default quota" if limit.get("scope") == "default" else "Custom quota"
    portal_url = html.escape(f"http://{CLIENT_PORTAL_PRIMARY_HOST}/")
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Traffic limit reached</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f5efe4;
      --panel: #fffdf8;
      --ink: #1f2937;
      --muted: #6b7280;
      --accent: #b45309;
      --border: #ead8be;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      padding: 24px;
      font-family: "Segoe UI", Tahoma, sans-serif;
      background:
        radial-gradient(circle at top, rgba(234, 179, 8, 0.18), transparent 38%),
        linear-gradient(180deg, #f9f5ed 0%, var(--bg) 100%);
      color: var(--ink);
    }}
    .card {{
      width: min(720px, 100%);
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 22px;
      padding: 28px;
      box-shadow: 0 24px 80px rgba(120, 53, 15, 0.12);
    }}
    h1 {{
      margin: 0 0 10px;
      font-size: clamp(1.8rem, 4vw, 2.6rem);
    }}
    p {{
      margin: 0 0 16px;
      line-height: 1.6;
    }}
    .lead {{
      color: var(--muted);
      font-size: 1.05rem;
    }}
    .meta {{
      display: grid;
      gap: 10px;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      margin: 20px 0;
    }}
    .pill {{
      background: #fff7ed;
      border: 1px solid var(--border);
      border-radius: 999px;
      padding: 10px 14px;
      font-weight: 600;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      margin-top: 18px;
    }}
    th, td {{
      padding: 12px 10px;
      border-bottom: 1px solid var(--border);
      text-align: left;
    }}
    th {{
      color: var(--muted);
      font-size: 0.92rem;
      font-weight: 600;
    }}
    .note {{
      margin-top: 16px;
      padding: 14px 16px;
      border-radius: 16px;
      background: #fffbeb;
      border: 1px solid var(--border);
    }}
  </style>
</head>
<body>
  <main class="card">
    <h1>Traffic limit reached</h1>
    <p class="lead">This device has reached its allowed traffic budget on this proxy, so new requests are paused for now.</p>
    <div class="meta">
      <div class="pill">Client: {html.escape(client_ip)}</div>
      <div class="pill">Limit source: {html.escape(limit_scope)}</div>
      <div class="pill">Retry in about {html.escape(retry_after_text)}</div>
      <div class="pill">Request: {html.escape(destination)}</div>
    </div>
    <table>
      <thead>
        <tr><th>Window</th><th>Used</th><th>Limit</th></tr>
      </thead>
      <tbody>
        {''.join(rows)}
      </tbody>
    </table>
    <div class="note">
      Please wait for older traffic to age out and try again.
      <br><br>Device portal: <a href="{portal_url}">{portal_url}</a>
      {"<br><br><strong>Admin note:</strong> " + limit_note if limit_note else ""}
    </div>
  </main>
</body>
</html>"""


def format_portal_timestamp_text(value) -> str:
    parsed = parse_usage_timestamp(value)
    if parsed is None:
        return str(value or "Never")
    return parsed.astimezone().strftime("%Y-%m-%d %H:%M:%S %z")


def render_client_portal_html(snapshot) -> str:
    client_ip = html.escape(str(snapshot.get("client") or "unknown"))
    requested_at = html.escape(format_portal_timestamp_text(snapshot.get("requested_at")))
    portal_url = html.escape(str(snapshot.get("portal_url") or ""))
    active_profile = snapshot.get("active_profile") or {}
    active_profile_name = html.escape(str(active_profile.get("name") or "Shared"))
    totals = snapshot.get("totals") or {}
    history = snapshot.get("history") or {}
    quota = snapshot.get("quota") or {}
    limit = quota.get("limit") or {}
    recent_requests = list(snapshot.get("recent_requests") or [])
    recent_failures = list(snapshot.get("recent_failures") or [])
    top_destinations = list(history.get("top_destinations") or [])

    if quota.get("exempt"):
        quota_status_text = "Exempt from quota"
    elif limit and not quota.get("allowed", True):
        quota_status_text = f"Blocked for about {format_duration_seconds(quota.get('retry_after_seconds'))}"
    elif limit:
        quota_status_text = "Within quota"
    else:
        quota_status_text = "No quota configured"
    quota_status_text = html.escape(quota_status_text)

    limit_scope = "No quota"
    if quota.get("exempt"):
        limit_scope = "Exempt device"
    elif limit.get("scope") == "default":
        limit_scope = "Default quota"
    elif limit.get("scope") == "custom":
        limit_scope = "Custom quota"
    limit_scope = html.escape(limit_scope)
    limit_note = html.escape(str(limit.get("note") or ""))

    range_key = str(history.get("range") or HISTORY_DEFAULT_RANGE)
    range_links = []
    for key, config in HISTORY_RANGE_OPTIONS.items():
        class_name = "range-link active" if key == range_key else "range-link"
        range_links.append(
            f'<a class="{class_name}" href="/?range={html.escape(key)}">{html.escape(config["title"])}</a>'
        )

    quota_rows = []
    exceeded_by_key = {
        item.get("key"): item
        for item in quota.get("exceeded_windows", [])
        if isinstance(item, dict)
    }
    for window_key, config in CLIENT_TRAFFIC_WINDOW_CONFIG.items():
        usage = (quota.get("usage") or {}).get(window_key) or {}
        used_bytes = int(usage.get("total_bytes", 0))
        limit_bytes = limit.get(
            "max_past_hour_bytes" if window_key == "1h" else "max_past_3h_bytes"
        )
        if quota.get("exempt"):
            state_text = "Exempt"
        elif limit_bytes is None:
            state_text = "Unlimited"
        elif window_key in exceeded_by_key:
            state_text = "Blocked"
        else:
            state_text = "OK"
        limit_text = format_mb(limit_bytes) if limit_bytes is not None else "Unlimited"
        quota_rows.append(
            "<tr>"
            f"<td>{html.escape(config['label'].title())}</td>"
            f"<td>{html.escape(format_mb(used_bytes))}</td>"
            f"<td>{html.escape(limit_text)}</td>"
            f"<td>{html.escape(state_text)}</td>"
            "</tr>"
        )

    destination_rows = []
    for item in top_destinations:
        destination_rows.append(
            "<tr>"
            f"<td>{html.escape(str(item.get('destination') or 'unknown'))}</td>"
            f"<td>{html.escape(str(item.get('count') or 0))}</td>"
            f"<td>{html.escape(format_mb(int(item.get('total_bytes', 0))))}</td>"
            "</tr>"
        )
    if not destination_rows:
        destination_rows.append('<tr><td colspan="3" class="empty">No traffic recorded in this range yet.</td></tr>')

    request_rows = []
    for item in recent_requests:
        request_rows.append(
            "<tr>"
            f"<td>{html.escape(format_portal_timestamp_text(item.get('timestamp')))}</td>"
            f"<td>{html.escape(str(item.get('method') or item.get('kind') or 'request'))}</td>"
            f"<td>{html.escape(str(item.get('destination') or 'unknown'))}</td>"
            f"<td>{html.escape(str(item.get('route_label') or 'direct'))}</td>"
            f"<td>{html.escape(format_mb(int(item.get('total_bytes', 0))))}</td>"
            "</tr>"
        )
    if not request_rows:
        request_rows.append('<tr><td colspan="5" class="empty">No recent requests recorded for this device yet.</td></tr>')

    failure_rows = []
    for item in recent_failures:
        failure_rows.append(
            "<tr>"
            f"<td>{html.escape(format_portal_timestamp_text(item.get('timestamp')))}</td>"
            f"<td>{html.escape(str(item.get('context') or 'failure'))}</td>"
            f"<td>{html.escape(str(item.get('destination') or 'unknown'))}</td>"
            f"<td>{html.escape(str(item.get('error') or 'unknown error'))}</td>"
            "</tr>"
        )
    if not failure_rows:
        failure_rows.append('<tr><td colspan="4" class="empty">No recent failures recorded for this device.</td></tr>')

    history_summary = history.get("summary") or {}
    history_range_title = html.escape(str(history.get("range_title") or "Selected range"))
    history_requests = html.escape(str(history_summary.get("count") or 0))
    history_total = html.escape(format_mb(int(history_summary.get("total_bytes", 0))))
    total_requests = html.escape(str(totals.get("count") or 0))
    total_data = html.escape(format_mb(int(totals.get("total_bytes", 0))))
    active_connections = html.escape(str(totals.get("active_connections") or 0))
    last_seen = html.escape(format_portal_timestamp_text(totals.get("last_seen_at")))
    last_range_json_url = f"/api/client.json?range={html.escape(range_key)}"
    live_script = """
  <script>
    (() => {
      const rangeParams = new URLSearchParams(window.location.search);
      const activeRange = rangeParams.get("range") || "24h";
      const rangeQuery = `?range=${encodeURIComponent(activeRange)}`;
      const liveStatus = document.getElementById("live-status");
      let reconnectTimer = null;

      function setText(id, value) {
        const element = document.getElementById(id);
        if (element) {
          element.textContent = value == null || value === "" ? "0" : String(value);
        }
      }

      function escapeHtml(value) {
        return String(value == null ? "" : value)
          .replaceAll("&", "&amp;")
          .replaceAll("<", "&lt;")
          .replaceAll(">", "&gt;")
          .replaceAll('"', "&quot;")
          .replaceAll("'", "&#39;");
      }

      function formatMb(bytes) {
        return `${(Number(bytes || 0) / 1000000).toFixed(2)} MB`;
      }

      function formatDuration(seconds) {
        const remaining = Math.max(1, Number.parseInt(seconds || 0, 10));
        const days = Math.floor(remaining / 86400);
        const hours = Math.floor((remaining % 86400) / 3600);
        const minutes = Math.floor((remaining % 3600) / 60);
        const secs = remaining % 60;
        const parts = [];
        if (days) parts.push(`${days}d`);
        if (hours) parts.push(`${hours}h`);
        if (minutes) parts.push(`${minutes}m`);
        if (secs && !hours && !days) parts.push(`${secs}s`);
        return parts.join(" ") || "under a minute";
      }

      function formatTimestamp(value) {
        if (!value) return "Never";
        const parsed = new Date(String(value));
        if (Number.isNaN(parsed.getTime())) return String(value);
        return parsed.toLocaleString();
      }

      function quotaStatusText(quota) {
        const limit = quota && quota.limit ? quota.limit : null;
        if (quota && quota.exempt) return "Exempt from quota";
        if (limit && quota && quota.allowed === false) {
          return `Blocked for about ${formatDuration(quota.retry_after_seconds)}`;
        }
        if (limit) return "Within quota";
        return "No quota configured";
      }

      function limitScopeText(quota) {
        const limit = quota && quota.limit ? quota.limit : {};
        if (quota && quota.exempt) return "Exempt device";
        if (limit.scope === "default") return "Default quota";
        if (limit.scope === "custom") return "Custom quota";
        return "No quota";
      }

      function renderQuotaRows(quota) {
        const limit = quota && quota.limit ? quota.limit : {};
        const usage = quota && quota.usage ? quota.usage : {};
        const exceeded = new Set((quota && quota.exceeded_windows ? quota.exceeded_windows : []).map((item) => item.key));
        const windows = [
          ["1h", "Past Hour", "max_past_hour_bytes"],
          ["3h", "Past 3 Hours", "max_past_3h_bytes"],
        ];
        return windows.map(([key, label, limitField]) => {
          const usedBytes = Number((usage[key] || {}).total_bytes || 0);
          const limitBytes = limit[limitField];
          let state = "OK";
          if (quota && quota.exempt) state = "Exempt";
          else if (limitBytes == null) state = "Unlimited";
          else if (exceeded.has(key)) state = "Blocked";
          return `<tr><td>${label}</td><td>${formatMb(usedBytes)}</td><td>${limitBytes == null ? "Unlimited" : formatMb(limitBytes)}</td><td>${state}</td></tr>`;
        }).join("");
      }

      function setRows(id, rows, emptyHtml) {
        const element = document.getElementById(id);
        if (element) {
          element.innerHTML = rows.length ? rows.join("") : emptyHtml;
        }
      }

      function updatePortal(snapshot) {
        if (!snapshot) return;
        const totals = snapshot.totals || {};
        const history = snapshot.history || {};
        const historySummary = history.summary || {};
        const quota = snapshot.quota || {};
        const limit = quota.limit || {};
        const profile = snapshot.active_profile || {};
        const quotaText = quotaStatusText(quota);

        setText("client-ip", snapshot.client || "unknown");
        setText("active-profile", profile.name || "Shared");
        setText("quota-status", quotaText);
        setText("updated-at", formatTimestamp(snapshot.requested_at));
        setText("total-data", formatMb(totals.total_bytes));
        setText("total-requests", `${totals.count || 0} recorded requests`);
        setText("history-range-title", history.range_title || "Selected range");
        setText("history-total", formatMb(historySummary.total_bytes));
        setText("history-requests", `${historySummary.count || 0} requests in the selected range`);
        setText("active-connections", totals.active_connections || 0);
        setText("last-seen", formatTimestamp(totals.last_seen_at));
        setText("limit-scope", limitScopeText(quota));

        const banner = document.getElementById("quota-banner");
        if (banner) {
          const parts = [escapeHtml(quotaText)];
          if (limit && quota.allowed === false) {
            parts.push(`Retry after about ${escapeHtml(formatDuration(quota.retry_after_seconds))}.`);
          }
          if (limit.note) {
            parts.push(`Admin note: ${escapeHtml(limit.note)}`);
          }
          banner.innerHTML = parts.join("<br>");
        }

        const quotaRows = document.getElementById("quota-rows");
        if (quotaRows) quotaRows.innerHTML = renderQuotaRows(quota);

        setRows(
          "destination-rows",
          (history.top_destinations || []).map((item) =>
            `<tr><td>${escapeHtml(item.destination || "unknown")}</td><td>${escapeHtml(item.count || 0)}</td><td>${formatMb(item.total_bytes)}</td></tr>`
          ),
          '<tr><td colspan="3" class="empty">No traffic recorded in this range yet.</td></tr>',
        );

        setRows(
          "request-rows",
          (snapshot.recent_requests || []).map((item) =>
            `<tr><td>${escapeHtml(formatTimestamp(item.timestamp))}</td><td>${escapeHtml(item.method || item.kind || "request")}</td><td>${escapeHtml(item.destination || "unknown")}</td><td>${escapeHtml(item.route_label || "direct")}</td><td>${formatMb(item.total_bytes)}</td></tr>`
          ),
          '<tr><td colspan="5" class="empty">No recent requests recorded for this device yet.</td></tr>',
        );

        setRows(
          "failure-rows",
          (snapshot.recent_failures || []).map((item) =>
            `<tr><td>${escapeHtml(formatTimestamp(item.timestamp))}</td><td>${escapeHtml(item.context || "failure")}</td><td>${escapeHtml(item.destination || "unknown")}</td><td>${escapeHtml(item.error || "unknown error")}</td></tr>`
          ),
          '<tr><td colspan="4" class="empty">No recent failures recorded for this device.</td></tr>',
        );
      }

      function connectLive() {
        if (!("WebSocket" in window)) {
          if (liveStatus) liveStatus.textContent = "Live updates unavailable";
          return;
        }
        const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
        const socket = new WebSocket(`${protocol}//${window.location.host}/api/client/live${rangeQuery}`);

        socket.addEventListener("open", () => {
          if (liveStatus) liveStatus.textContent = "Live updates connected";
        });

        socket.addEventListener("message", (event) => {
          let message = null;
          try {
            message = JSON.parse(event.data);
          } catch {
            return;
          }
          if (message.type === "client_snapshot") {
            updatePortal(message.snapshot);
            if (liveStatus) liveStatus.textContent = `Live updates connected · ${new Date().toLocaleTimeString()}`;
          }
        });

        socket.addEventListener("close", () => {
          if (liveStatus) liveStatus.textContent = "Live updates disconnected · retrying";
          window.clearTimeout(reconnectTimer);
          reconnectTimer = window.setTimeout(connectLive, 3000);
        });

        socket.addEventListener("error", () => {
          try {
            socket.close();
          } catch {
            // Ignore close errors while reconnecting.
          }
        });
      }

      connectLive();
    })();
  </script>
"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Your proxy usage</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    :root {{
      color-scheme: light;
      --bg: #f7f8fb;
      --panel: #ffffff;
      --ink: #172033;
      --muted: #667085;
      --accent: #0f766e;
      --accent-soft: #dff7f2;
      --warn: #b45309;
      --warn-soft: #fff4e5;
      --border: #e3e7ef;
      --shadow: rgba(20, 33, 61, 0.10);
    }}
    *,
    *::before,
    *::after {{
      box-sizing: border-box;
    }}
    body {{
      margin: 0;
      font-family: "IBM Plex Sans", "Segoe UI", sans-serif;
      background: linear-gradient(180deg, #ffffff 0%, var(--bg) 100%);
      color: var(--ink);
    }}
    .portal-shell {{
      width: min(1160px, calc(100% - 32px));
      margin: 0 auto;
      padding: 24px 0 48px;
    }}
    .metrics-grid,
    .content-grid {{
      display: grid;
      gap: 18px;
    }}
    .metrics-grid {{
      grid-template-columns: repeat(4, minmax(0, 1fr));
    }}
    .content-grid {{
      margin-top: 18px;
      align-items: stretch;
    }}
    .metrics-grid > *,
    .content-grid > * {{
      min-width: 0;
    }}
    .content-grid-primary {{
      grid-template-columns: minmax(0, 1.25fr) minmax(360px, 0.75fr);
    }}
    .content-grid-even {{
      grid-template-columns: minmax(0, 1.1fr) minmax(360px, 0.9fr);
    }}
    .table {{
      width: 100%;
      border-collapse: collapse;
    }}
    .align-middle td,
    .align-middle th {{
      vertical-align: middle;
    }}
    .hero {{
      background: linear-gradient(135deg, rgba(15, 118, 110, 0.95), rgba(20, 33, 61, 0.92));
      color: #f8fafc;
      border-radius: 22px;
      padding: 28px;
      box-shadow: 0 26px 60px var(--shadow);
    }}
    .eyebrow {{
      text-transform: uppercase;
      letter-spacing: 0.12em;
      font-size: 0.78rem;
      opacity: 0.8;
      margin-bottom: 10px;
    }}
    h1 {{
      margin: 0;
      font-size: clamp(2rem, 4vw, 3.2rem);
      line-height: 1.04;
    }}
    .hero p {{
      margin: 14px 0 0;
      max-width: 58rem;
      line-height: 1.6;
      color: rgba(248, 250, 252, 0.9);
      overflow-wrap: anywhere;
    }}
    .hero-meta {{
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      margin-top: 18px;
    }}
    .pill {{
      border-radius: 999px;
      padding: 10px 14px;
      font-size: 0.95rem;
      font-weight: 600;
      background: rgba(255, 255, 255, 0.14);
      border: 1px solid rgba(255, 255, 255, 0.18);
      overflow-wrap: anywhere;
    }}
    .layout {{
      margin-top: 18px;
    }}
    .metric-card, .portal-card {{
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 18px;
      box-shadow: 0 16px 40px rgba(20, 33, 61, 0.06);
    }}
    .metric-card {{
      padding: 18px 18px 16px;
      min-height: 100%;
      width: 100%;
    }}
    .metric-card .label {{
      color: var(--muted);
      font-size: 0.88rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }}
    .metric-card .value {{
      margin-top: 10px;
      font-size: 1.65rem;
      font-weight: 700;
      overflow-wrap: anywhere;
    }}
    .metric-card .sub {{
      margin-top: 6px;
      color: var(--muted);
      font-size: 0.92rem;
    }}
    .portal-card {{
      padding: 20px;
      height: 100%;
      min-width: 0;
    }}
    .panel-head {{
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: center;
      flex-wrap: wrap;
      margin-bottom: 16px;
    }}
    h2 {{
      margin: 0;
      font-size: 1.28rem;
    }}
    .muted {{
      color: var(--muted);
    }}
    .range-links {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
    }}
    .range-link {{
      text-decoration: none;
      color: var(--ink);
      background: #f3f4f6;
      border: 1px solid var(--border);
      border-radius: 999px;
      padding: 8px 12px;
      font-weight: 600;
      font-size: 0.92rem;
    }}
    .range-link.active {{
      background: var(--accent-soft);
      border-color: rgba(15, 118, 110, 0.28);
      color: var(--accent);
    }}
    .quota-banner {{
      margin-bottom: 14px;
      padding: 14px 16px;
      border-radius: 18px;
      background: { '#fff4e5' if not quota.get('allowed', True) and limit else '#edf7f6' };
      border: 1px solid { '#f1c48a' if not quota.get('allowed', True) and limit else '#c8e9e4' };
      color: { '#9a3412' if not quota.get('allowed', True) and limit else '#115e59' };
      font-weight: 600;
      line-height: 1.55;
    }}
    .table-responsive {{
      width: 100%;
      max-width: 100%;
      border: 1px solid var(--border);
      border-radius: 14px;
      overflow-x: auto;
      -webkit-overflow-scrolling: touch;
    }}
    .portal-table {{
      min-width: 100%;
      margin-bottom: 0;
    }}
    .portal-table th,
    .portal-table td {{
      padding: 12px 10px;
      text-align: left;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
      overflow-wrap: anywhere;
    }}
    .portal-table th {{
      color: var(--muted);
      font-size: 0.88rem;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      background: #fbfcfe;
    }}
    .portal-table tr:last-child td {{
      border-bottom: none;
    }}
    .empty {{
      color: var(--muted);
      text-align: center;
      padding: 18px 12px;
    }}
    .note {{
      margin-top: 14px;
      color: var(--muted);
      line-height: 1.6;
      overflow-wrap: anywhere;
    }}
    .live-status {{
      margin-top: 12px;
      color: rgba(248, 250, 252, 0.86);
      font-size: 0.95rem;
      font-weight: 600;
    }}
    a {{
      color: var(--accent);
    }}
    @media (max-width: 1050px) {{
      .content-grid-primary,
      .content-grid-even {{
        grid-template-columns: 1fr;
      }}
    }}
    @media (max-width: 840px) {{
      .metrics-grid {{
        grid-template-columns: repeat(2, minmax(0, 1fr));
      }}
    }}
    @media (max-width: 575.98px) {{
      .portal-shell {{
        width: min(100%, calc(100% - 32px));
        padding: 16px 0 32px;
      }}
      .hero {{
        border-radius: 16px;
        padding: 20px;
      }}
      h1 {{
        font-size: 2rem;
      }}
      .hero-meta {{
        display: grid;
        grid-template-columns: 1fr;
      }}
      .pill {{
        width: 100%;
      }}
      .metrics-grid {{
        grid-template-columns: 1fr;
      }}
      .portal-card {{
        padding: 16px;
      }}
      .panel-head {{
        align-items: flex-start;
      }}
      .range-links {{
        width: 100%;
      }}
      .range-link {{
        flex: 1 1 calc(50% - 8px);
        text-align: center;
      }}
      .metric-card .value {{
        font-size: 1.4rem;
      }}
      .portal-table {{
        min-width: 560px;
      }}
    }}
  </style>
</head>
<body>
  <main class="portal-shell">
    <section class="hero">
      <div class="eyebrow">Proxy client portal</div>
      <h1>Your device usage</h1>
      <p>This page only shows traffic, quota state, and recent failures recorded for the device currently connected as <strong id="client-ip">{client_ip}</strong>. It updates live while this page is open.</p>
      <div class="hero-meta">
        <div class="pill">Client: {client_ip}</div>
        <div class="pill">Profile: <span id="active-profile">{active_profile_name}</span></div>
        <div class="pill">Quota: <span id="quota-status">{quota_status_text}</span></div>
        <div class="pill">Updated: <span id="updated-at">{requested_at}</span></div>
      </div>
      <div class="live-status" id="live-status">Connecting live updates…</div>
    </section>

    <div class="layout">
      <section class="metrics-grid">
        <article>
          <div class="metric-card">
          <div class="label">All-time data</div>
          <div class="value" id="total-data">{total_data}</div>
          <div class="sub" id="total-requests">{total_requests} recorded requests</div>
          </div>
        </article>
        <article>
          <div class="metric-card">
          <div class="label" id="history-range-title">{history_range_title}</div>
          <div class="value" id="history-total">{history_total}</div>
          <div class="sub" id="history-requests">{history_requests} requests in the selected range</div>
          </div>
        </article>
        <article>
          <div class="metric-card">
          <div class="label">Active connections</div>
          <div class="value" id="active-connections">{active_connections}</div>
          <div class="sub">Open connections from this device right now</div>
          </div>
        </article>
        <article>
          <div class="metric-card">
          <div class="label">Last seen</div>
          <div class="value" id="last-seen" style="font-size:1.1rem">{last_seen}</div>
          <div class="sub">Most recent recorded usage</div>
          </div>
        </article>
      </section>

      <section class="content-grid content-grid-primary">
        <article>
          <div class="portal-card">
          <div class="panel-head">
            <h2>Quota status</h2>
            <span class="muted" id="limit-scope">{limit_scope}</span>
          </div>
          <div class="quota-banner" id="quota-banner">
            {quota_status_text}
            {f"<br>Retry after about {html.escape(format_duration_seconds(quota.get('retry_after_seconds')))}." if limit and not quota.get('allowed', True) else ""}
            {f"<br>Admin note: {limit_note}" if limit_note else ""}
          </div>
          <div class="table-responsive">
          <table class="table portal-table align-middle">
            <thead>
              <tr><th>Window</th><th>Used</th><th>Limit</th><th>Status</th></tr>
            </thead>
            <tbody id="quota-rows">
              {''.join(quota_rows)}
            </tbody>
          </table>
          </div>
          <p class="note">Portal URL while using the proxy: <a href="{portal_url}">{portal_url}</a>. Raw JSON: <a href="{last_range_json_url}">{last_range_json_url}</a></p>
          </div>
        </article>

        <article>
          <div class="portal-card">
          <div class="panel-head">
            <h2>Top destinations</h2>
            <div class="range-links">{''.join(range_links)}</div>
          </div>
          <div class="table-responsive">
          <table class="table portal-table align-middle">
            <thead>
              <tr><th>Destination</th><th>Requests</th><th>Data</th></tr>
            </thead>
            <tbody id="destination-rows">
              {''.join(destination_rows)}
            </tbody>
          </table>
          </div>
          </div>
        </article>
      </section>

      <section class="content-grid">
        <article>
          <div class="portal-card">
          <div class="panel-head">
            <h2>Recent requests</h2>
            <span class="muted">Latest usage log entries for this device</span>
          </div>
          <div class="table-responsive">
          <table class="table portal-table align-middle">
            <thead>
              <tr><th>Time</th><th>Method</th><th>Destination</th><th>Route</th><th>Data</th></tr>
            </thead>
            <tbody id="request-rows">
              {''.join(request_rows)}
            </tbody>
          </table>
          </div>
          </div>
        </article>

        <article>
          <div class="portal-card">
          <div class="panel-head">
            <h2>Recent failures</h2>
            <span class="muted">Newest failure records for this device</span>
          </div>
          <div class="table-responsive">
          <table class="table portal-table align-middle">
            <thead>
              <tr><th>Time</th><th>Context</th><th>Destination</th><th>Error</th></tr>
            </thead>
            <tbody id="failure-rows">
              {''.join(failure_rows)}
            </tbody>
          </table>
          </div>
          </div>
        </article>
      </section>
    </div>
  </main>
  {live_script}
</body>
</html>"""
