import unittest
from types import SimpleNamespace
from unittest.mock import patch

from proxy_router.constants import DEFAULT_ROUTING_PROFILE_ID
import proxy_router.proxy_server as proxy_server
from proxy_router.proxy_server import ProxyRequestHandler


class RouteConfig:
    def decide(self, host):
        return {
            "host": host,
            "action": "direct",
            "matched_rule": None,
            "upstream": {"enabled": True, "type": "socks5", "host": "127.0.0.1", "port": 8901},
            "profile_id": DEFAULT_ROUTING_PROFILE_ID,
            "profile_name": "Shared",
            "route_label": "direct",
        }


class RouteRuntime:
    def __init__(self):
        self.calls = 0
        self.self_endpoints = SimpleNamespace(resolve_target_kind=lambda _host, _port: None)

    def apply_auto_proxy_probe_route(self, host, route_decision):
        self.calls += 1
        routed = dict(route_decision)
        routed["action"] = "proxy"
        routed["route_label"] = f"proxy:auto-probe:socks5://127.0.0.1:8901"
        routed["auto_proxy_probe"] = True
        return routed


class AutoProxyConnectProbeTests(unittest.TestCase):
    def _handler(self):
        handler = ProxyRequestHandler.__new__(ProxyRequestHandler)
        runtime = RouteRuntime()
        handler.server = SimpleNamespace(
            runtime=runtime,
            router_config=RouteConfig(),
        )
        handler._debug = lambda *args, **kwargs: None
        return handler, runtime

    def test_resolve_route_can_skip_auto_proxy_probe_for_intercepted_connect(self):
        handler, runtime = self._handler()

        route = handler._resolve_route("djangoproject.com", 443, apply_auto_proxy_probe=False)

        self.assertEqual(route["route_label"], "direct")
        self.assertFalse(route.get("auto_proxy_probe", False))
        self.assertEqual(runtime.calls, 0)

    def test_resolve_route_uses_auto_proxy_probe_for_real_upstream_request(self):
        handler, runtime = self._handler()

        route = handler._resolve_route("djangoproject.com", 443)

        self.assertEqual(route["route_label"], "proxy:auto-probe:socks5://127.0.0.1:8901")
        self.assertTrue(route["auto_proxy_probe"])
        self.assertEqual(runtime.calls, 1)

    def test_intercepted_connect_defers_quota_check_to_inner_https_request(self):
        handler = ProxyRequestHandler.__new__(ProxyRequestHandler)
        calls = []
        route = {
            "host": "example.com",
            "action": "direct",
            "matched_rule": None,
            "upstream": None,
            "profile_id": DEFAULT_ROUTING_PROFILE_ID,
            "profile_name": "Shared",
            "route_label": "direct",
        }
        handler.path = "example.com:443"
        handler.requestline = "CONNECT example.com:443 HTTP/1.1"
        handler.headers = {}
        handler.client_address = ("192.168.1.23", 50000)
        handler.server = SimpleNamespace(
            router_config=SimpleNamespace(
                https_interception_settings=lambda: {
                    "enabled": True,
                    "mode": "all",
                    "host_patterns": [],
                    "bypass_patterns": [],
                }
            ),
            runtime=SimpleNamespace(https_interception_adaptive_bypass=lambda *_args: None),
        )
        handler._check_client_allowed = lambda: True
        handler._is_client_portal_https_trust_check_target = lambda *_args: False
        handler._is_client_portal_connect_target = lambda *_args: False
        handler._authenticate_http_client = lambda: True
        handler._drop_blocked_client = lambda **_kwargs: False
        handler._check_client_traffic_limit = lambda **_kwargs: calls.append("quota") or False
        handler._resolve_route = lambda *_args, **_kwargs: route
        handler._debug = lambda *_args, **_kwargs: None
        handler._log_http_event = lambda *_args, **_kwargs: None
        handler._handle_intercepted_connect = lambda *_args, **_kwargs: calls.append("intercept")

        handler.do_CONNECT()

        self.assertEqual(calls, ["intercept"])

    def test_raw_connect_still_rejects_quota_before_tunnel(self):
        handler = ProxyRequestHandler.__new__(ProxyRequestHandler)
        calls = []
        handler.path = "example.com:443"
        handler.requestline = "CONNECT example.com:443 HTTP/1.1"
        handler.headers = {}
        handler.client_address = ("192.168.1.23", 50000)
        handler.server = SimpleNamespace(
            router_config=SimpleNamespace(
                https_interception_settings=lambda: {
                    "enabled": True,
                    "mode": "all",
                    "host_patterns": [],
                    "bypass_patterns": [],
                }
            ),
            runtime=SimpleNamespace(
                https_interception_adaptive_bypass=lambda *_args: {"scope": "client-host"}
            ),
        )
        handler._check_client_allowed = lambda: True
        handler._is_client_portal_https_trust_check_target = lambda *_args: False
        handler._is_client_portal_connect_target = lambda *_args: False
        handler._authenticate_http_client = lambda: True
        handler._drop_blocked_client = lambda **_kwargs: False
        handler._check_client_traffic_limit = lambda **_kwargs: calls.append("quota") or False
        handler._resolve_route = lambda *_args, **_kwargs: calls.append("route")
        handler._debug = lambda *_args, **_kwargs: None
        handler._log_http_event = lambda *_args, **_kwargs: None
        handler._handle_intercepted_connect = lambda *_args, **_kwargs: calls.append("intercept")

        handler.do_CONNECT()

        self.assertEqual(calls, ["quota"])

    def test_raw_direct_connect_does_not_record_auto_proxy_success(self):
        handler = ProxyRequestHandler.__new__(ProxyRequestHandler)
        calls = []
        route = {
            "host": "example.com",
            "action": "direct",
            "matched_rule": None,
            "upstream": {"enabled": True, "type": "socks5", "host": "127.0.0.1", "port": 8901},
            "profile_id": DEFAULT_ROUTING_PROFILE_ID,
            "profile_name": "Shared",
            "route_label": "direct",
        }

        class FakeSocket:
            def getsockname(self):
                return ("127.0.0.1", 40000)

            def getpeername(self):
                return ("93.184.216.34", 443)

            def close(self):
                calls.append("upstream-close")

        handler.path = "example.com:443"
        handler.requestline = "CONNECT example.com:443 HTTP/1.1"
        handler.headers = {}
        handler.client_address = ("192.168.1.23", 50000)
        handler.connection = object()
        handler.server = SimpleNamespace(
            proxy_label="mixed",
            router_config=SimpleNamespace(
                https_interception_settings=lambda: {
                    "enabled": False,
                    "mode": "allowlist",
                    "host_patterns": [],
                    "bypass_patterns": [],
                }
            ),
            runtime=SimpleNamespace(
                https_interception_adaptive_bypass=lambda *_args: None,
                observe_https_connect=lambda *_args: calls.append("observe"),
                record_usage=lambda **_kwargs: calls.append("usage"),
                record_auto_proxy_success=lambda *_args: calls.append("auto-success"),
            ),
        )
        handler._check_client_allowed = lambda: True
        handler._is_client_portal_https_trust_check_target = lambda *_args: False
        handler._is_client_portal_connect_target = lambda *_args: False
        handler._authenticate_http_client = lambda: True
        handler._drop_blocked_client = lambda **_kwargs: False
        handler._check_client_traffic_limit = lambda **_kwargs: True
        handler._resolve_route = lambda *_args, **_kwargs: route
        handler._open_routed_stream = lambda *_args, **_kwargs: (FakeSocket(), None)
        handler.send_response = lambda *_args, **_kwargs: calls.append("response")
        handler.end_headers = lambda *_args, **_kwargs: calls.append("headers")
        handler._debug = lambda *_args, **_kwargs: None
        handler._log_http_event = lambda *_args, **_kwargs: None

        original_tunnel = proxy_server.tunnel_bidirectional
        proxy_server.tunnel_bidirectional = lambda *_args, **_kwargs: {
            "left_to_right_bytes": 128,
            "right_to_left_bytes": 256,
        }
        try:
            handler.do_CONNECT()
        finally:
            proxy_server.tunnel_bidirectional = original_tunnel

        self.assertIn("usage", calls)
        self.assertNotIn("auto-success", calls)

    def test_raw_direct_connect_failure_retries_auto_proxy_probe(self):
        handler = ProxyRequestHandler.__new__(ProxyRequestHandler)
        calls = []
        route = {
            "host": "rr1---sn-nv47zne7.googlevideo.com",
            "action": "direct",
            "matched_rule": None,
            "upstream": {"enabled": True, "type": "socks5", "host": "127.0.0.1", "port": 8901},
            "profile_id": DEFAULT_ROUTING_PROFILE_ID,
            "profile_name": "Shared",
            "route_label": "direct",
        }
        probe_route = dict(route)
        probe_route["action"] = "proxy"
        probe_route["route_label"] = "proxy:auto-probe:socks5://127.0.0.1:8901"
        probe_route["auto_proxy_probe"] = True

        class FakeSocket:
            def getsockname(self):
                return ("127.0.0.1", 40000)

            def getpeername(self):
                return ("127.0.0.1", 8901)

            def close(self):
                calls.append("upstream-close")

        def open_routed_stream(_host, _port, selected_route, **_kwargs):
            calls.append(f"open:{selected_route['route_label']}")
            if selected_route["route_label"] == "direct":
                raise ConnectionRefusedError("direct refused")
            return FakeSocket(), None

        handler.path = "rr1---sn-nv47zne7.googlevideo.com:443"
        handler.requestline = "CONNECT rr1---sn-nv47zne7.googlevideo.com:443 HTTP/1.1"
        handler.headers = {}
        handler.client_address = ("192.168.1.23", 50000)
        handler.connection = object()
        handler.server = SimpleNamespace(
            proxy_label="mixed",
            router_config=SimpleNamespace(
                https_interception_settings=lambda: {
                    "enabled": False,
                    "mode": "allowlist",
                    "host_patterns": [],
                    "bypass_patterns": [],
                }
            ),
            runtime=SimpleNamespace(
                https_interception_adaptive_bypass=lambda *_args: None,
                observe_https_connect=lambda *_args: calls.append("observe"),
                build_auto_proxy_direct_failure_probe_route=lambda *_args: probe_route,
                record_usage=lambda **kwargs: calls.append(f"usage:{kwargs['route_label']}"),
                record_auto_proxy_success=lambda _host, selected_route: calls.append(
                    f"auto-success:{selected_route['route_label']}"
                ),
            ),
        )
        handler._check_client_allowed = lambda: True
        handler._is_client_portal_https_trust_check_target = lambda *_args: False
        handler._is_client_portal_connect_target = lambda *_args: False
        handler._authenticate_http_client = lambda: True
        handler._drop_blocked_client = lambda **_kwargs: False
        handler._check_client_traffic_limit = lambda **_kwargs: True
        handler._resolve_route = lambda *_args, **_kwargs: route
        handler._open_routed_stream = open_routed_stream
        handler.send_response = lambda *_args, **_kwargs: calls.append("response")
        handler.end_headers = lambda *_args, **_kwargs: calls.append("headers")
        handler._debug = lambda *_args, **_kwargs: None
        handler._log_http_event = lambda *_args, **_kwargs: None
        handler._send_gateway_error = lambda *_args, **_kwargs: calls.append("gateway-error")

        original_tunnel = proxy_server.tunnel_bidirectional
        proxy_server.tunnel_bidirectional = lambda *_args, **_kwargs: {
            "left_to_right_bytes": 128,
            "right_to_left_bytes": 256,
        }
        try:
            handler.do_CONNECT()
        finally:
            proxy_server.tunnel_bidirectional = original_tunnel

        self.assertIn("open:direct", calls)
        self.assertIn("open:proxy:auto-probe:socks5://127.0.0.1:8901", calls)
        self.assertIn("usage:proxy:auto-probe:socks5://127.0.0.1:8901", calls)
        self.assertIn("auto-success:proxy:auto-probe:socks5://127.0.0.1:8901", calls)
        self.assertNotIn("gateway-error", calls)

    def test_raw_proxy_connect_failover_tries_next_candidate(self):
        handler = ProxyRequestHandler.__new__(ProxyRequestHandler)
        calls = []
        first_proxy = {
            "id": "first",
            "enabled": True,
            "type": "socks5",
            "host": "127.0.0.1",
            "port": 8901,
            "access_mode": "public",
        }
        second_proxy = {
            "id": "second",
            "enabled": True,
            "type": "socks5",
            "host": "127.0.0.1",
            "port": 8902,
            "access_mode": "public",
        }
        route = {
            "host": "example.com",
            "action": "proxy",
            "matched_rule": None,
            "upstream": first_proxy,
            "upstream_candidates": [first_proxy, second_proxy],
            "profile_id": DEFAULT_ROUTING_PROFILE_ID,
            "profile_name": "Shared",
            "route_label": "proxy:socks5://127.0.0.1:8901",
        }

        class FakeSocket:
            pass

        def open_once(_host, _port, selected_route):
            proxy_id = selected_route["upstream"]["id"]
            calls.append(proxy_id)
            if proxy_id == "first":
                raise ConnectionRefusedError("first proxy refused")
            return FakeSocket(), None

        handler.client_address = ("192.168.1.23", 50000)
        handler.server = SimpleNamespace(
            router_config=SimpleNamespace(
                upstream_retry_settings=lambda: {
                    "enabled": False,
                    "attempts": 1,
                    "initial_delay_seconds": 1,
                    "max_delay_seconds": 1,
                }
            ),
            runtime=SimpleNamespace(
                traffic_quota_manager=SimpleNamespace(proxy_allowed=lambda *_args, **_kwargs: True),
            ),
        )
        handler._client_id = lambda: "192.168.1.23"
        handler._debug = lambda *_args, **_kwargs: None
        handler._open_routed_stream_once = open_once

        upstream, upstream_owner, selected_route = handler._open_routed_stream("example.com", 443, route)

        self.assertIsInstance(upstream, FakeSocket)
        self.assertIsNone(upstream_owner)
        self.assertEqual(selected_route["upstream"]["id"], "second")
        self.assertEqual(selected_route["proxy_failover_count"], 1)
        self.assertEqual(calls, ["first", "second"])

    def test_http_post_setup_failure_can_failover_to_next_candidate(self):
        handler = ProxyRequestHandler.__new__(ProxyRequestHandler)
        calls = []
        first_proxy = {
            "id": "first",
            "enabled": True,
            "type": "socks5",
            "host": "127.0.0.1",
            "port": 8901,
            "access_mode": "public",
        }
        second_proxy = {
            "id": "second",
            "enabled": True,
            "type": "socks5",
            "host": "127.0.0.1",
            "port": 8902,
            "access_mode": "public",
        }
        route = {
            "host": "example.com",
            "action": "proxy",
            "matched_rule": None,
            "upstream": first_proxy,
            "upstream_candidates": [first_proxy, second_proxy],
            "profile_id": DEFAULT_ROUTING_PROFILE_ID,
            "profile_name": "Shared",
            "route_label": "proxy:socks5://127.0.0.1:8901",
        }

        class FakeResponse:
            status = 200

        class FakeConnection:
            pass

        def perform_once(_scheme, _host, _port, _target_path, _body, _headers, *, route_decision):
            proxy_id = route_decision["upstream"]["id"]
            calls.append(proxy_id)
            if proxy_id == "first":
                raise proxy_server.UpstreamRequestSetupError(ConnectionRefusedError("first proxy refused"))
            return FakeConnection(), FakeResponse()

        handler.command = "POST"
        handler.client_address = ("192.168.1.23", 50000)
        handler.server = SimpleNamespace(
            router_config=SimpleNamespace(
                upstream_retry_settings=lambda: {
                    "enabled": False,
                    "attempts": 1,
                    "initial_delay_seconds": 1,
                    "max_delay_seconds": 1,
                }
            ),
            runtime=SimpleNamespace(
                traffic_quota_manager=SimpleNamespace(proxy_allowed=lambda *_args, **_kwargs: True),
            ),
        )
        handler._client_id = lambda: "192.168.1.23"
        handler._debug = lambda *_args, **_kwargs: None
        handler._perform_upstream_request_once = perform_once

        connection, response, selected_route = handler._perform_upstream_request(
            "https",
            "example.com",
            443,
            "/submit",
            b'{"payload": true}',
            {},
            route_decision=route,
        )

        self.assertIsInstance(connection, FakeConnection)
        self.assertIsInstance(response, FakeResponse)
        self.assertEqual(selected_route["upstream"]["id"], "second")
        self.assertEqual(selected_route["proxy_failover_count"], 1)
        self.assertEqual(calls, ["first", "second"])

    def test_https_post_http_proxy_connect_failure_can_failover_to_next_candidate(self):
        handler = ProxyRequestHandler.__new__(ProxyRequestHandler)
        calls = []
        first_proxy = {
            "id": "first",
            "enabled": True,
            "type": "http",
            "host": "127.0.0.1",
            "port": 8901,
            "access_mode": "public",
        }
        second_proxy = {
            "id": "second",
            "enabled": True,
            "type": "http",
            "host": "127.0.0.1",
            "port": 8902,
            "access_mode": "public",
        }
        route = {
            "host": "example.com",
            "action": "proxy",
            "matched_rule": None,
            "upstream": first_proxy,
            "upstream_candidates": [first_proxy, second_proxy],
            "profile_id": DEFAULT_ROUTING_PROFILE_ID,
            "profile_name": "Shared",
            "route_label": "proxy:http://127.0.0.1:8901",
        }

        class FakeResponse:
            status = 200
            reason = "OK"
            headers = {}

        class FakeHttpsConnection:
            def __init__(self, host, port, **_kwargs):
                self.host = host
                self.port = port
                self.closed = False

            def set_tunnel(self, host, port):
                calls.append(f"tunnel:{self.port}:{host}:{port}")

            def connect(self):
                calls.append(f"connect:{self.port}")
                if self.port == 8901:
                    raise ConnectionRefusedError("first proxy refused")

            def request(self, method, target, body=None, headers=None):
                calls.append(f"request:{self.port}:{method}:{target}:{body!r}")

            def getresponse(self):
                calls.append(f"response:{self.port}")
                return FakeResponse()

            def close(self):
                self.closed = True
                calls.append(f"close:{self.port}")

        handler.command = "POST"
        handler.client_address = ("192.168.1.23", 50000)
        handler.server = SimpleNamespace(
            proxy_label="http",
            timeout_seconds=1,
            router_config=SimpleNamespace(
                upstream_retry_settings=lambda: {
                    "enabled": False,
                    "attempts": 1,
                    "initial_delay_seconds": 1,
                    "max_delay_seconds": 1,
                }
            ),
            runtime=SimpleNamespace(
                traffic_quota_manager=SimpleNamespace(proxy_allowed=lambda *_args, **_kwargs: True),
                record_upstream_route_success=lambda *_args, **_kwargs: calls.append("route-success"),
            ),
        )
        handler._client_id = lambda: "192.168.1.23"
        handler._debug = lambda *_args, **_kwargs: None

        with patch("proxy_router.proxy_server.http.client.HTTPSConnection", FakeHttpsConnection):
            connection, response, selected_route = handler._perform_upstream_request(
                "https",
                "example.com",
                443,
                "/submit",
                b'{"payload": true}',
                {},
                route_decision=route,
            )

        self.assertIsInstance(connection, FakeHttpsConnection)
        self.assertIsInstance(response, FakeResponse)
        self.assertEqual(selected_route["upstream"]["id"], "second")
        self.assertEqual(selected_route["proxy_failover_count"], 1)
        self.assertEqual(
            calls,
            [
                "tunnel:8901:example.com:443",
                "connect:8901",
                "close:8901",
                "tunnel:8902:example.com:443",
                "connect:8902",
                "request:8902:POST:/submit:b'{\"payload\": true}'",
                "response:8902",
                "route-success",
            ],
        )



if __name__ == "__main__":
    unittest.main()
