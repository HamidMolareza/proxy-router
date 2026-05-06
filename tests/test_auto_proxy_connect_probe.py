import unittest
from types import SimpleNamespace

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


if __name__ == "__main__":
    unittest.main()
