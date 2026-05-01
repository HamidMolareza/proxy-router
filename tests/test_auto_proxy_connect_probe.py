import unittest
from types import SimpleNamespace

from proxy_router.constants import DEFAULT_ROUTING_PROFILE_ID
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
        handler._check_client_traffic_limit = lambda **_kwargs: calls.append("quota") or False
        handler._resolve_route = lambda *_args, **_kwargs: calls.append("route")
        handler._debug = lambda *_args, **_kwargs: None
        handler._log_http_event = lambda *_args, **_kwargs: None
        handler._handle_intercepted_connect = lambda *_args, **_kwargs: calls.append("intercept")

        handler.do_CONNECT()

        self.assertEqual(calls, ["quota"])


if __name__ == "__main__":
    unittest.main()
