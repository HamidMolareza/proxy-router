import errno
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from proxy_router.config import RouterConfigManager
from proxy_router.proxy_server import normalize_upstream_retry_policy, retry_upstream_operation, should_retry_stream_setup_error
from proxy_router.runtime import AppRuntime
from proxy_router.util import normalize_router_config, proxy_allows_client


class UpstreamRetryConfigTests(unittest.TestCase):
    def test_direct_local_network_unreachable_is_not_retried(self):
        route = {"action": "direct", "route_label": "direct"}
        exc = OSError(errno.ENETUNREACH, "Network is unreachable")

        self.assertFalse(should_retry_stream_setup_error(exc, route))

    def test_proxy_network_unreachable_can_retry(self):
        route = {"action": "proxy", "route_label": "proxy:socks5://127.0.0.1:8901"}
        exc = OSError(errno.ENETUNREACH, "Network is unreachable")

        self.assertTrue(should_retry_stream_setup_error(exc, route))

    def test_normalize_router_config_preserves_upstream_retry_policy(self):
        config = normalize_router_config(
            {
                "upstream_retry": {
                    "enabled": True,
                    "attempts": "6",
                    "connect_timeout_seconds": "7",
                    "initial_delay_seconds": "2",
                    "max_delay_seconds": "8",
                },
            }
        )

        self.assertEqual(
            config["upstream_retry"],
            {
                "enabled": True,
                "attempts": 6,
                "connect_timeout_seconds": 7,
                "initial_delay_seconds": 2,
                "max_delay_seconds": 8,
            },
        )

    def test_normalize_upstream_retry_policy_clamps_connect_timeout(self):
        self.assertEqual(
            normalize_upstream_retry_policy({"connect_timeout_seconds": "300"})["connect_timeout_seconds"],
            120.0,
        )
        self.assertEqual(
            normalize_upstream_retry_policy({"connect_timeout_seconds": "invalid"})["connect_timeout_seconds"],
            8.0,
        )

    def test_route_decision_cache_reuses_match_and_returns_fresh_clone(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = RouterConfigManager(Path(temp_dir) / "router-config.json")
            try:
                manager.update(
                    {
                        "default_action": "direct",
                        "proxies": [
                            {
                                "id": "main",
                                "enabled": True,
                                "type": "socks5",
                                "host": "127.0.0.1",
                                "port": 8901,
                                "priority": 1,
                            }
                        ],
                        "rules": [
                            {
                                "enabled": True,
                                "pattern": "example.com",
                                "match": "suffix",
                                "action": "proxy",
                                "duration": "always",
                            }
                        ],
                    }
                )

                import proxy_router.config as config_module

                calls = []
                original_rule_matches_host = config_module.rule_matches_host

                def counted_rule_matches_host(rule, host):
                    calls.append((rule["pattern"], host))
                    return original_rule_matches_host(rule, host)

                with patch("proxy_router.config.rule_matches_host", side_effect=counted_rule_matches_host):
                    first = manager.decide("api.example.com", client_ip="127.0.0.1")
                    first["connect_host"] = "mutated"
                    first["upstream_candidates"].append({"id": "mutated"})
                    second = manager.decide("api.example.com", client_ip="127.0.0.1")

                self.assertEqual(first["action"], "proxy")
                self.assertEqual(second["action"], "proxy")
                self.assertNotIn("connect_host", second)
                self.assertEqual([proxy["id"] for proxy in second["upstream_candidates"]], ["main"])
                self.assertEqual(calls, [("example.com", "api.example.com")])
            finally:
                manager.shutdown()

    def test_route_decision_cache_is_invalidated_after_config_update(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = RouterConfigManager(Path(temp_dir) / "router-config.json")
            try:
                base_config = {
                    "default_action": "direct",
                    "proxies": [
                        {
                            "id": "main",
                            "enabled": True,
                            "type": "socks5",
                            "host": "127.0.0.1",
                            "port": 8901,
                            "priority": 1,
                        }
                    ],
                    "rules": [
                        {
                            "enabled": True,
                            "pattern": "example.com",
                            "match": "suffix",
                            "action": "direct",
                            "duration": "always",
                        }
                    ],
                }
                manager.update(base_config)
                self.assertEqual(manager.decide("api.example.com", client_ip="127.0.0.1")["action"], "direct")

                updated_config = dict(base_config)
                updated_config["rules"] = [dict(base_config["rules"][0], action="proxy")]
                manager.update(updated_config)

                decision = manager.decide("api.example.com", client_ip="127.0.0.1")
                self.assertEqual(decision["action"], "proxy")
                self.assertEqual(decision["upstream"]["id"], "main")
            finally:
                manager.shutdown()

    def test_normalize_router_config_rejects_retry_max_below_initial_delay(self):
        with self.assertRaisesRegex(ValueError, "max_delay_seconds"):
            normalize_router_config(
                {
                    "upstream_retry": {
                        "initial_delay_seconds": 5,
                        "max_delay_seconds": 2,
                    },
                }
            )

    def test_retry_upstream_operation_uses_configured_delays(self):
        calls = []
        retries = []
        retry_metrics = {}

        def operation(attempt):
            calls.append(attempt)
            if len(calls) < 3:
                raise TimeoutError("temporary upstream failure")
            return "ok"

        with patch("proxy_router.proxy_server.time.sleep") as sleep:
            result = retry_upstream_operation(
                operation,
                retry_policy={
                    "enabled": True,
                    "attempts": 4,
                    "initial_delay_seconds": 2,
                    "max_delay_seconds": 3,
                },
                retry_metrics=retry_metrics,
                on_retry=lambda attempt, attempts, delay, exc: retries.append(
                    (attempt, attempts, delay, type(exc).__name__)
                ),
            )

        self.assertEqual(result, "ok")
        self.assertEqual(calls, [1, 2, 3])
        self.assertEqual(retries, [(1, 4, 2.0, "TimeoutError"), (2, 4, 3.0, "TimeoutError")])
        self.assertEqual(retry_metrics, {"upstream_retry_count": 2, "upstream_retry_delay_ms": 5000})
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [2.0, 3.0])

    def test_retry_upstream_operation_can_be_disabled(self):
        calls = []

        def operation(attempt):
            calls.append(attempt)
            raise TimeoutError("temporary upstream failure")

        with patch("proxy_router.proxy_server.time.sleep") as sleep:
            with self.assertRaises(TimeoutError):
                retry_upstream_operation(
                    operation,
                    retry_policy={
                        "enabled": False,
                        "attempts": 4,
                        "initial_delay_seconds": 2,
                        "max_delay_seconds": 3,
                    },
                    on_retry=lambda attempt, attempts, delay, exc: None,
                )

        self.assertEqual(calls, [1])
        sleep.assert_not_called()

    def test_normalize_router_config_migrates_legacy_upstream_to_proxy_list(self):
        config = normalize_router_config(
            {
                "upstream": {
                    "enabled": True,
                    "type": "socks5",
                    "host": "127.0.0.1",
                    "port": "9050",
                }
            }
        )

        self.assertEqual(len(config["proxies"]), 1)
        self.assertEqual(config["proxies"][0]["id"], "upstream-default")
        self.assertEqual(config["proxies"][0]["type"], "socks5")
        self.assertEqual(config["upstream"]["port"], 9050)

    def test_normalize_router_config_preserves_ordered_private_and_auth_proxies(self):
        config = normalize_router_config(
            {
                "proxies": [
                    {
                        "id": "fallback",
                        "enabled": True,
                        "priority": 20,
                        "type": "http",
                        "host": "127.0.0.1",
                        "port": 8080,
                        "access_mode": "authenticated",
                    },
                    {
                        "id": "phone-only",
                        "enabled": True,
                        "priority": 10,
                        "type": "socks5",
                        "host": "127.0.0.1",
                        "port": 9050,
                        "access_mode": "private",
                        "allowed_clients": ["phone"],
                        "traffic_limit": {
                            "enabled": True,
                            "max_past_week_mb": "5000",
                        },
                        "per_client_traffic_limit": {
                            "enabled": True,
                            "max_past_hour_mb": "100",
                        },
                    },
                ],
                "default_action": "proxy",
            }
        )

        self.assertEqual([proxy["id"] for proxy in config["proxies"]], ["phone-only", "fallback"])
        self.assertTrue(proxy_allows_client(config["proxies"][0], "user:phone"))
        self.assertFalse(proxy_allows_client(config["proxies"][0], "user:tablet"))
        self.assertTrue(proxy_allows_client(config["proxies"][1], "user:tablet"))
        self.assertFalse(proxy_allows_client(config["proxies"][1], "192.168.1.50"))
        self.assertEqual(config["proxies"][0]["traffic_limit"]["max_past_week_mb"], 5000)

    def test_private_proxy_allows_loopback_without_allowed_clients(self):
        config = normalize_router_config(
            {
                "proxies": [
                    {
                        "id": "localhost-only",
                        "enabled": True,
                        "type": "socks5",
                        "host": "127.0.0.1",
                        "port": 9050,
                        "access_mode": "private",
                    },
                ],
                "default_action": "proxy",
            }
        )

        proxy = config["proxies"][0]
        self.assertEqual(proxy["allowed_clients"], [])
        self.assertTrue(proxy_allows_client(proxy, "127.0.0.1"))
        self.assertTrue(proxy_allows_client(proxy, "localhost"))
        self.assertTrue(proxy_allows_client(proxy, "user:local-tool", client_ip="127.0.0.1"))
        self.assertTrue(proxy_allows_client(proxy, "user:local-tool", client_ip="::1"))
        self.assertFalse(proxy_allows_client(proxy, "user:local-tool", client_ip="192.168.1.50"))

    def test_proxy_rules_can_load_when_all_proxies_are_disabled(self):
        config = normalize_router_config(
            {
                "proxies": [
                    {
                        "id": "disabled-proxy",
                        "enabled": False,
                        "type": "socks5",
                        "host": "127.0.0.1",
                        "port": 9050,
                    },
                ],
                "default_action": "direct",
                "rules": [
                    {
                        "enabled": True,
                        "pattern": "example.com",
                        "match": "suffix",
                        "action": "proxy",
                    },
                ],
            }
        )

        self.assertEqual(config["rules"][0]["action"], "proxy")
        self.assertFalse(config["proxies"][0]["enabled"])
        self.assertFalse(config["upstream"]["enabled"])

    def test_route_decision_filters_private_proxies_by_client_ip(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = RouterConfigManager(Path(temp_dir) / "router.json")
            try:
                manager.update(
                    {
                        "proxies": [
                            {
                                "id": "localhost-only",
                                "enabled": True,
                                "type": "http",
                                "host": "127.0.0.1",
                                "port": 8080,
                                "access_mode": "private",
                            },
                        ],
                        "default_action": "proxy",
                    }
                )

                local_route = manager.decide(
                    "example.com",
                    client_id="user:local-tool",
                    client_ip="127.0.0.1",
                )
                remote_route = manager.decide(
                    "example.com",
                    client_id="user:local-tool",
                    client_ip="192.168.1.50",
                )

                self.assertEqual(local_route["upstream"]["id"], "localhost-only")
                self.assertIsNone(remote_route["upstream"])
            finally:
                manager.shutdown()

    def test_check_upstream_proxies_reports_each_proxy_result(self):
        runtime = AppRuntime()
        config = normalize_router_config(
            {
                "proxies": [
                    {
                        "id": "enabled-proxy",
                        "enabled": True,
                        "type": "http",
                        "host": "127.0.0.1",
                        "port": 8080,
                    },
                    {
                        "id": "disabled-proxy",
                        "enabled": False,
                        "type": "socks5",
                        "host": "127.0.0.1",
                        "port": 9050,
                    },
                ],
            }
        )

        with patch("proxy_router.runtime._probe_upstream_connectivity") as probe:
            probe.return_value = {
                "status": "reachable",
                "checked_at": "2026-05-07T12:00:00+00:00",
                "message": "TCP connection succeeded.",
                "protocol_verified": False,
            }
            payload = runtime.check_upstream_proxies(config)

        self.assertEqual([item["id"] for item in payload["results"]], ["enabled-proxy", "disabled-proxy"])
        self.assertEqual(payload["results"][0]["status"], "reachable")
        self.assertEqual(payload["results"][1]["status"], "disabled")
        status = runtime.proxy_status.snapshot()
        self.assertEqual(status["connected_count"], 1)
        self.assertEqual(status["enabled_count"], 1)
        self.assertEqual(status["results"][0]["status"], "reachable")
        probe.assert_called_once()

    def test_proxy_status_updates_from_repeated_failures_and_success(self):
        runtime = AppRuntime()
        config = normalize_router_config(
            {
                "proxies": [
                    {
                        "id": "main",
                        "enabled": True,
                        "type": "http",
                        "host": "127.0.0.1",
                        "port": 8080,
                    }
                ],
            }
        )
        runtime.refresh_upstream_status(config)
        route_decision = {
            "action": "proxy",
            "upstream": config["proxies"][0],
        }

        for index in range(2):
            runtime.record_upstream_route_failure(
                route_decision,
                destination=f"api.example.com:{443 + index}",
                error="connection refused",
                context="CONNECT",
                proxy_label="mixed",
            )

        first_snapshot = runtime.proxy_status.snapshot()
        self.assertEqual(first_snapshot["results"][0]["status"], "unknown")
        self.assertEqual(first_snapshot["results"][0]["consecutive_failures"], 2)

        runtime.record_upstream_route_failure(
            route_decision,
            destination="api.example.com:445",
            error="connection refused",
            context="CONNECT",
            proxy_label="mixed",
        )

        failed_snapshot = runtime.proxy_status.snapshot()
        self.assertEqual(failed_snapshot["connected_count"], 0)
        self.assertEqual(failed_snapshot["results"][0]["status"], "error")
        self.assertEqual(failed_snapshot["results"][0]["consecutive_failures"], 3)

        runtime.record_upstream_route_success(
            route_decision,
            destination="api.example.com:443",
            proxy_label="mixed",
        )

        recovered_snapshot = runtime.proxy_status.snapshot()
        self.assertEqual(recovered_snapshot["connected_count"], 1)
        self.assertEqual(recovered_snapshot["results"][0]["status"], "reachable")
        self.assertEqual(recovered_snapshot["results"][0]["consecutive_failures"], 0)


if __name__ == "__main__":
    unittest.main()
