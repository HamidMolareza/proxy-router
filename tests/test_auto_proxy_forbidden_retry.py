import json
import tempfile
import unittest
from pathlib import Path

from proxy_router.config import RouterConfigManager
from proxy_router.constants import AUTO_PROXY_PROBE_ROUTE_LABEL_PREFIX
from proxy_router.traffic import AutoProxyFailureManager
from proxy_router.util import default_router_config, is_auto_proxy_rule, normalize_router_config


class AutoProxyForbiddenRetryTests(unittest.TestCase):
    def _build_manager(self, temp_dir):
        config = default_router_config()
        config["auto_proxy_failures"]["enabled"] = True
        config["upstream"] = {
            "enabled": True,
            "type": "socks5",
            "host": "127.0.0.1",
            "port": 9050,
        }
        config_path = Path(temp_dir) / "router-config.json"
        config_path.write_text(
            json.dumps(normalize_router_config(config), indent=2),
            encoding="utf-8",
        )
        router_config = RouterConfigManager(config_path)
        manager = AutoProxyFailureManager(router_config)
        return router_config, manager

    def test_https_403_can_build_immediate_auto_proxy_probe_route(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            router_config, manager = self._build_manager(temp_dir)
            try:
                route_decision = router_config.decide("blocked.example.com")

                probe_route = manager.status_probe_route(
                    "blocked.example.com",
                    route_decision,
                    status_code=403,
                )

                self.assertIsNotNone(probe_route)
                self.assertEqual(probe_route["action"], "proxy")
                self.assertTrue(probe_route["auto_proxy_probe"])
                self.assertTrue(
                    probe_route["route_label"].startswith(AUTO_PROXY_PROBE_ROUTE_LABEL_PREFIX)
                )
            finally:
                manager.shutdown()
                router_config.shutdown()

    def test_successful_403_probe_adds_auto_proxy_rule(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            router_config, manager = self._build_manager(temp_dir)
            try:
                route_decision = router_config.decide("blocked.example.com")
                probe_route = manager.status_probe_route(
                    "blocked.example.com",
                    route_decision,
                    status_code=403,
                )

                manager.record_success(
                    "blocked.example.com",
                    route_label=probe_route["route_label"],
                    profile_id=probe_route["profile_id"],
                )

                rules = router_config.snapshot()["rules"]
                self.assertTrue(
                    any(
                        is_auto_proxy_rule(rule, "example.com") and rule.get("action") == "proxy"
                        for rule in rules
                    )
                )
            finally:
                manager.shutdown()
                router_config.shutdown()

    def test_failed_403_probe_does_not_add_auto_proxy_rule(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            router_config, manager = self._build_manager(temp_dir)
            try:
                route_decision = router_config.decide("blocked.example.com")
                probe_route = manager.status_probe_route(
                    "blocked.example.com",
                    route_decision,
                    status_code=403,
                )

                manager.record_failure(
                    "blocked.example.com",
                    route_label=probe_route["route_label"],
                    destination="https://blocked.example.com/",
                    error="Upstream responded with HTTP 403 Forbidden",
                    context="upstream http 403",
                    method="GET",
                    profile_id=probe_route["profile_id"],
                )

                rules = router_config.snapshot()["rules"]
                self.assertFalse(any(is_auto_proxy_rule(rule, "example.com") for rule in rules))
                self.assertEqual(
                    len(manager.manual_review_failures(profile_id=probe_route["profile_id"])),
                    1,
                )
            finally:
                manager.shutdown()
                router_config.shutdown()

    def test_status_probe_route_ignores_non_403_and_handled_routes(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            router_config, manager = self._build_manager(temp_dir)
            try:
                route_decision = router_config.decide("blocked.example.com")
                self.assertIsNone(
                    manager.status_probe_route("blocked.example.com", route_decision, status_code=404)
                )

                handled_route = dict(route_decision)
                handled_route["matched_rule"] = {"pattern": "example.com", "action": "direct"}
                self.assertIsNone(
                    manager.status_probe_route("blocked.example.com", handled_route, status_code=403)
                )
            finally:
                manager.shutdown()
                router_config.shutdown()


if __name__ == "__main__":
    unittest.main()
