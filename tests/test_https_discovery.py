import json
import tempfile
import unittest
from pathlib import Path

from proxy_router.config import RouterConfigManager
from proxy_router.constants import DEFAULT_ROUTING_PROFILE_ID
from proxy_router.traffic import AutoProxyFailureManager, HttpsDiscoveryManager
from proxy_router.util import default_router_config, is_auto_proxy_rule, normalize_router_config


class HttpsDiscoveryTests(unittest.TestCase):
    def _build_managers(self, temp_dir):
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
        auto_proxy = AutoProxyFailureManager(router_config)
        discovery = HttpsDiscoveryManager(router_config, auto_proxy, timeout_seconds=1)
        return router_config, auto_proxy, discovery

    def test_direct_fail_proxy_success_adds_auto_proxy_rule(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            router_config, auto_proxy, discovery = self._build_managers(temp_dir)
            try:
                discovery._probe_tls_direct = lambda *_args: {"ok": False, "error": "direct blocked"}
                discovery._probe_tls_via_upstream = lambda *_args: {"ok": True, "error": ""}
                route = router_config.decide("api.blocked.example.com")

                result = discovery.probe_now("api.blocked.example.com", 443, route)

                self.assertEqual(result["status"], "proxy-recommended")
                rules = router_config.snapshot()["rules"]
                self.assertTrue(any(is_auto_proxy_rule(rule, "example.com") for rule in rules))
                self.assertEqual(discovery.snapshot()["proxy_recommended"], 1)
            finally:
                discovery.shutdown()
                auto_proxy.shutdown()
                router_config.shutdown()

    def test_direct_and_proxy_fail_creates_manual_review(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            router_config, auto_proxy, discovery = self._build_managers(temp_dir)
            try:
                discovery._probe_tls_direct = lambda *_args: {"ok": False, "error": "direct blocked"}
                discovery._probe_tls_via_upstream = lambda *_args: {"ok": False, "error": "proxy blocked"}
                route = router_config.decide("api.blocked.example.com")

                result = discovery.probe_now("api.blocked.example.com", 443, route)

                self.assertEqual(result["status"], "manual-review")
                self.assertEqual(
                    len(auto_proxy.manual_review_failures(profile_id=DEFAULT_ROUTING_PROFILE_ID)),
                    1,
                )
                self.assertEqual(discovery.snapshot()["manual_review"], 1)
            finally:
                discovery.shutdown()
                auto_proxy.shutdown()
                router_config.shutdown()

    def test_fresh_probe_is_skipped_and_state_reloads(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            router_config, auto_proxy, discovery = self._build_managers(temp_dir)
            try:
                calls = {"direct": 0, "proxy": 0}

                def direct_ok(*_args):
                    calls["direct"] += 1
                    return {"ok": True, "error": ""}

                def proxy_probe(*_args):
                    calls["proxy"] += 1
                    return {"ok": True, "error": ""}

                discovery._probe_tls_direct = direct_ok
                discovery._probe_tls_via_upstream = proxy_probe
                route = router_config.decide("api.example.com")

                first = discovery.probe_now("api.example.com", 443, route)
                second = discovery.probe_now("api.example.com", 443, route)
                reloaded = HttpsDiscoveryManager(router_config, auto_proxy, timeout_seconds=1)

                self.assertEqual(first["status"], "direct-ok")
                self.assertIsNone(second)
                self.assertEqual(calls, {"direct": 1, "proxy": 0})
                self.assertEqual(reloaded.snapshot()["total_domains"], 1)
                reloaded.shutdown()
            finally:
                discovery.shutdown()
                auto_proxy.shutdown()
                router_config.shutdown()


if __name__ == "__main__":
    unittest.main()
