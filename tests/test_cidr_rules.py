import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from proxy_router.config import RouterConfigManager
from proxy_router.sing_box import build_sing_box_config
from proxy_router.util import (
    is_specific_rule_override,
    normalize_routing_target_payload,
    rule_conflict_hint,
    rule_matches_host,
    rule_patterns_overlap,
)


class CidrRulesTests(unittest.TestCase):
    def test_rule_matches_host_ipv4_and_ipv6_cidr(self):
        rule_v4 = {"pattern": "149.154.160.0/20", "match": "cidr", "action": "proxy"}
        self.assertTrue(rule_matches_host(rule_v4, "149.154.167.91"))
        self.assertTrue(rule_matches_host(rule_v4, "149.154.175.254"))
        self.assertFalse(rule_matches_host(rule_v4, "149.154.159.255"))
        self.assertFalse(rule_matches_host(rule_v4, "8.8.8.8"))
        self.assertFalse(rule_matches_host(rule_v4, "telegram.org"))

        rule_v6 = {"pattern": "2001:b28:f23d::/48", "match": "cidr", "action": "proxy"}
        self.assertTrue(rule_matches_host(rule_v6, "2001:b28:f23d:1::1"))
        self.assertTrue(rule_matches_host(rule_v6, "[2001:b28:f23d:1::1]"))
        self.assertFalse(rule_matches_host(rule_v6, "2001:b28:f23e::1"))
        self.assertFalse(rule_matches_host(rule_v6, "127.0.0.1"))

    def test_normalize_routing_target_payload_validates_cidr(self):
        now = datetime.now(timezone.utc)
        default_config = {"default_action": "direct"}

        # Valid CIDR
        valid_payload = {
            "default_action": "direct",
            "rules": [
                {"pattern": "149.154.160.0/20", "match": "cidr", "action": "proxy"}
            ],
        }
        normalized = normalize_routing_target_payload(
            valid_payload, field_prefix="test", default_config=default_config, now=now
        )
        self.assertEqual(len(normalized["rules"]), 1)
        self.assertEqual(normalized["rules"][0]["pattern"], "149.154.160.0/20")
        self.assertEqual(normalized["rules"][0]["match"], "cidr")

        # Invalid CIDR
        invalid_payload = {
            "default_action": "direct",
            "rules": [
                {"pattern": "not-an-ip/24", "match": "cidr", "action": "proxy"}
            ],
        }
        with self.assertRaises(ValueError):
            normalize_routing_target_payload(
                invalid_payload, field_prefix="test", default_config=default_config, now=now
            )

    def test_cidr_overlap_and_override_detection(self):
        broad_cidr = {"pattern": "149.154.160.0/20", "match": "cidr"}
        narrow_cidr = {"pattern": "149.154.167.0/24", "match": "cidr"}
        exact_ip = {"pattern": "149.154.167.91", "match": "exact"}
        other_cidr = {"pattern": "91.108.4.0/22", "match": "cidr"}

        self.assertTrue(rule_patterns_overlap(broad_cidr, narrow_cidr))
        self.assertTrue(rule_patterns_overlap(broad_cidr, exact_ip))
        self.assertTrue(rule_patterns_overlap(exact_ip, broad_cidr))
        self.assertFalse(rule_patterns_overlap(broad_cidr, other_cidr))

        # is_specific_rule_override: narrow over broad
        self.assertTrue(is_specific_rule_override(narrow_cidr, broad_cidr))
        self.assertFalse(is_specific_rule_override(broad_cidr, narrow_cidr))
        self.assertTrue(is_specific_rule_override(exact_ip, broad_cidr))
        self.assertFalse(is_specific_rule_override(broad_cidr, exact_ip))

        hint = rule_conflict_hint(
            {"rule": narrow_cidr, "scope": "profile", "scope_label": "Shared", "index": 0},
            {"rule": broad_cidr, "scope": "profile", "scope_label": "Shared", "index": 1},
        )
        self.assertIn("specific exception", hint)

    def test_sing_box_export_includes_ip_cidr(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "router-config.json"
            manager = RouterConfigManager(config_file)
            try:
                manager.update(
                    {
                        "proxies": [
                            {
                                "id": "gh-proxy",
                                "name": "gh-proxy",
                                "type": "socks5",
                                "host": "127.0.0.1",
                                "port": 8910,
                            }
                        ],
                        "rules": [
                            {
                                "pattern": "149.154.160.0/20",
                                "match": "cidr",
                                "action": "proxy",
                            }
                        ],
                    }
                )
                sb_config = build_sing_box_config(manager)
                matching_rules = [
                    r for r in sb_config["route"]["rules"]
                    if r.get("ip_cidr") == ["149.154.160.0/20"]
                ]
                self.assertEqual(len(matching_rules), 1)
                self.assertEqual(matching_rules[0]["action"], "route")
                self.assertEqual(matching_rules[0]["outbound"], "proxy-gh-proxy")
            finally:
                manager.shutdown()

    def test_router_config_route_decision_matches_cidr(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_file = Path(temp_dir) / "router-config.json"
            manager = RouterConfigManager(config_file)
            try:
                manager.update(
                    {
                        "default_action": "direct",
                        "proxies": [
                            {
                                "id": "gh-proxy",
                                "name": "gh-proxy",
                                "type": "socks5",
                                "host": "127.0.0.1",
                                "port": 8910,
                            }
                        ],
                        "rules": [
                            {
                                "pattern": "149.154.160.0/20",
                                "match": "cidr",
                                "action": "proxy",
                            }
                        ],
                    }
                )
                decision = manager.decide("149.154.167.91")
                self.assertEqual(decision["action"], "proxy")
                self.assertEqual(decision["upstream"]["id"], "gh-proxy")

                # Outside subnet should fall back to direct
                outside_decision = manager.decide("8.8.8.8")
                self.assertEqual(outside_decision["action"], "direct")
            finally:
                manager.shutdown()


if __name__ == "__main__":
    unittest.main()
