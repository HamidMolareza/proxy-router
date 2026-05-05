import tempfile
import unittest
from pathlib import Path

from proxy_router.config import RouterConfigManager
from proxy_router.util import find_router_rule_issues, normalize_router_config, validate_router_rule_issues


def profile_signature():
    return {
        "internet_key": "wifi:test",
        "internet_label": "Test Wi-Fi",
        "route_interface": "wlan0",
        "route_gateway": "192.168.1.1",
        "vpn_keys": [],
        "vpn_labels": [],
    }


class RuleConflictTests(unittest.TestCase):
    def test_duplicate_rule_identity_in_same_scope_is_blocking(self):
        config = normalize_router_config(
            {
                "rules": [
                    {"pattern": "Example.com", "match": "suffix", "action": "direct"},
                    {"pattern": "*.example.com", "match": "suffix", "action": "direct"},
                ]
            }
        )

        issues = find_router_rule_issues(config)

        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["type"], "duplicate")
        with self.assertRaisesRegex(ValueError, "duplicate suffix rule"):
            validate_router_rule_issues(config)

    def test_duplicate_between_enabled_profile_and_shared_is_blocking(self):
        config = normalize_router_config(
            {
                "rules": [
                    {"pattern": "example.com", "match": "suffix", "action": "direct"},
                ],
                "routing_profiles": [
                    {
                        "id": "profile-home",
                        "name": "Home",
                        "enabled": True,
                        "signature": profile_signature(),
                        "rules": [
                            {"pattern": "example.com", "match": "suffix", "action": "direct"},
                        ],
                    }
                ],
            }
        )

        issues = find_router_rule_issues(config)

        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["type"], "duplicate")
        self.assertEqual(issues[0]["context_label"], "Home + Shared")

    def test_overlapping_enabled_rules_with_different_actions_are_blocking(self):
        config = normalize_router_config(
            {
                "rules": [
                    {"pattern": "example.com", "match": "suffix", "action": "direct"},
                ],
                "routing_profiles": [
                    {
                        "id": "profile-home",
                        "name": "Home",
                        "enabled": True,
                        "signature": profile_signature(),
                        "rules": [
                            {"pattern": "api.example.com", "match": "exact", "action": "block"},
                        ],
                    }
                ],
            }
        )

        issues = find_router_rule_issues(config)

        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["type"], "conflict")
        with self.assertRaisesRegex(ValueError, "conflicting actions"):
            validate_router_rule_issues(config)

    def test_same_action_overlap_is_allowed_unless_duplicate(self):
        config = normalize_router_config(
            {
                "rules": [
                    {"pattern": "example.com", "match": "suffix", "action": "direct"},
                    {"pattern": "api.example.com", "match": "exact", "action": "direct"},
                ]
            }
        )

        self.assertEqual(find_router_rule_issues(config), [])
        validate_router_rule_issues(config)

    def test_disabled_rules_do_not_create_action_conflicts(self):
        config = normalize_router_config(
            {
                "rules": [
                    {"pattern": "example.com", "match": "suffix", "action": "direct"},
                    {"pattern": "api.example.com", "match": "exact", "action": "block", "enabled": False},
                ]
            }
        )

        self.assertEqual(find_router_rule_issues(config), [])
        validate_router_rule_issues(config)

    def test_contains_rules_conflict_with_broader_overlap(self):
        config = normalize_router_config(
            {
                "rules": [
                    {"pattern": "ads", "match": "contains", "action": "block"},
                    {"pattern": "example.com", "match": "suffix", "action": "direct"},
                ]
            }
        )

        issues = find_router_rule_issues(config)

        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]["type"], "conflict")

    def test_manager_update_rejects_unresolved_rule_issues(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = RouterConfigManager(Path(temp_dir) / "router.json")
            try:
                with self.assertRaisesRegex(ValueError, "blocking issue"):
                    manager.update(
                        {
                            "rules": [
                                {"pattern": "example.com", "match": "suffix", "action": "direct"},
                                {"pattern": "api.example.com", "match": "exact", "action": "block"},
                            ]
                        }
                    )
            finally:
                manager.shutdown()


if __name__ == "__main__":
    unittest.main()
