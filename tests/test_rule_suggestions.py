import tempfile
import unittest
from pathlib import Path

from proxy_router.config import RouterConfigManager, RuleSuggestionConflictError, RuleSuggestionManager
from proxy_router.util import rule_suggestions_state_file_path


def requester():
    return {
        "id": "user:phone",
        "username": "phone",
        "label": "Android phone",
    }


class RuleSuggestionTests(unittest.TestCase):
    def test_authenticated_user_can_submit_and_admin_can_approve(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "router.json"
            router_config = RouterConfigManager(config_path)
            manager = RuleSuggestionManager(rule_suggestions_state_file_path(config_path), router_config)
            try:
                suggestion = manager.submit(
                    requester_identity=requester(),
                    requester_ip="192.168.1.20",
                    profile={"id": "default", "name": "Shared"},
                    rule_payload={"pattern": "example.com", "match": "suffix", "action": "direct"},
                    request_note="works better direct",
                )

                result = manager.approve(suggestion["id"])

                self.assertEqual(result["suggestion"]["status"], "approved")
                self.assertEqual(result["router_config"]["rules"][0]["pattern"], "example.com")
                self.assertEqual(result["router_config"]["rules"][0]["note"], "works better direct")
            finally:
                router_config.shutdown()

    def test_conflicting_suggestion_requires_user_confirmation_before_queueing(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "router.json"
            router_config = RouterConfigManager(config_path)
            manager = RuleSuggestionManager(rule_suggestions_state_file_path(config_path), router_config)
            try:
                router_config.update(
                    {
                        "rules": [
                            {"pattern": "example.com", "match": "suffix", "action": "direct"},
                        ]
                    }
                )

                with self.assertRaises(RuleSuggestionConflictError) as raised:
                    manager.submit(
                        requester_identity=requester(),
                        requester_ip="192.168.1.20",
                        profile={"id": "default", "name": "Shared"},
                        rule_payload={"pattern": "api.example.com", "match": "exact", "action": "block"},
                        request_note="API should be blocked",
                    )

                self.assertEqual(raised.exception.rule["pattern"], "api.example.com")
                self.assertEqual(raised.exception.conflicts[0]["type"], "conflict")

                suggestion = manager.submit(
                    requester_identity=requester(),
                    requester_ip="192.168.1.20",
                    profile={"id": "default", "name": "Shared"},
                    rule_payload={"pattern": "api.example.com", "match": "exact", "action": "block"},
                    request_note="API should be blocked",
                    confirm_conflicts=True,
                )

                self.assertTrue(suggestion["conflict_confirmed"])
                self.assertEqual(len(manager.snapshot(client="user:phone")), 1)
            finally:
                router_config.shutdown()

    def test_admin_approval_is_blocked_while_conflict_still_exists(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "router.json"
            router_config = RouterConfigManager(config_path)
            manager = RuleSuggestionManager(rule_suggestions_state_file_path(config_path), router_config)
            try:
                router_config.update(
                    {
                        "rules": [
                            {"pattern": "example.com", "match": "suffix", "action": "direct"},
                        ]
                    }
                )
                suggestion = manager.submit(
                    requester_identity=requester(),
                    requester_ip="192.168.1.20",
                    profile={"id": "default", "name": "Shared"},
                    rule_payload={"pattern": "api.example.com", "match": "exact", "action": "block"},
                    request_note="",
                    confirm_conflicts=True,
                )

                with self.assertRaises(RuleSuggestionConflictError):
                    manager.approve(suggestion["id"])

                self.assertEqual(manager.snapshot()[0]["status"], "pending")
            finally:
                router_config.shutdown()

    def test_rejection_message_persists_in_sidecar_state(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "router.json"
            state_path = rule_suggestions_state_file_path(config_path)
            router_config = RouterConfigManager(config_path)
            manager = RuleSuggestionManager(state_path, router_config)
            try:
                suggestion = manager.submit(
                    requester_identity=requester(),
                    requester_ip="192.168.1.20",
                    profile={"id": "default", "name": "Shared"},
                    rule_payload={"pattern": "example.org", "match": "suffix", "action": "direct"},
                    request_note="please add",
                )
                manager.reject(suggestion["id"], message="Not needed on this network")

                reloaded = RuleSuggestionManager(state_path, router_config)
                saved = reloaded.snapshot(client="user:phone")[0]

                self.assertEqual(saved["status"], "rejected")
                self.assertEqual(saved["admin_message"], "Not needed on this network")
            finally:
                router_config.shutdown()

    def test_clear_history_can_remove_only_one_requester(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "router.json"
            router_config = RouterConfigManager(config_path)
            manager = RuleSuggestionManager(rule_suggestions_state_file_path(config_path), router_config)
            try:
                manager.submit(
                    requester_identity=requester(),
                    requester_ip="192.168.1.20",
                    profile={"id": "default", "name": "Shared"},
                    rule_payload={"pattern": "phone.example", "action": "direct"},
                    request_note="phone rule",
                )
                manager.submit(
                    requester_identity={
                        "id": "user:tablet",
                        "username": "tablet",
                        "label": "Tablet",
                    },
                    requester_ip="192.168.1.21",
                    profile={"id": "default", "name": "Shared"},
                    rule_payload={"pattern": "tablet.example", "action": "direct"},
                    request_note="tablet rule",
                )

                result = manager.clear_history(client="user:phone")

                self.assertEqual(result, {"removed": 1, "remaining": 1})
                self.assertEqual(manager.snapshot(client="user:phone"), [])
                self.assertEqual(manager.snapshot(client="user:tablet")[0]["rule"]["pattern"], "tablet.example")
            finally:
                router_config.shutdown()

    def test_clear_history_without_client_removes_all_suggestions(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "router.json"
            router_config = RouterConfigManager(config_path)
            manager = RuleSuggestionManager(rule_suggestions_state_file_path(config_path), router_config)
            try:
                manager.submit(
                    requester_identity=requester(),
                    requester_ip="192.168.1.20",
                    profile={"id": "default", "name": "Shared"},
                    rule_payload={"pattern": "phone.example", "action": "direct"},
                    request_note="phone rule",
                )
                manager.submit(
                    requester_identity={
                        "id": "user:tablet",
                        "username": "tablet",
                        "label": "Tablet",
                    },
                    requester_ip="192.168.1.21",
                    profile={"id": "default", "name": "Shared"},
                    rule_payload={"pattern": "tablet.example", "action": "direct"},
                    request_note="tablet rule",
                )

                result = manager.clear_history()

                self.assertEqual(result, {"removed": 2, "remaining": 0})
                self.assertEqual(manager.snapshot(), [])
            finally:
                router_config.shutdown()

    def test_delete_removes_one_requester_suggestion(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "router.json"
            router_config = RouterConfigManager(config_path)
            manager = RuleSuggestionManager(rule_suggestions_state_file_path(config_path), router_config)
            try:
                phone = manager.submit(
                    requester_identity=requester(),
                    requester_ip="192.168.1.20",
                    profile={"id": "default", "name": "Shared"},
                    rule_payload={"pattern": "phone.example", "action": "direct"},
                    request_note="phone rule",
                )
                manager.submit(
                    requester_identity={
                        "id": "user:tablet",
                        "username": "tablet",
                        "label": "Tablet",
                    },
                    requester_ip="192.168.1.21",
                    profile={"id": "default", "name": "Shared"},
                    rule_payload={"pattern": "tablet.example", "action": "direct"},
                    request_note="tablet rule",
                )

                result = manager.delete(phone["id"], client="user:phone")

                self.assertEqual(result["suggestion"]["id"], phone["id"])
                self.assertEqual(result["remaining"], 1)
                self.assertEqual(manager.snapshot(client="user:phone"), [])
                self.assertEqual(manager.snapshot(client="user:tablet")[0]["rule"]["pattern"], "tablet.example")
            finally:
                router_config.shutdown()

    def test_delete_rejects_other_requester_suggestion(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "router.json"
            router_config = RouterConfigManager(config_path)
            manager = RuleSuggestionManager(rule_suggestions_state_file_path(config_path), router_config)
            try:
                phone = manager.submit(
                    requester_identity=requester(),
                    requester_ip="192.168.1.20",
                    profile={"id": "default", "name": "Shared"},
                    rule_payload={"pattern": "phone.example", "action": "direct"},
                    request_note="phone rule",
                )

                with self.assertRaises(PermissionError):
                    manager.delete(phone["id"], client="user:tablet")

                self.assertEqual(manager.snapshot(client="user:phone")[0]["id"], phone["id"])
            finally:
                router_config.shutdown()

    def test_anonymous_clients_cannot_submit_suggestions(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "router.json"
            router_config = RouterConfigManager(config_path)
            manager = RuleSuggestionManager(rule_suggestions_state_file_path(config_path), router_config)
            try:
                with self.assertRaises(PermissionError):
                    manager.submit(
                        requester_identity={"id": "192.168.1.20"},
                        requester_ip="192.168.1.20",
                        profile={"id": "default", "name": "Shared"},
                        rule_payload={"pattern": "example.net", "action": "direct"},
                        request_note="",
                    )
            finally:
                router_config.shutdown()


if __name__ == "__main__":
    unittest.main()
