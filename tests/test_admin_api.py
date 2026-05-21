import tempfile
import unittest
from pathlib import Path

from proxy_router.config import RouterConfigManager
from proxy_router.util import normalize_router_config, verify_client_auth_password


class AdminApiTokenTests(unittest.TestCase):
    def test_normalize_router_config_hashes_plaintext_admin_token(self):
        config = normalize_router_config(
            {
                "admin_api": {
                    "enabled": True,
                    "tokens": [
                        {
                            "id": "codex",
                            "name": "Codex",
                            "token": "secret-token",
                            "created_at": "2026-05-11T00:00:00+03:30",
                        }
                    ],
                }
            }
        )

        token = config["admin_api"]["tokens"][0]
        self.assertEqual(token["id"], "codex")
        self.assertEqual(token["name"], "Codex")
        self.assertNotIn("token", token)
        self.assertTrue(token["token_hash"].startswith("pbkdf2_sha256:"))
        self.assertTrue(verify_client_auth_password("secret-token", token["token_hash"]))

    def test_public_snapshot_hides_admin_token_hashes(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = RouterConfigManager(Path(temp_dir) / "router.json")
            try:
                manager.update(
                    {
                        "admin_api": {
                            "enabled": True,
                            "tokens": [{"id": "codex", "name": "Codex", "token": "secret-token"}],
                        }
                    }
                )

                public = manager.public_snapshot()

                token = public["admin_api"]["tokens"][0]
                self.assertNotIn("token", token)
                self.assertNotIn("token_hash", token)
                self.assertEqual(token["id"], "codex")
            finally:
                manager.shutdown()

    def test_update_without_admin_api_preserves_existing_tokens(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = RouterConfigManager(Path(temp_dir) / "router.json")
            try:
                manager.update(
                    {
                        "admin_api": {
                            "enabled": True,
                            "tokens": [{"id": "codex", "name": "Codex", "token": "secret-token"}],
                        }
                    }
                )

                manager.update({"rules": [{"pattern": "example.com", "action": "direct"}]})

                token = manager.snapshot()["admin_api"]["tokens"][0]
                self.assertEqual(token["id"], "codex")
                self.assertTrue(verify_client_auth_password("secret-token", token["token_hash"]))
            finally:
                manager.shutdown()

    def test_update_with_public_admin_api_metadata_preserves_existing_tokens(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = RouterConfigManager(Path(temp_dir) / "router.json")
            try:
                manager.update(
                    {
                        "admin_api": {
                            "enabled": True,
                            "tokens": [{"id": "codex", "name": "Codex", "token": "secret-token"}],
                        }
                    }
                )
                public_config = manager.public_snapshot()
                public_config["rules"] = [{"pattern": "example.com", "action": "direct"}]

                manager.update(public_config)

                token = manager.snapshot()["admin_api"]["tokens"][0]
                self.assertEqual(token["id"], "codex")
                self.assertTrue(verify_client_auth_password("secret-token", token["token_hash"]))
            finally:
                manager.shutdown()

    def test_preview_without_admin_api_hides_preserved_token_hashes(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = RouterConfigManager(Path(temp_dir) / "router.json")
            try:
                manager.update(
                    {
                        "admin_api": {
                            "enabled": True,
                            "tokens": [{"id": "codex", "name": "Codex", "token": "secret-token"}],
                        }
                    }
                )

                preview = manager.preview_update({"rules": [{"pattern": "example.com", "action": "direct"}]})

                token = preview["router_config"]["admin_api"]["tokens"][0]
                self.assertNotIn("token", token)
                self.assertNotIn("token_hash", token)
                self.assertEqual(token["id"], "codex")
            finally:
                manager.shutdown()

    def test_created_admin_token_enables_auth_and_verifies(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = RouterConfigManager(Path(temp_dir) / "router.json")
            try:
                result = manager.create_admin_api_token("Codex MCP")

                self.assertTrue(manager.admin_api_requires_auth())
                self.assertTrue(manager.verify_admin_api_token(result["token"], client_ip="127.0.0.1"))
                self.assertFalse(manager.verify_admin_api_token("wrong", client_ip="127.0.0.1"))
            finally:
                manager.shutdown()


if __name__ == "__main__":
    unittest.main()
