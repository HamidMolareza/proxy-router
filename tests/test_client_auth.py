import hashlib
import unittest

from proxy_router.util import (
    authenticate_client_auth_credentials,
    client_ip_matches_limit_target,
    hash_client_auth_password,
    normalize_client_limit_target,
    normalize_router_config,
    verify_client_auth_password,
)


class ClientAuthTests(unittest.TestCase):
    def test_normalize_router_config_hashes_plaintext_passwords(self):
        config = normalize_router_config(
            {
                "client_auth": {
                    "enabled": True,
                    "allow_anonymous": True,
                    "realm": "lab",
                    "credentials": [
                        {
                            "username": "phone",
                            "password": "secret",
                            "label": "Android phone",
                        }
                    ],
                }
            }
        )

        credential = config["client_auth"]["credentials"][0]
        self.assertEqual(credential["username"], "phone")
        self.assertNotIn("password", credential)
        self.assertTrue(credential["password_hash"].startswith("pbkdf2_sha256:"))
        self.assertTrue(verify_client_auth_password("secret", credential["password_hash"]))
        self.assertFalse(verify_client_auth_password("wrong", credential["password_hash"]))

    def test_authentication_accepts_enabled_credential(self):
        settings = {
            "enabled": True,
            "allow_anonymous": True,
            "credentials": [
                {
                    "enabled": True,
                    "username": "phone",
                    "password_hash": hash_client_auth_password("secret"),
                    "label": "Android phone",
                }
            ],
        }

        authenticated = authenticate_client_auth_credentials(settings, "phone", "secret")

        self.assertIsNotNone(authenticated)
        self.assertEqual(authenticated["id"], "user:phone")
        self.assertEqual(authenticated["label"], "Android phone")
        self.assertIsNone(authenticate_client_auth_credentials(settings, "phone", "wrong"))

    def test_legacy_sha256_password_hashes_still_verify(self):
        legacy_hash = "sha256:" + hashlib.sha256(b"secret").hexdigest()

        self.assertTrue(verify_client_auth_password("secret", legacy_hash))
        self.assertFalse(verify_client_auth_password("wrong", legacy_hash))

    def test_client_limit_targets_can_match_authenticated_identity(self):
        self.assertEqual(normalize_client_limit_target("phone"), "user:phone")
        self.assertEqual(normalize_client_limit_target("user:phone"), "user:phone")
        self.assertTrue(client_ip_matches_limit_target("user:phone", "user:phone"))
        self.assertFalse(client_ip_matches_limit_target("192.168.1.23", "user:phone"))


if __name__ == "__main__":
    unittest.main()
