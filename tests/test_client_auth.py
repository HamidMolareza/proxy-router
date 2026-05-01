import hashlib
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from proxy_router.constants import SOCKS_AUTH_NO_ACCEPTABLE, SOCKS_AUTH_NO_AUTH, SOCKS_VERSION
from proxy_router.config import RouterConfigManager
from proxy_router.proxy_server import ProxyRequestHandler, Socks5RequestHandler, is_loopback_client_ip
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

    def test_normalize_router_config_supports_authenticated_default_quota(self):
        config = normalize_router_config(
            {
                "default_authenticated_client_traffic_limit": {
                    "enabled": True,
                    "max_past_hour_mb": "20",
                    "max_past_3h_mb": "",
                    "note": "signed-in clients",
                }
            }
        )

        self.assertEqual(
            config["default_authenticated_client_traffic_limit"],
            {
                "enabled": True,
                "max_past_hour_mb": 20,
                "max_past_3h_mb": None,
                "note": "signed-in clients",
            },
        )

    def test_authenticated_default_quota_overrides_general_default(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = RouterConfigManager(Path(temp_dir) / "router.json")
            try:
                manager.update(
                    {
                        "default_client_traffic_limit": {
                            "enabled": True,
                            "max_past_hour_mb": 10,
                        },
                        "default_authenticated_client_traffic_limit": {
                            "enabled": True,
                            "max_past_hour_mb": 50,
                        },
                    }
                )

                anonymous_limit = manager.find_client_traffic_limit("192.168.1.23")
                authenticated_limit = manager.find_client_traffic_limit("user:mobile")

                self.assertEqual(anonymous_limit["scope"], "default")
                self.assertEqual(anonymous_limit["max_past_hour_mb"], 10)
                self.assertEqual(authenticated_limit["scope"], "default_authenticated")
                self.assertEqual(authenticated_limit["target"], "authenticated users")
                self.assertEqual(authenticated_limit["max_past_hour_mb"], 50)
            finally:
                manager.shutdown()

    def test_authenticated_default_quota_falls_back_to_general_default_when_disabled(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = RouterConfigManager(Path(temp_dir) / "router.json")
            try:
                manager.update(
                    {
                        "default_client_traffic_limit": {
                            "enabled": True,
                            "max_past_hour_mb": 10,
                        },
                        "default_authenticated_client_traffic_limit": {
                            "enabled": False,
                            "max_past_hour_mb": 50,
                        },
                    }
                )

                authenticated_limit = manager.find_client_traffic_limit("user:mobile")

                self.assertEqual(authenticated_limit["scope"], "default")
                self.assertEqual(authenticated_limit["max_past_hour_mb"], 10)
            finally:
                manager.shutdown()

    def test_custom_user_quota_overrides_authenticated_default_quota(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = RouterConfigManager(Path(temp_dir) / "router.json")
            try:
                manager.update(
                    {
                        "default_authenticated_client_traffic_limit": {
                            "enabled": True,
                            "max_past_hour_mb": 50,
                        },
                        "client_traffic_limits": [
                            {
                                "client": "user:mobile",
                                "max_past_hour_mb": 5,
                            }
                        ],
                    }
                )

                authenticated_limit = manager.find_client_traffic_limit("user:mobile")

                self.assertEqual(authenticated_limit["scope"], "custom")
                self.assertEqual(authenticated_limit["target"], "user:mobile")
                self.assertEqual(authenticated_limit["max_past_hour_mb"], 5)
            finally:
                manager.shutdown()

    def test_loopback_http_client_bypasses_required_auth(self):
        handler = ProxyRequestHandler.__new__(ProxyRequestHandler)
        handler.client_address = ("127.0.0.1", 50000)
        handler.headers = {}
        handler.server = SimpleNamespace(
            router_config=SimpleNamespace(
                client_auth_settings=lambda: {
                    "enabled": True,
                    "allow_anonymous": False,
                    "realm": "lab",
                    "credentials": [],
                }
            ),
            client_tracker=SimpleNamespace(reidentified=lambda *_args, **_kwargs: None),
        )

        self.assertTrue(handler._authenticate_http_client())
        self.assertEqual(handler._client_identity()["auth_type"], "anonymous")
        self.assertEqual(handler._client_id(), "127.0.0.1")

    def test_remote_http_client_still_requires_auth_when_anonymous_disabled(self):
        handler = ProxyRequestHandler.__new__(ProxyRequestHandler)
        handler.client_address = ("192.168.1.23", 50000)
        handler.headers = {}
        handler.server = SimpleNamespace(
            router_config=SimpleNamespace(
                client_auth_settings=lambda: {
                    "enabled": True,
                    "allow_anonymous": False,
                    "realm": "lab",
                    "credentials": [],
                }
            ),
            client_tracker=SimpleNamespace(reidentified=lambda *_args, **_kwargs: None),
        )
        responses = []
        handler._send_proxy_auth_required = lambda settings, error=None: responses.append((settings, error))

        self.assertFalse(handler._authenticate_http_client())
        self.assertEqual(len(responses), 1)

    def test_loopback_socks_client_can_use_no_auth_when_anonymous_disabled(self):
        writes = []
        handler = Socks5RequestHandler.__new__(Socks5RequestHandler)
        handler.client_address = ("::1", 50000)
        handler.request = SimpleNamespace(sendall=lambda data: writes.append(data))
        handler.server = SimpleNamespace(
            router_config=SimpleNamespace(
                client_auth_settings=lambda: {
                    "enabled": True,
                    "allow_anonymous": False,
                    "credentials": [],
                }
            ),
            client_tracker=SimpleNamespace(reidentified=lambda *_args, **_kwargs: None),
        )

        self.assertTrue(handler._negotiate_authentication(bytes([SOCKS_AUTH_NO_AUTH])))
        self.assertEqual(writes, [bytes([SOCKS_VERSION, SOCKS_AUTH_NO_AUTH])])
        self.assertEqual(handler._client_id(), "::1")

    def test_remote_socks_client_cannot_use_no_auth_when_anonymous_disabled(self):
        writes = []
        handler = Socks5RequestHandler.__new__(Socks5RequestHandler)
        handler.client_address = ("192.168.1.23", 50000)
        handler.request = SimpleNamespace(sendall=lambda data: writes.append(data))
        handler.server = SimpleNamespace(
            router_config=SimpleNamespace(
                client_auth_settings=lambda: {
                    "enabled": True,
                    "allow_anonymous": False,
                    "credentials": [],
                }
            ),
            client_tracker=SimpleNamespace(reidentified=lambda *_args, **_kwargs: None),
        )

        self.assertFalse(handler._negotiate_authentication(bytes([SOCKS_AUTH_NO_AUTH])))
        self.assertEqual(writes, [bytes([SOCKS_VERSION, SOCKS_AUTH_NO_ACCEPTABLE])])

    def test_loopback_detection_includes_ipv4_and_ipv6(self):
        self.assertTrue(is_loopback_client_ip("127.0.0.1"))
        self.assertTrue(is_loopback_client_ip("127.42.0.9"))
        self.assertTrue(is_loopback_client_ip("::1"))
        self.assertFalse(is_loopback_client_ip("192.168.1.23"))


if __name__ == "__main__":
    unittest.main()
