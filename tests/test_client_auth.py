import base64
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

import proxy_router.proxy_server as proxy_server
from proxy_router.constants import (
    SOCKS_AUTH_NO_ACCEPTABLE,
    SOCKS_AUTH_NO_AUTH,
    SOCKS_AUTH_USERNAME_PASSWORD,
    SOCKS_VERSION,
)
from proxy_router.config import RouterConfigManager
from proxy_router.proxy_server import ProxyRequestHandler, Socks5RequestHandler, is_loopback_client_ip
from proxy_router.traffic import TrafficQuotaManager
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

    def test_change_client_auth_password_updates_only_target_password(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = RouterConfigManager(Path(temp_dir) / "router.json")
            try:
                saved = manager.update(
                    {
                        "client_auth": {
                            "enabled": True,
                            "allow_anonymous": True,
                            "credentials": [
                                {"username": "phone", "password": "old-secret", "label": "Android phone"},
                                {"username": "tablet", "password": "tablet-secret", "label": "Tablet"},
                            ],
                        }
                    }
                )
                old_hash = saved["client_auth"]["credentials"][0]["password_hash"]

                changed = manager.change_client_auth_password(
                    "phone",
                    current_password="old-secret",
                    new_password="new-secret",
                )

                phone = changed["client_auth"]["credentials"][0]
                tablet = changed["client_auth"]["credentials"][1]
                self.assertEqual(phone["username"], "phone")
                self.assertEqual(phone["label"], "Android phone")
                self.assertNotEqual(phone["password_hash"], old_hash)
                self.assertTrue(verify_client_auth_password("new-secret", phone["password_hash"]))
                self.assertFalse(verify_client_auth_password("old-secret", phone["password_hash"]))
                self.assertTrue(verify_client_auth_password("tablet-secret", tablet["password_hash"]))
            finally:
                manager.shutdown()

    def test_change_client_auth_password_rejects_wrong_current_password(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = RouterConfigManager(Path(temp_dir) / "router.json")
            try:
                manager.update(
                    {
                        "client_auth": {
                            "credentials": [
                                {"username": "phone", "password": "old-secret"},
                            ],
                        }
                    }
                )

                with self.assertRaises(PermissionError):
                    manager.change_client_auth_password(
                        "phone",
                        current_password="wrong-secret",
                        new_password="new-secret",
                    )

                credential = manager.snapshot()["client_auth"]["credentials"][0]
                self.assertTrue(verify_client_auth_password("old-secret", credential["password_hash"]))
            finally:
                manager.shutdown()

    def test_change_client_auth_password_rejects_blank_new_password(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = RouterConfigManager(Path(temp_dir) / "router.json")
            try:
                manager.update(
                    {
                        "client_auth": {
                            "credentials": [
                                {"username": "phone", "password": "old-secret"},
                            ],
                        }
                    }
                )

                with self.assertRaises(ValueError):
                    manager.change_client_auth_password(
                        "phone",
                        current_password="old-secret",
                        new_password="",
                    )
            finally:
                manager.shutdown()

    def test_change_client_auth_password_rejects_disabled_credential(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = RouterConfigManager(Path(temp_dir) / "router.json")
            try:
                manager.update(
                    {
                        "client_auth": {
                            "credentials": [
                                {"username": "phone", "password": "old-secret", "enabled": False},
                            ],
                        }
                    }
                )

                with self.assertRaises(PermissionError):
                    manager.change_client_auth_password(
                        "phone",
                        current_password="old-secret",
                        new_password="new-secret",
                    )
            finally:
                manager.shutdown()

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

    def test_normalize_router_config_defaults_quota_groups_to_empty_list(self):
        config = normalize_router_config({})

        self.assertEqual(config["client_quota_groups"], [])

    def test_normalize_router_config_accepts_quota_groups(self):
        config = normalize_router_config(
            {
                "client_quota_groups": [
                    {
                        "id": "Ali Devices",
                        "label": "Ali",
                        "enabled": True,
                        "members": ["user:ali-phone", "ali-laptop", "user:ali-phone"],
                    }
                ],
                "client_traffic_limits": [
                    {
                        "client": "group:Ali Devices",
                        "max_past_hour_mb": "500",
                    }
                ],
            }
        )

        self.assertEqual(
            config["client_quota_groups"],
            [
                {
                    "id": "ali-devices",
                    "label": "Ali",
                    "enabled": True,
                    "members": ["user:ali-phone", "user:ali-laptop"],
                }
            ],
        )
        self.assertEqual(config["client_traffic_limits"][0]["client"], "group:ali-devices")

    def test_normalize_router_config_rejects_duplicate_enabled_group_members(self):
        with self.assertRaises(ValueError):
            normalize_router_config(
                {
                    "client_quota_groups": [
                        {"id": "ali", "members": ["user:ali-phone"]},
                        {"id": "ali-alt", "members": ["user:ali-phone"]},
                    ]
                }
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

    def test_group_quota_applies_to_members_and_aggregates_usage(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = RouterConfigManager(Path(temp_dir) / "router.json")
            quota_manager = TrafficQuotaManager()
            try:
                manager.update(
                    {
                        "client_quota_groups": [
                            {
                                "id": "ali",
                                "label": "Ali",
                                "members": ["user:ali-phone", "user:ali-laptop"],
                            }
                        ],
                        "client_traffic_limits": [
                            {
                                "client": "group:ali",
                                "max_past_hour_mb": 1,
                            }
                        ],
                    }
                )
                quota_manager.record_usage(client="user:ali-phone", total_bytes=600_000)
                quota_manager.record_usage(client="user:ali-laptop", total_bytes=500_000)

                phone_limit = manager.find_client_traffic_limit("user:ali-phone")
                laptop_limit = manager.find_client_traffic_limit("user:ali-laptop")
                evaluation = quota_manager.evaluate_client("user:ali-phone", manager)

                self.assertEqual(phone_limit["scope"], "group")
                self.assertEqual(laptop_limit["scope"], "group")
                self.assertEqual(phone_limit["target"], "group:ali")
                self.assertEqual(evaluation["usage"]["1h"]["total_bytes"], 1_100_000)
                self.assertFalse(evaluation["allowed"])
                self.assertEqual(evaluation["exceeded_windows"][0]["key"], "1h")
            finally:
                manager.shutdown()

    def test_user_quota_overrides_group_quota(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = RouterConfigManager(Path(temp_dir) / "router.json")
            try:
                manager.update(
                    {
                        "client_quota_groups": [
                            {
                                "id": "ali",
                                "members": ["user:ali-phone", "user:ali-laptop"],
                            }
                        ],
                        "client_traffic_limits": [
                            {
                                "client": "group:ali",
                                "max_past_hour_mb": 1,
                            },
                            {
                                "client": "user:ali-phone",
                                "max_past_hour_mb": 5,
                            },
                        ],
                    }
                )

                phone_limit = manager.find_client_traffic_limit("user:ali-phone")
                laptop_limit = manager.find_client_traffic_limit("user:ali-laptop")

                self.assertEqual(phone_limit["scope"], "custom")
                self.assertEqual(phone_limit["target"], "user:ali-phone")
                self.assertEqual(phone_limit["max_past_hour_mb"], 5)
                self.assertEqual(laptop_limit["scope"], "group")
                self.assertEqual(laptop_limit["target"], "group:ali")
            finally:
                manager.shutdown()

    def test_user_exemption_overrides_user_and_group_quota(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = RouterConfigManager(Path(temp_dir) / "router.json")
            try:
                manager.update(
                    {
                        "client_quota_groups": [
                            {
                                "id": "ali",
                                "members": ["user:ali-phone", "user:ali-laptop"],
                            }
                        ],
                        "client_traffic_limits": [
                            {
                                "client": "group:ali",
                                "max_past_hour_mb": 1,
                            },
                            {
                                "client": "user:ali-phone",
                                "max_past_hour_mb": 5,
                            },
                        ],
                        "client_traffic_exemptions": [
                            {
                                "client": "user:ali-phone",
                                "duration": "always",
                            }
                        ],
                    }
                )

                phone_limit = manager.find_client_traffic_limit("user:ali-phone")
                laptop_limit = manager.find_client_traffic_limit("user:ali-laptop")

                self.assertEqual(phone_limit["scope"], "exempt")
                self.assertTrue(phone_limit["exempt"])
                self.assertEqual(laptop_limit["scope"], "group")
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

    def test_loopback_http_client_uses_basic_auth_when_header_is_present(self):
        handler = ProxyRequestHandler.__new__(ProxyRequestHandler)
        handler.client_address = ("127.0.0.1", 50000)
        token = base64.b64encode(b"phone:secret").decode("ascii")
        handler.headers = {"Proxy-Authorization": f"Basic {token}"}
        handler.server = SimpleNamespace(
            router_config=SimpleNamespace(
                client_auth_settings=lambda: {
                    "enabled": True,
                    "allow_anonymous": False,
                    "realm": "lab",
                    "credentials": [
                        {
                            "username": "phone",
                            "password_hash": hash_client_auth_password("secret"),
                            "label": "Phone",
                            "enabled": True,
                        }
                    ],
                }
            ),
            client_tracker=SimpleNamespace(reidentified=lambda *_args, **_kwargs: None),
        )

        self.assertTrue(handler._authenticate_http_client())
        self.assertEqual(handler._client_identity()["auth_type"], "basic")
        self.assertEqual(handler._client_id(), "user:phone")

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

    def test_intercepted_https_reuses_authenticated_connect_identity(self):
        handler = ProxyRequestHandler.__new__(ProxyRequestHandler)
        handler.client_address = ("192.168.1.23", 50000)
        handler.headers = {}
        inherited_identity = {
            "id": "user:phone",
            "ip": "192.168.1.23",
            "auth_type": "basic",
            "username": "phone",
            "label": "Phone",
        }
        handler.server = SimpleNamespace(
            client_identity=inherited_identity,
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

        self.assertTrue(handler._authenticate_http_client())
        self.assertEqual(handler._client_identity(), inherited_identity)
        self.assertEqual(responses, [])

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

    def test_remote_socks_client_prefers_no_auth_when_anonymous_allowed(self):
        writes = []
        handler = Socks5RequestHandler.__new__(Socks5RequestHandler)
        handler.client_address = ("192.168.1.23", 50000)
        handler.request = SimpleNamespace(sendall=lambda data: writes.append(data))
        handler.server = SimpleNamespace(
            router_config=SimpleNamespace(
                client_auth_settings=lambda: {
                    "enabled": True,
                    "allow_anonymous": True,
                    "credentials": [
                        {
                            "enabled": True,
                            "username": "phone",
                            "password_hash": hash_client_auth_password("secret"),
                        }
                    ],
                }
            ),
            client_tracker=SimpleNamespace(reidentified=lambda *_args, **_kwargs: None),
        )

        self.assertTrue(
            handler._negotiate_authentication(bytes([SOCKS_AUTH_NO_AUTH, SOCKS_AUTH_USERNAME_PASSWORD]))
        )
        self.assertEqual(writes, [bytes([SOCKS_VERSION, SOCKS_AUTH_NO_AUTH])])
        self.assertEqual(handler._client_identity()["auth_type"], "anonymous")

    def test_client_portal_keeps_inherited_socks_identity(self):
        handler = ProxyRequestHandler.__new__(ProxyRequestHandler)
        handler.client_address = ("192.168.1.23", 50000)
        handler.headers = {}
        inherited_identity = {
            "id": "user:phone",
            "ip": "192.168.1.23",
            "auth_type": "socks5",
            "username": "phone",
            "label": "",
        }
        handler.server = SimpleNamespace(
            client_identity=inherited_identity,
            router_config=SimpleNamespace(
                client_auth_settings=lambda: {
                    "enabled": True,
                    "allow_anonymous": False,
                    "credentials": [],
                }
            ),
            client_tracker=SimpleNamespace(reidentified=lambda *_args, **_kwargs: None),
        )

        handler._apply_optional_http_client_identity()

        self.assertEqual(handler._client_identity(), inherited_identity)

    def test_socks_client_portal_http_stream_serves_local_portal_with_identity(self):
        writes = []
        captured = []
        original_handler = proxy_server.ClientPortalSocksRequestHandler
        proxy_server.ClientPortalSocksRequestHandler = (
            lambda request, client_address, server: captured.append((request, client_address, server))
        )
        try:
            handler = Socks5RequestHandler.__new__(Socks5RequestHandler)
            handler.client_address = ("192.168.1.23", 50000)
            handler.request = SimpleNamespace(
                getsockname=lambda: ("192.168.1.44", 8900),
                sendall=lambda data: writes.append(data),
            )
            identity = {
                "id": "user:phone",
                "ip": "192.168.1.23",
                "auth_type": "socks5",
                "username": "phone",
                "label": "",
            }
            handler._proxy_client_identity = identity
            handler.server = SimpleNamespace(
                allowed_networks=[],
                timeout_seconds=30,
                verbose=False,
                debug=False,
                proxy_label="socks5",
                client_tracker=SimpleNamespace(),
                router_config=SimpleNamespace(),
                runtime=SimpleNamespace(),
                history_cache=SimpleNamespace(),
                server_address=("0.0.0.0", 8900),
            )

            handler._handle_client_portal_http_stream("proxy.router", 80)

            self.assertEqual(writes, [bytes([SOCKS_VERSION, 0, 0, 1, 192, 168, 1, 44, 34, 196])])
            self.assertEqual(len(captured), 1)
            self.assertIs(captured[0][2].client_identity, identity)
            self.assertEqual(captured[0][2].proxy_label, "socks5")
        finally:
            proxy_server.ClientPortalSocksRequestHandler = original_handler

    def test_loopback_detection_includes_ipv4_and_ipv6(self):
        self.assertTrue(is_loopback_client_ip("127.0.0.1"))
        self.assertTrue(is_loopback_client_ip("127.42.0.9"))
        self.assertTrue(is_loopback_client_ip("::1"))
        self.assertFalse(is_loopback_client_ip("192.168.1.23"))

    def _build_password_portal_handler(self, manager, *, body, identity=None, identity_by_client_ip=None):
        responses = []
        handler = ProxyRequestHandler.__new__(ProxyRequestHandler)
        handler.command = "POST"
        handler.client_address = ("192.168.1.23", 50000)
        handler.headers = {}
        if identity is not None:
            handler._proxy_client_identity = identity
        handler.server = SimpleNamespace(
            proxy_label="http",
            router_config=manager,
            runtime=SimpleNamespace(
                self_endpoints=SimpleNamespace(
                    resolve_target_kind=lambda _host, _port: "listener",
                    is_client_portal_host=lambda _host: False,
                ),
                dashboard_state=SimpleNamespace(
                    snapshot=lambda: {"identity_by_client_ip": dict(identity_by_client_ip or {})}
                ),
            ),
        )
        handler._apply_optional_http_client_identity = lambda: None
        handler._drop_blocked_client = lambda **_kwargs: False
        handler._read_request_body = lambda: json.dumps(body).encode("utf-8")
        handler._send_json_response = lambda payload, status=200: responses.append((status, payload))
        handler._send_body_response = lambda *_args, **_kwargs: responses.append(("body", _args, _kwargs))
        return handler, responses

    def test_client_portal_password_endpoint_changes_authenticated_user_password(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = RouterConfigManager(Path(temp_dir) / "router.json")
            original_snapshot_builder = proxy_server.build_client_portal_snapshot
            proxy_server.build_client_portal_snapshot = (
                lambda _server, client, **_kwargs: {"client": client, "can_change_password": True}
            )
            try:
                manager.update(
                    {
                        "client_auth": {
                            "enabled": True,
                            "credentials": [
                                {"username": "phone", "password": "old-secret"},
                            ],
                        }
                    }
                )
                handler, responses = self._build_password_portal_handler(
                    manager,
                    identity={"id": "user:phone", "username": "phone", "auth_type": "basic", "label": ""},
                    body={"current_password": "old-secret", "new_password": "new-secret"},
                )

                handled = handler._handle_client_portal_request("http", "proxy.router", 8900, "/api/client/password")

                self.assertTrue(handled)
                self.assertEqual(responses[0][0], 200)
                self.assertTrue(responses[0][1]["ok"])
                credential = manager.snapshot()["client_auth"]["credentials"][0]
                self.assertTrue(verify_client_auth_password("new-secret", credential["password_hash"]))
            finally:
                proxy_server.build_client_portal_snapshot = original_snapshot_builder
                manager.shutdown()

    def test_client_portal_password_endpoint_rejects_anonymous_client(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = RouterConfigManager(Path(temp_dir) / "router.json")
            try:
                handler, responses = self._build_password_portal_handler(
                    manager,
                    body={"current_password": "old-secret", "new_password": "new-secret"},
                )

                handled = handler._handle_client_portal_request("http", "proxy.router", 8900, "/api/client/password")

                self.assertTrue(handled)
                self.assertEqual(responses[0][0], 403)
            finally:
                manager.shutdown()

    def test_client_portal_password_endpoint_rejects_wrong_current_password(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = RouterConfigManager(Path(temp_dir) / "router.json")
            try:
                manager.update(
                    {
                        "client_auth": {
                            "credentials": [
                                {"username": "phone", "password": "old-secret"},
                            ],
                        }
                    }
                )
                handler, responses = self._build_password_portal_handler(
                    manager,
                    identity={"id": "user:phone", "username": "phone", "auth_type": "basic", "label": ""},
                    body={"current_password": "wrong-secret", "new_password": "new-secret"},
                )

                handled = handler._handle_client_portal_request("http", "proxy.router", 8900, "/api/client/password")

                self.assertTrue(handled)
                self.assertEqual(responses[0][0], 403)
                credential = manager.snapshot()["client_auth"]["credentials"][0]
                self.assertTrue(verify_client_auth_password("old-secret", credential["password_hash"]))
            finally:
                manager.shutdown()

    def test_client_portal_password_endpoint_uses_mapped_client_identity(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = RouterConfigManager(Path(temp_dir) / "router.json")
            original_snapshot_builder = proxy_server.build_client_portal_snapshot
            proxy_server.build_client_portal_snapshot = (
                lambda _server, client, **_kwargs: {"client": client, "can_change_password": True}
            )
            try:
                manager.update(
                    {
                        "client_auth": {
                            "credentials": [
                                {"username": "phone", "password": "old-secret"},
                            ],
                        }
                    }
                )
                handler, responses = self._build_password_portal_handler(
                    manager,
                    body={"current_password": "old-secret", "new_password": "new-secret"},
                    identity_by_client_ip={"192.168.1.23": "user:phone"},
                )

                handled = handler._handle_client_portal_request("http", "proxy.router", 8900, "/api/client/password")

                self.assertTrue(handled)
                self.assertEqual(responses[0][0], 200)
                credential = manager.snapshot()["client_auth"]["credentials"][0]
                self.assertTrue(verify_client_auth_password("new-secret", credential["password_hash"]))
            finally:
                proxy_server.build_client_portal_snapshot = original_snapshot_builder
                manager.shutdown()


if __name__ == "__main__":
    unittest.main()
