import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from proxy_router.config import RouterConfigManager
from proxy_router.dashboard_api import build_client_block_status_map, build_known_client_rows
from proxy_router.proxy_server import ProxyRequestHandler
from proxy_router.util import normalize_router_config


class ClientBlockTests(unittest.TestCase):
    def test_normalize_router_config_supports_client_blocks(self):
        config = normalize_router_config(
            {
                "client_blocks": [
                    {
                        "client": "phone",
                        "duration": "6h",
                        "note": "temporary hold",
                    }
                ]
            }
        )

        block = config["client_blocks"][0]
        self.assertEqual(block["client"], "user:phone")
        self.assertEqual(block["duration"], "6h")
        self.assertEqual(block["note"], "temporary hold")
        self.assertIsNotNone(block["expires_at"])

    def test_find_client_block_prefers_more_specific_target(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = RouterConfigManager(Path(temp_dir) / "router.json")
            try:
                manager.update(
                    {
                        "client_blocks": [
                            {"client": "192.168.1.0/24", "duration": "always", "note": "network"},
                            {"client": "192.168.1.23", "duration": "6h", "note": "device"},
                            {"client": "phone", "duration": "1h", "note": "user"},
                        ]
                    }
                )

                ip_block = manager.find_client_block("192.168.1.23")
                user_block = manager.find_client_block("user:phone")

                self.assertEqual(ip_block["target"], "192.168.1.23")
                self.assertEqual(ip_block["duration"], "6h")
                self.assertEqual(user_block["target"], "user:phone")
                self.assertEqual(user_block["duration"], "1h")
            finally:
                manager.shutdown()

    def test_build_known_clients_includes_credentials_seen_clients_and_blocks(self):
        snapshot = {
            "totals_by_client": [
                {
                    "client": "user:phone",
                    "count": 3,
                    "active_connections": 1,
                    "uploaded_bytes": 100,
                    "downloaded_bytes": 200,
                    "total_bytes": 300,
                    "proxy_types": ["http"],
                    "last_seen_at": "2026-05-02T10:00:00+03:30",
                }
            ],
            "active_by_client": {"user:phone": 1},
            "identity_by_client_ip": {"192.168.1.20": "user:phone"},
            "recent_requests": [
                {
                    "client": "user:phone",
                    "client_ip": "192.168.1.20",
                    "client_auth_label": "Android phone",
                    "client_auth_username": "phone",
                    "proxy_type": "http",
                    "timestamp": "2026-05-02T10:00:00+03:30",
                }
            ],
            "recent_failures": [],
        }
        router_config_snapshot = normalize_router_config(
            {
                "client_auth": {
                    "credentials": [
                        {"username": "phone", "password": "secret", "label": "Android phone"},
                        {"username": "tablet", "password": "secret", "label": "Tablet"},
                    ]
                },
                "client_blocks": [
                    {"client": "192.168.1.50", "duration": "always"},
                ],
            }
        )

        rows = build_known_client_rows(snapshot, router_config_snapshot)
        clients = {row["client"]: row for row in rows}

        self.assertIn("user:phone", clients)
        self.assertIn("user:tablet", clients)
        self.assertIn("192.168.1.50", clients)
        self.assertEqual(clients["user:phone"]["label"], "Android phone")
        self.assertEqual(clients["user:phone"]["source_ips"], ["192.168.1.20"])
        self.assertEqual(clients["user:phone"]["active_connections"], 1)

    def test_build_known_clients_excludes_historical_users_not_in_current_credentials(self):
        snapshot = {
            "totals_by_client": [
                {
                    "client": "user:mobile",
                    "count": 5,
                    "active_connections": 0,
                    "uploaded_bytes": 100,
                    "downloaded_bytes": 100,
                    "total_bytes": 200,
                    "proxy_types": ["http"],
                    "last_seen_at": "2026-05-02T09:00:00+03:30",
                },
                {
                    "client": "192.168.1.50",
                    "count": 2,
                    "active_connections": 0,
                    "uploaded_bytes": 50,
                    "downloaded_bytes": 50,
                    "total_bytes": 100,
                    "proxy_types": ["http"],
                    "last_seen_at": "2026-05-02T08:00:00+03:30",
                },
            ],
            "active_by_client": {},
            "identity_by_client_ip": {"192.168.1.20": "user:mobile"},
            "recent_requests": [
                {
                    "client": "user:m",
                    "client_ip": "192.168.1.21",
                    "client_auth_label": "Old device",
                    "client_auth_username": "m",
                    "proxy_type": "http",
                    "timestamp": "2026-05-02T10:00:00+03:30",
                }
            ],
            "recent_failures": [],
        }
        router_config_snapshot = normalize_router_config(
            {
                "client_auth": {
                    "credentials": [
                        {"username": "phone", "password": "secret", "label": "Android phone"},
                    ]
                }
            }
        )

        rows = build_known_client_rows(snapshot, router_config_snapshot)
        clients = {row["client"] for row in rows}

        self.assertIn("user:phone", clients)
        self.assertIn("192.168.1.50", clients)
        self.assertNotIn("user:mobile", clients)
        self.assertNotIn("user:m", clients)

    def test_build_client_block_status_map_resolves_effective_block(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = RouterConfigManager(Path(temp_dir) / "router.json")
            try:
                manager.update(
                    {
                        "client_blocks": [
                            {"client": "192.168.1.0/24", "duration": "always"},
                            {"client": "phone", "duration": "6h"},
                        ]
                    }
                )

                status_map = build_client_block_status_map(
                    [
                        {"client": "192.168.1.23"},
                        {"client": "user:phone"},
                        {"client": "192.168.2.10"},
                    ],
                    manager,
                )

                self.assertEqual(status_map["192.168.1.23"]["target"], "192.168.1.0/24")
                self.assertEqual(status_map["user:phone"]["target"], "user:phone")
                self.assertNotIn("192.168.2.10", status_map)
            finally:
                manager.shutdown()

    def test_http_handler_silently_drops_blocked_client(self):
        recorded_failures = []
        closed = []
        handler = ProxyRequestHandler.__new__(ProxyRequestHandler)
        handler.client_address = ("192.168.1.23", 50000)
        handler.server = SimpleNamespace(
            proxy_label="http",
            router_config=SimpleNamespace(find_client_block=lambda client_id: {"target": client_id}),
            runtime=SimpleNamespace(record_failure=lambda **payload: recorded_failures.append(payload)),
        )
        handler.connection = SimpleNamespace(
            shutdown=lambda *_args, **_kwargs: closed.append("shutdown"),
            close=lambda: closed.append("close"),
        )
        handler.close_connection = False
        handler._client_identity = lambda: {
            "id": "192.168.1.23",
            "auth_type": "anonymous",
            "username": None,
            "label": "",
        }
        handler._client_id = lambda: "192.168.1.23"
        handler._client_label = lambda: "192.168.1.23:50000"

        blocked = handler._drop_blocked_client(
            method="GET",
            destination="http://example.com/",
            host="example.com",
            port=80,
            client_id="192.168.1.23",
        )

        self.assertTrue(blocked)
        self.assertTrue(handler.close_connection)
        self.assertEqual(closed, ["shutdown", "close"])
        self.assertEqual(recorded_failures[0]["route_label"], "reject:client-access-block")


if __name__ == "__main__":
    unittest.main()
