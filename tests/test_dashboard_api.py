import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from proxy_router.config import RouterConfigManager
from proxy_router.dashboard_api import build_dashboard_snapshot
from proxy_router.runtime import DashboardState


class DashboardApiScopeTests(unittest.TestCase):
    def _server(self, temp_dir):
        router_config = RouterConfigManager(Path(temp_dir) / "router.json")
        router_config.update(
            {
                "client_auth": {
                    "credentials": [
                        {
                            "username": "phone",
                            "password": "secret",
                            "label": "Phone",
                        }
                    ]
                },
                "client_blocks": [
                    {
                        "client": "phone",
                        "duration": "always",
                        "note": "test block",
                    }
                ],
                "proxies": [
                    {
                        "id": "main",
                        "name": "Main",
                        "type": "http",
                        "host": "127.0.0.1",
                        "port": 8901,
                    }
                ],
            }
        )
        dashboard_state = DashboardState()
        dashboard_state.record_request(
            proxy_label="http",
            kind="http",
            client="user:phone",
            destination="https://api.example.com/v1/items",
            uploaded_bytes=10,
            downloaded_bytes=90,
            method="GET",
            timestamp="2026-05-01T10:00:00+00:00",
            route_label="proxy:main",
            upstream_proxy_id="main",
            client_ip="192.168.1.20",
            client_auth_type="userpass",
            client_auth_username="phone",
            client_auth_label="Phone",
        )
        dashboard_state.record_failure(
            proxy_label="connect",
            client="user:phone",
            method="CONNECT",
            destination="broken.example.com:443",
            host="broken.example.com",
            port=443,
            error="upstream failed",
            context="connect",
            timestamp="2026-05-01T10:01:00+00:00",
            route_label="proxy:main",
            upstream_proxy_id="main",
        )

        quota_manager = SimpleNamespace(
            snapshot_for_clients=lambda clients, _router_config: {
                client: {"client": client, "allowed": True, "usage": {}, "limit": None}
                for client in clients
            },
            proxy_snapshot=lambda proxies, clients: {
                proxy["id"]: {
                    "proxy_id": proxy["id"],
                    "allowed": True,
                    "usage": {},
                    "clients": {},
                }
                for proxy in proxies
            },
        )
        runtime = SimpleNamespace(
            dashboard_state=dashboard_state,
            upstream_status=SimpleNamespace(snapshot=lambda: {"main": {"ok": True}}),
            https_interception_status=lambda settings: {"enabled": bool(settings.get("enabled", False))},
            auto_proxy_failure_manager=None,
            traffic_quota_manager=quota_manager,
            rule_suggestion_manager=SimpleNamespace(
                snapshot=lambda include_current_conflicts=False: [
                    {
                        "id": "suggestion-1",
                        "status": "pending",
                        "include_current_conflicts": include_current_conflicts,
                    }
                ]
            ),
        )
        return SimpleNamespace(router_config=router_config, runtime=runtime), router_config

    def test_dashboard_scopes_keep_heavy_sections_out_of_overview(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            server, router_config = self._server(temp_dir)
            try:
                overview = build_dashboard_snapshot(server)
                failures = build_dashboard_snapshot(server, scope="failures")
                users = build_dashboard_snapshot(server, scope="users")
                quotas = build_dashboard_snapshot(server, scope="quotas")
                proxies = build_dashboard_snapshot(server, scope="proxies")
                routing = build_dashboard_snapshot(server, scope="routing")
                https_status = build_dashboard_snapshot(server, scope="https-status")
                full = build_dashboard_snapshot(server, scope="full")

                self.assertIn("recent_requests", overview)
                self.assertIn("router_runtime", overview)
                self.assertNotIn("recent_failures", overview)
                self.assertNotIn("failure_summary", overview)
                self.assertNotIn("known_clients", overview)
                self.assertNotIn("client_quota_status", overview)
                self.assertNotIn("proxy_quota_status", overview)
                self.assertNotIn("rule_suggestions", overview)

                self.assertEqual(len(failures["recent_failures"]), 1)
                self.assertIn("failure_summary", failures)
                self.assertEqual(users["known_clients"][0]["client"], "user:phone")
                self.assertIn("user:phone", users["client_block_status"])
                self.assertIn("user:phone", quotas["client_quota_status"])
                self.assertIn("main", proxies["proxy_quota_status"])
                self.assertTrue(routing["rule_suggestions"][0]["include_current_conflicts"])
                self.assertIn("https_interception_status", https_status["router_runtime"])
                self.assertIn("recent_failures", full)
                self.assertIn("known_clients", full)
                self.assertIn("client_quota_status", full)
                self.assertIn("proxy_quota_status", full)
                self.assertIn("rule_suggestions", full)
            finally:
                router_config.shutdown()


if __name__ == "__main__":
    unittest.main()
