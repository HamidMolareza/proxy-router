import unittest

from proxy_router.runtime import DashboardState


class ClientIdentityDashboardTests(unittest.TestCase):
    def test_active_authenticated_client_moves_from_ip_to_user_identity(self):
        state = DashboardState()

        state.client_connected("http", "192.168.1.20")
        state.client_reidentified("192.168.1.20", "user:mobile")

        snapshot = state.snapshot()

        self.assertEqual(snapshot["active_by_client"], {"user:mobile": 1})
        self.assertEqual(len(snapshot["totals_by_client"]), 1)
        self.assertEqual(snapshot["totals_by_client"][0]["client"], "user:mobile")
        self.assertEqual(snapshot["totals_by_client"][0]["active_connections"], 1)

    def test_authenticated_usage_maps_source_ip_to_user_identity(self):
        state = DashboardState()

        state.record_request(
            proxy_label="http",
            kind="http",
            client="user:mobile",
            client_ip="192.168.1.20",
            destination="https://example.com/",
            uploaded_bytes=100,
            downloaded_bytes=200,
            method="GET",
            timestamp="2026-05-01T07:00:00+03:30",
            client_auth_type="basic",
            client_auth_username="mobile",
        )

        snapshot = state.snapshot()

        self.assertEqual(snapshot["identity_by_client_ip"], {"192.168.1.20": "user:mobile"})
        self.assertEqual(len(snapshot["totals_by_client"]), 1)
        self.assertEqual(snapshot["totals_by_client"][0]["client"], "user:mobile")
        self.assertEqual(snapshot["totals_by_client"][0]["total_bytes"], 300)


if __name__ == "__main__":
    unittest.main()
