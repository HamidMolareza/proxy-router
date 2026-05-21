import unittest

from proxy_router.proxy_server import (
    render_ca_install_html,
    render_ca_trust_check_html,
    render_client_portal_html,
    render_client_traffic_limit_html,
)


class PanelThemeTests(unittest.TestCase):
    def assert_has_theme_controls(self, document):
        self.assertIn("proxy-router-theme", document)
        self.assertIn('data-theme-choice-button="system"', document)
        self.assertIn('data-theme-choice-button="light"', document)
        self.assertIn('data-theme-choice-button="dark"', document)
        self.assertIn('html[data-theme="dark"]', document)
        self.assertIn("prefers-color-scheme: dark", document)

    def test_quota_page_includes_theme_controls(self):
        document = render_client_traffic_limit_html(
            client_ip="192.168.1.20",
            destination="example.com:443",
            evaluation={
                "allowed": False,
                "retry_after_seconds": 120,
                "limit": {"scope": "default"},
                "exceeded_windows": [
                    {
                        "label": "past hour",
                        "used_bytes": 2_000_000,
                        "limit_bytes": 1_000_000,
                    }
                ],
            },
        )

        self.assert_has_theme_controls(document)

    def test_ca_pages_include_theme_controls(self):
        snapshot = {
            "client": "192.168.1.20",
            "portal_url": "http://proxy.router/",
            "ca_install_url": "http://proxy.router/ca",
            "ca_check_url": "https://proxy.router/ca-check",
            "https_interception_status": {"ca_exists": True, "adaptive_bypass_count": 0},
        }

        self.assert_has_theme_controls(render_ca_install_html(snapshot))
        self.assert_has_theme_controls(render_ca_trust_check_html(snapshot, trusted=True))

    def test_client_portal_includes_theme_controls(self):
        document = render_client_portal_html(
            {
                "client": "192.168.1.20",
                "requested_at": "2026-05-20T12:00:00+00:00",
                "portal_url": "http://proxy.router/",
                "ca_install_url": "http://proxy.router/ca",
                "ca_certificate_url": "http://proxy.router/ca.crt",
                "ca_check_url": "https://proxy.router/ca-check",
                "client_live_url": "ws://127.0.0.1:8900/api/client/live",
                "totals": {},
                "history": {},
                "quota": {},
                "recent_requests": [],
                "recent_failures": [],
                "rule_suggestions": [],
            }
        )

        self.assert_has_theme_controls(document)
