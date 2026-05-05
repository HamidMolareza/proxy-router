import tempfile
import unittest
from pathlib import Path

from proxy_router.traffic import HttpsInterceptionTrustManager
from proxy_router.util import default_router_config, normalize_router_config


class HttpsInterceptionAdaptiveTests(unittest.TestCase):
    def test_https_interception_trust_policy_defaults_to_adaptive(self):
        config = default_router_config()
        self.assertEqual(config["https_interception"]["trust_policy"], "adaptive")

        normalized = normalize_router_config({"https_interception": {"enabled": True}})
        self.assertEqual(normalized["https_interception"]["trust_policy"], "adaptive")

    def test_first_intercept_failure_adds_host_temporary_bypass(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = HttpsInterceptionTrustManager(Path(temp_dir) / "https-state.json")

            manager.record_failure(
                "10.0.0.2",
                "api.example.com",
                error="tlsv1 alert unknown ca",
                context="HTTPS interception TLS handshake",
                source="intercept",
            )

            host_bypass = manager.current_bypass("10.0.0.2", "api.example.com")
            unrelated_bypass = manager.current_bypass("10.0.0.2", "other.example.org")
            self.assertIsNotNone(host_bypass)
            self.assertEqual(host_bypass["scope"], "host")
            self.assertIsNone(unrelated_bypass)

    def test_trust_check_failure_adds_client_wide_temporary_bypass(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = HttpsInterceptionTrustManager(Path(temp_dir) / "https-state.json")

            manager.record_failure(
                "10.0.0.2",
                "proxy.router",
                error="tlsv1 alert unknown ca",
                context="HTTPS CA trust check",
                source="trust-check",
            )

            bypass = manager.current_bypass("10.0.0.2", "other.example.org")
            self.assertIsNotNone(bypass)
            self.assertEqual(bypass["scope"], "client")

    def test_repeated_intercept_failures_add_client_wide_temporary_bypass(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = HttpsInterceptionTrustManager(Path(temp_dir) / "https-state.json")

            for host in ("one.example.com", "two.example.net", "three.example.org"):
                manager.record_failure(
                    "10.0.0.2",
                    host,
                    error="tlsv1 alert unknown ca",
                    context="HTTPS interception TLS handshake",
                    source="intercept",
                )

            bypass = manager.current_bypass("10.0.0.2", "unrelated.example.test")
            self.assertIsNotNone(bypass)
            self.assertEqual(bypass["scope"], "client")

    def test_trust_check_success_clears_adaptive_bypasses_for_client(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = HttpsInterceptionTrustManager(Path(temp_dir) / "https-state.json")

            manager.record_failure(
                "10.0.0.2",
                "api.example.com",
                error="tlsv1 alert unknown ca",
                context="HTTPS interception TLS handshake",
                source="intercept",
            )
            manager.record_success("10.0.0.2", "proxy.router", source="trust-check")

            self.assertIsNone(manager.current_bypass("10.0.0.2", "api.example.com"))
            self.assertEqual(manager.snapshot()["adaptive_bypass_count"], 0)

    def test_failure_after_trust_adds_host_bypass_only(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = HttpsInterceptionTrustManager(Path(temp_dir) / "https-state.json")

            manager.record_success("10.0.0.2", "proxy.router", source="trust-check")
            manager.record_failure(
                "10.0.0.2",
                "pinned.example.net",
                error="tlsv1 alert unknown ca",
                context="HTTPS interception TLS handshake",
                source="intercept",
            )

            pinned_bypass = manager.current_bypass("10.0.0.2", "api.example.net")
            unrelated_bypass = manager.current_bypass("10.0.0.2", "api.example.org")
            self.assertIsNotNone(pinned_bypass)
            self.assertEqual(pinned_bypass["scope"], "host")
            self.assertIsNone(unrelated_bypass)


if __name__ == "__main__":
    unittest.main()
