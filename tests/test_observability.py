import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from proxy_router.runtime import DashboardState, UsageLogger
from proxy_router.traffic import TrafficQuotaManager
from proxy_router.util import summarize_history_records, summarize_usage_records


class ObservabilityTests(unittest.TestCase):
    def test_dashboard_state_records_request_performance_metrics(self):
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
            route_label="proxy:socks5://127.0.0.1:9050",
            duration_ms=2000,
            upstream_setup_ms=150,
            relay_ms=1850,
            upstream_retry_count=1,
            upstream_retry_delay_ms=1000,
            upstream_proxy_id="main",
            upstream_proxy_name="Main",
            upstream_proxy_access_mode="public",
        )

        snapshot = state.snapshot()
        latest = snapshot["latest_request"]

        self.assertEqual(latest["duration_ms"], 2000)
        self.assertEqual(latest["upstream_setup_ms"], 150)
        self.assertEqual(latest["relay_ms"], 1850)
        self.assertEqual(latest["upstream_retry_count"], 1)
        self.assertEqual(latest["upstream_retry_delay_ms"], 1000)
        self.assertEqual(latest["throughput_bps"], 150)
        self.assertEqual(snapshot["overall"]["duration_sample_count"], 1)
        self.assertEqual(snapshot["overall"]["duration_ms_avg"], 2000)
        self.assertEqual(snapshot["overall"]["upstream_setup_ms_avg"], 150)
        self.assertEqual(snapshot["overall"]["throughput_bps"], 150)
        self.assertEqual(snapshot["totals_by_route"]["proxy"]["duration_ms_max"], 2000)
        self.assertEqual(snapshot["totals_by_upstream_proxy"]["main"]["total_bytes"], 300)

    def test_history_summaries_ignore_missing_timing_fields_for_old_logs(self):
        records = [
            {
                "timestamp": "2026-05-01T03:07:00+00:00",
                "proxy_type": "http",
                "client": "192.168.1.10",
                "destination": "old.example.com",
                "uploaded_bytes": 100,
                "downloaded_bytes": 200,
            },
            {
                "timestamp": "2026-05-01T03:08:00+00:00",
                "proxy_type": "http",
                "client": "192.168.1.10",
                "destination": "timed.example.com",
                "uploaded_bytes": 200,
                "downloaded_bytes": 300,
                "duration_ms": 1000,
                "upstream_setup_ms": 125,
                    "relay_ms": 875,
                    "upstream_proxy_id": "main",
            },
        ]

        history = summarize_history_records(
            records,
            invalid_lines=0,
            range_key="1h",
            timezone_name="UTC",
            now=datetime(2026, 5, 1, 3, 10, tzinfo=timezone.utc),
        )
        usage = summarize_usage_records(records)

        self.assertEqual(history["summary"]["count"], 2)
        self.assertEqual(history["summary"]["total_bytes"], 800)
        self.assertEqual(history["summary"]["duration_sample_count"], 1)
        self.assertEqual(history["summary"]["duration_sample_bytes"], 500)
        self.assertEqual(history["summary"]["duration_ms_avg"], 1000)
        self.assertEqual(history["summary"]["upstream_setup_ms_avg"], 125)
        self.assertEqual(history["summary"]["throughput_bps"], 500)
        self.assertEqual(history["available_upstream_proxies"], ["main"])
        filtered_history = summarize_history_records(
            records,
            invalid_lines=0,
            range_key="1h",
            upstream_proxy_id="main",
            timezone_name="UTC",
            now=datetime(2026, 5, 1, 3, 10, tzinfo=timezone.utc),
        )
        self.assertEqual(filtered_history["summary"]["count"], 1)
        self.assertEqual(usage["duration_sample_count"], 1)
        self.assertEqual(usage["throughput_bps"], 500)

    def test_usage_logger_writes_optional_performance_fields(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_file = Path(temp_dir) / "usage.log"
            logger = UsageLogger(log_file)
            try:
                logger.record(
                    proxy_label="socks5",
                    kind="connect",
                    client="192.168.1.10",
                    destination="example.com:443",
                    uploaded_bytes=1000,
                    downloaded_bytes=3000,
                    timestamp="2026-05-01T03:08:00+00:00",
                    method="CONNECT",
                    duration_ms=2000,
                    upstream_setup_ms=100,
                    relay_ms=1900,
                    upstream_retry_count=2,
                    upstream_retry_delay_ms=3000,
                    upstream_proxy_id="fallback",
                    upstream_proxy_name="Fallback",
                    upstream_proxy_access_mode="authenticated",
                    proxy_failover_count=1,
                )
            finally:
                logger.close()

            record = json.loads(log_file.read_text(encoding="utf-8").strip())
            self.assertEqual(record["duration_ms"], 2000)
            self.assertEqual(record["upstream_setup_ms"], 100)
            self.assertEqual(record["relay_ms"], 1900)
            self.assertEqual(record["upstream_retry_count"], 2)
            self.assertEqual(record["upstream_retry_delay_ms"], 3000)
            self.assertEqual(record["throughput_bps"], 2000)
            self.assertEqual(record["upstream_proxy_id"], "fallback")
            self.assertEqual(record["proxy_failover_count"], 1)

    def test_usage_logger_clear_waits_for_pending_async_writes(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_file = Path(temp_dir) / "usage.log"
            logger = UsageLogger(log_file)
            try:
                for index in range(25):
                    logger.record(
                        proxy_label="http",
                        kind="http",
                        client="127.0.0.1",
                        destination=f"example-{index}.com",
                        uploaded_bytes=10,
                        downloaded_bytes=20,
                        timestamp="2026-05-01T03:08:00+00:00",
                    )
                logger.clear_data()
            finally:
                logger.close()

            self.assertEqual(log_file.read_text(encoding="utf-8"), "")

    def test_proxy_quota_manager_tracks_global_and_per_client_proxy_usage(self):
        manager = TrafficQuotaManager()
        proxy = {
            "id": "main",
            "traffic_limit": {
                "enabled": True,
                "max_past_hour_mb": 1,
            },
            "per_client_traffic_limit": {
                "enabled": True,
                "max_past_hour_mb": 1,
            },
        }

        manager.record_usage(
            client="user:phone",
            upstream_proxy_id="main",
            total_bytes=1_100_000,
        )

        evaluation = manager.evaluate_proxy(proxy, client="user:phone")
        other_user = manager.evaluate_proxy(proxy, client="user:tablet")

        self.assertFalse(evaluation["allowed"])
        self.assertEqual(evaluation["exceeded_windows"][0]["key"], "1h")
        self.assertEqual(evaluation["client_exceeded_windows"][0]["key"], "1h")
        self.assertFalse(other_user["allowed"])
        self.assertEqual(other_user["client_exceeded_windows"], [])


if __name__ == "__main__":
    unittest.main()
