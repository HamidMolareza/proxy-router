import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from proxy_router.records import UsageHistoryCache


class UsageHistoryCacheRequestQueryTests(unittest.TestCase):
    def test_query_records_filters_searches_sorts_and_pages(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_file = Path(temp_dir) / "usage.log"
            records = [
                {
                    "timestamp": "2026-05-01T10:00:00+00:00",
                    "client": "user:mobile",
                    "client_ip": "192.168.1.33",
                    "proxy_type": "http",
                    "method": "GET",
                    "destination": "https://api.example.com/v1/items",
                    "host": "api.example.com",
                    "path": "/v1/items",
                    "route_label": "direct",
                    "profile_id": "default",
                    "status_code": 200,
                    "uploaded_bytes": 10,
                    "downloaded_bytes": 90,
                    "total_bytes": 100,
                    "duration_ms": 25,
                },
                {
                    "timestamp": "2026-05-01T10:01:00+00:00",
                    "client": "192.168.1.40",
                    "client_ip": "192.168.1.40",
                    "proxy_type": "connect",
                    "method": "CONNECT",
                    "destination": "auth.example.net:443",
                    "route_label": "proxy:main",
                    "upstream_proxy_id": "main",
                    "upstream_proxy_name": "Main",
                    "status_code": 502,
                    "uploaded_bytes": 30,
                    "downloaded_bytes": 70,
                    "total_bytes": 100,
                    "duration_ms": 200,
                },
                {
                    "timestamp": "2026-05-01T10:02:00+00:00",
                    "client": "user:mobile",
                    "client_ip": "192.168.1.33",
                    "proxy_type": "http",
                    "method": "POST",
                    "destination": "https://api.example.com/v1/login",
                    "host": "api.example.com",
                    "path": "/v1/login",
                    "route_label": "proxy:main",
                    "upstream_proxy_id": "main",
                    "status_code": 403,
                    "uploaded_bytes": 20,
                    "downloaded_bytes": 30,
                    "total_bytes": 50,
                    "duration_ms": 50,
                },
            ]
            log_file.write_text("\n".join(json.dumps(item) for item in records) + "\n", encoding="utf-8")

            cache = UsageHistoryCache(log_file)
            payload = cache.query_records(
                client="user:mobile",
                host="example.com",
                search="login",
                sort="duration_ms",
                direction="desc",
                page=1,
                page_size=1,
            )

            self.assertEqual(payload["total"], 1)
            self.assertEqual(payload["items"][0]["path"], "/v1/login")
            self.assertEqual(payload["items"][0]["status_code"], 403)
            self.assertEqual(payload["items"][0]["upstream_proxy_id"], "main")
            self.assertEqual(payload["available_clients"], ["192.168.1.40", "user:mobile"])
            self.assertEqual(payload["available_upstream_proxy_ids"], ["main"])

    def test_query_records_caps_max_results_before_paging(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_file = Path(temp_dir) / "usage.log"
            records = [
                {
                    "timestamp": f"2026-05-01T10:0{index}:00+00:00",
                    "client": "user:mobile",
                    "proxy_type": "http",
                    "destination": f"api{index}.example.com",
                    "total_bytes": index,
                }
                for index in range(4)
            ]
            log_file.write_text("\n".join(json.dumps(item) for item in records) + "\n", encoding="utf-8")

            cache = UsageHistoryCache(log_file)
            payload = cache.query_records(max_results=2, page=2, page_size=2, sort="timestamp", direction="desc")

            self.assertEqual(payload["total"], 4)
            self.assertTrue(payload["truncated"])
            self.assertEqual(payload["items"], [])

    def test_build_history_payload_reuses_cached_summary_until_cache_window_expires(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_file = Path(temp_dir) / "usage.log"
            first_record = {
                "timestamp": "2026-05-01T10:00:00+00:00",
                "client": "user:mobile",
                "proxy_type": "http",
                "destination": "https://api.example.com/v1/items",
                "total_bytes": 100,
            }
            second_record = {
                "timestamp": "2026-05-01T10:01:00+00:00",
                "client": "user:mobile",
                "proxy_type": "http",
                "destination": "https://api.example.com/v1/login",
                "total_bytes": 50,
            }
            log_file.write_text(json.dumps(first_record) + "\n", encoding="utf-8")

            call_record_counts = []

            def fake_summary(records, **kwargs):
                call_record_counts.append(len(records))
                return {
                    "summary": {"count": len(records)},
                    "invalid_lines": kwargs["invalid_lines"],
                    "range": kwargs["range_key"],
                }

            cache = UsageHistoryCache(log_file)
            with patch("proxy_router.records.summarize_history_records", side_effect=fake_summary):
                with patch("proxy_router.records.time.time", return_value=1000):
                    first_payload = cache.build_history_payload(range_key="24h", timezone_name="UTC")
                    first_payload["summary"]["count"] = 999
                    second_payload = cache.build_history_payload(range_key="24h", timezone_name="UTC")
                    with log_file.open("a", encoding="utf-8") as stream:
                        stream.write(json.dumps(second_record) + "\n")
                    appended_payload = cache.build_history_payload(range_key="24h", timezone_name="UTC")
                with patch("proxy_router.records.time.time", return_value=1070):
                    expired_payload = cache.build_history_payload(range_key="24h", timezone_name="UTC")
                    deadline = time.monotonic() + 2
                    refreshed_payload = None
                    while time.monotonic() < deadline:
                        refreshed_payload = cache.build_history_payload(range_key="24h", timezone_name="UTC")
                        if refreshed_payload["summary"]["count"] == 2:
                            break
                        time.sleep(0.01)

            self.assertEqual(call_record_counts, [1, 2])
            self.assertEqual(second_payload["summary"]["count"], 1)
            self.assertEqual(appended_payload["summary"]["count"], 1)
            self.assertEqual(expired_payload["summary"]["count"], 1)
            self.assertEqual(refreshed_payload["summary"]["count"], 2)

    def test_build_history_payload_invalidates_cached_summary_on_log_rotation(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_file = Path(temp_dir) / "usage.log"
            first_record = {
                "timestamp": "2026-05-01T10:00:00+00:00",
                "client": "user:mobile",
                "proxy_type": "http",
                "destination": "https://api.example.com/v1/items",
                "total_bytes": 100,
            }
            rotated_record = {
                "timestamp": "2026-05-01T10:01:00+00:00",
                "client": "192.168.1.30",
                "proxy_type": "connect",
                "destination": "rotated.example.com:443",
                "total_bytes": 50,
            }
            log_file.write_text(json.dumps(first_record) + "\n", encoding="utf-8")

            call_record_counts = []

            def fake_summary(records, **kwargs):
                call_record_counts.append(len(records))
                return {
                    "summary": {"first_client": records[0]["client"] if records else ""},
                    "invalid_lines": kwargs["invalid_lines"],
                    "range": kwargs["range_key"],
                }

            cache = UsageHistoryCache(log_file)
            with (
                patch("proxy_router.records.time.time", return_value=1000),
                patch("proxy_router.records.summarize_history_records", side_effect=fake_summary),
            ):
                first_payload = cache.build_history_payload(range_key="24h", timezone_name="UTC")
                log_file.unlink()
                log_file.write_text(json.dumps(rotated_record) + "\n", encoding="utf-8")
                second_payload = cache.build_history_payload(range_key="24h", timezone_name="UTC")

            self.assertEqual(call_record_counts, [1, 1])
            self.assertEqual(first_payload["summary"]["first_client"], "user:mobile")
            self.assertEqual(second_payload["summary"]["first_client"], "192.168.1.30")


if __name__ == "__main__":
    unittest.main()
