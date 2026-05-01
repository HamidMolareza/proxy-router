import unittest
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from proxy_router.util import bucket_datetime, summarize_history_records


class HistoryTimezoneTests(unittest.TestCase):
    def test_bucket_datetime_uses_requested_timezone_wall_clock(self):
        timestamp = datetime(2026, 5, 1, 3, 7, tzinfo=timezone.utc)
        tehran = ZoneInfo("Asia/Tehran")

        five_minute_bucket = bucket_datetime(timestamp, 300, tehran)
        hourly_bucket = bucket_datetime(timestamp, 3600, tehran)

        self.assertEqual(five_minute_bucket.strftime("%H:%M"), "06:35")
        self.assertEqual(hourly_bucket.strftime("%H:%M"), "06:00")

    def test_history_summary_labels_use_requested_timezone(self):
        records = [
            {
                "timestamp": "2026-05-01T03:07:00+00:00",
                "proxy_type": "http",
                "client": "127.0.0.1",
                "destination": "example.com:443",
                "uploaded_bytes": 100,
                "downloaded_bytes": 200,
            }
        ]

        history = summarize_history_records(
            records,
            invalid_lines=0,
            range_key="1h",
            timezone_name="Asia/Tehran",
            now=datetime(2026, 5, 1, 3, 10, tzinfo=timezone.utc),
        )

        labels = [item["label"] for item in history["series"]]
        self.assertIn("06:35", labels)
        self.assertNotIn("03:05", labels)

    def test_history_summary_can_filter_by_client(self):
        records = [
            {
                "timestamp": "2026-05-01T03:07:00+00:00",
                "proxy_type": "http",
                "client": "user:phone",
                "destination": "api.example.com",
                "uploaded_bytes": 100,
                "downloaded_bytes": 200,
            },
            {
                "timestamp": "2026-05-01T03:08:00+00:00",
                "proxy_type": "socks5",
                "client": "192.168.1.50",
                "destination": "other.example.com",
                "uploaded_bytes": 300,
                "downloaded_bytes": 400,
            },
        ]

        history = summarize_history_records(
            records,
            invalid_lines=0,
            range_key="1h",
            client="user:phone",
            timezone_name="UTC",
            now=datetime(2026, 5, 1, 3, 10, tzinfo=timezone.utc),
        )

        self.assertEqual(history["client"], "user:phone")
        self.assertEqual(history["summary"]["count"], 1)
        self.assertEqual(history["summary"]["total_bytes"], 300)
        self.assertEqual(history["top_destinations"][0]["destination"], "api.example.com")
        self.assertEqual(history["available_clients"], ["192.168.1.50", "user:phone"])


if __name__ == "__main__":
    unittest.main()
