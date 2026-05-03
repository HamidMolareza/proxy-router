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

    def test_history_period_totals_use_calendar_boundaries(self):
        records = [
            {
                "timestamp": "2026-05-02T01:00:00+00:00",
                "proxy_type": "http",
                "client": "user:phone",
                "destination": "today.example.com",
                "uploaded_bytes": 200,
                "downloaded_bytes": 300,
            },
            {
                "timestamp": "2026-04-28T12:00:00+00:00",
                "proxy_type": "http",
                "client": "user:phone",
                "destination": "week.example.com",
                "uploaded_bytes": 300,
                "downloaded_bytes": 400,
            },
            {
                "timestamp": "2026-04-10T12:00:00+00:00",
                "proxy_type": "http",
                "client": "user:phone",
                "destination": "month.example.com",
                "uploaded_bytes": 500,
                "downloaded_bytes": 600,
            },
            {
                "timestamp": "2026-01-15T12:00:00+00:00",
                "proxy_type": "http",
                "client": "user:phone",
                "destination": "year.example.com",
                "uploaded_bytes": 700,
                "downloaded_bytes": 800,
            },
            {
                "timestamp": "2025-12-31T23:00:00+00:00",
                "proxy_type": "http",
                "client": "user:phone",
                "destination": "old.example.com",
                "uploaded_bytes": 900,
                "downloaded_bytes": 1000,
            },
        ]

        history = summarize_history_records(
            records,
            invalid_lines=0,
            range_key="1h",
            timezone_name="UTC",
            now=datetime(2026, 5, 2, 15, 0, tzinfo=timezone.utc),
        )

        periods = {item["key"]: item["summary"] for item in history["period_totals"]}
        self.assertEqual(periods["day"]["total_bytes"], 500)
        self.assertEqual(periods["week"]["total_bytes"], 1200)
        self.assertEqual(periods["month"]["total_bytes"], 500)
        self.assertEqual(periods["year"]["total_bytes"], 3800)
        self.assertEqual(history["summary"]["total_bytes"], 0)

    def test_history_period_totals_include_per_client_breakdown(self):
        records = [
            {
                "timestamp": "2026-05-02T08:00:00+00:00",
                "proxy_type": "http",
                "client": "user:alpha",
                "destination": "alpha.example.com",
                "uploaded_bytes": 100,
                "downloaded_bytes": 200,
            },
            {
                "timestamp": "2026-05-01T08:00:00+00:00",
                "proxy_type": "socks5",
                "client": "user:beta",
                "destination": "beta.example.com",
                "uploaded_bytes": 1000,
                "downloaded_bytes": 2000,
            },
            {
                "timestamp": "2026-05-02T10:00:00+00:00",
                "proxy_type": "socks5",
                "client": "user:beta",
                "destination": "beta2.example.com",
                "uploaded_bytes": 500,
                "downloaded_bytes": 500,
            },
        ]

        history = summarize_history_records(
            records,
            invalid_lines=0,
            range_key="24h",
            timezone_name="UTC",
            now=datetime(2026, 5, 2, 18, 0, tzinfo=timezone.utc),
        )

        rows = {item["client"]: item for item in history["client_period_totals"]}
        self.assertEqual(list(rows.keys()), ["user:beta", "user:alpha"])
        self.assertEqual(rows["user:alpha"]["period_totals"]["day"]["total_bytes"], 300)
        self.assertEqual(rows["user:beta"]["period_totals"]["day"]["total_bytes"], 1000)
        self.assertEqual(rows["user:beta"]["period_totals"]["week"]["total_bytes"], 4000)
        self.assertEqual(rows["user:beta"]["proxy_types"], ["socks5"])

        filtered = summarize_history_records(
            records,
            invalid_lines=0,
            range_key="24h",
            client="user:beta",
            timezone_name="UTC",
            now=datetime(2026, 5, 2, 18, 0, tzinfo=timezone.utc),
        )
        self.assertEqual([item["client"] for item in filtered["client_period_totals"]], ["user:beta"])
        self.assertEqual(filtered["period_totals"][0]["summary"]["total_bytes"], 1000)


if __name__ == "__main__":
    unittest.main()
