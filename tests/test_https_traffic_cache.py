import json
import tempfile
import unittest
from pathlib import Path

from proxy_router.records import HttpsTrafficCache


class HttpsTrafficCacheTests(unittest.TestCase):
    def test_https_traffic_cache_filters_sorts_and_loads_detail(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            log_file = Path(temp_dir) / "https-traffic.log"
            records = [
                {
                    "id": "first",
                    "timestamp": "2026-05-01T10:00:00+00:00",
                    "client": "user:mobile",
                    "client_ip": "192.168.1.33",
                    "method": "GET",
                    "scheme": "https",
                    "host": "api.example.com",
                    "port": 443,
                    "path": "/v1/a",
                    "destination": "https://api.example.com/v1/a",
                    "status_code": 200,
                    "reason": "OK",
                    "duration_ms": 25,
                    "route_label": "direct",
                    "request": {"body_bytes": 0, "headers": [], "body_preview": {"text": ""}},
                    "response": {
                        "body_bytes": 120,
                        "headers": [{"name": "Content-Type", "value": "application/json"}],
                        "body_preview": {"text": "{}"},
                        "content_type": "application/json",
                    },
                    "total_bytes": 120,
                },
                {
                    "id": "second",
                    "timestamp": "2026-05-01T10:01:00+00:00",
                    "client": "192.168.1.40",
                    "method": "POST",
                    "scheme": "https",
                    "host": "auth.example.net",
                    "port": 443,
                    "path": "/login",
                    "destination": "https://auth.example.net/login",
                    "status_code": 403,
                    "reason": "Forbidden",
                    "duration_ms": 200,
                    "route_label": "proxy:auto-probe:socks5://127.0.0.1:9050",
                    "request": {"body_bytes": 10, "headers": [], "body_preview": {"text": "x"}},
                    "response": {"body_bytes": 0, "headers": [], "body_preview": {"text": ""}},
                    "total_bytes": 10,
                },
            ]
            log_file.write_text("\n".join(json.dumps(item) for item in records) + "\n", encoding="utf-8")

            cache = HttpsTrafficCache(log_file)
            payload = cache.query(client="user:mobile", sort="duration_ms", direction="desc")

            self.assertEqual(payload["total"], 1)
            self.assertEqual(payload["items"][0]["id"], "first")
            self.assertEqual(payload["available_clients"], ["192.168.1.40", "user:mobile"])
            self.assertEqual(cache.detail("second")["status_code"], 403)


if __name__ == "__main__":
    unittest.main()
