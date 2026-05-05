import json
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from proxy_router.runtime import AppRuntime


def _write_jsonl(path: Path, records):
    path.write_text(
        "".join(
            item if isinstance(item, str) else f"{json.dumps(item, sort_keys=True)}\n"
            for item in records
        ),
        encoding="utf-8",
    )


def _load_jsonl(path: Path):
    records = []
    invalid_lines = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            invalid_lines += 1
    return records, invalid_lines


class ClientHistoryClearTests(unittest.TestCase):
    def test_clear_client_history_rewrites_logs_and_rehydrates_runtime_state(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            data_dir = Path(temp_dir)
            usage_log = data_dir / "usage.log"
            failure_log = data_dir / "failures.log"
            https_log = data_dir / "https-traffic.log"
            current_timestamp = datetime.now().astimezone().isoformat(timespec="seconds")

            phone_usage = {
                "timestamp": current_timestamp,
                "proxy_type": "socks5",
                "kind": "http",
                "client": "user:phone",
                "client_ip": "192.168.1.23",
                "destination": "https://phone.example/",
                "uploaded_bytes": 10,
                "downloaded_bytes": 90,
                "total_bytes": 100,
            }
            tablet_usage = {
                "timestamp": current_timestamp,
                "proxy_type": "socks5",
                "kind": "http",
                "client": "user:tablet",
                "client_ip": "192.168.1.24",
                "destination": "https://tablet.example/",
                "uploaded_bytes": 20,
                "downloaded_bytes": 180,
                "total_bytes": 200,
            }
            phone_failure = {
                "timestamp": current_timestamp,
                "proxy_type": "socks5",
                "client": "user:phone",
                "client_ip": "192.168.1.23",
                "method": "CONNECT",
                "destination": "phone.example:443",
                "host": "phone.example",
                "port": 443,
                "error": "upstream failed",
                "context": "proxy",
            }
            tablet_failure = {
                "timestamp": current_timestamp,
                "proxy_type": "socks5",
                "client": "user:tablet",
                "client_ip": "192.168.1.24",
                "method": "CONNECT",
                "destination": "tablet.example:443",
                "host": "tablet.example",
                "port": 443,
                "error": "upstream failed",
                "context": "proxy",
            }
            phone_https = {
                "id": "phone",
                "timestamp": current_timestamp,
                "client": "user:phone",
                "client_ip": "192.168.1.23",
                "method": "GET",
                "scheme": "https",
                "host": "phone.example",
                "port": 443,
                "path": "/",
                "destination": "https://phone.example/",
                "status_code": 200,
                "request": {"body_bytes": 0, "headers": [], "body_preview": {"text": ""}},
                "response": {"body_bytes": 1, "headers": [], "body_preview": {"text": ""}},
                "total_bytes": 1,
            }
            tablet_https = {
                "id": "tablet",
                "timestamp": current_timestamp,
                "client": "user:tablet",
                "client_ip": "192.168.1.24",
                "method": "GET",
                "scheme": "https",
                "host": "tablet.example",
                "port": 443,
                "path": "/",
                "destination": "https://tablet.example/",
                "status_code": 200,
                "request": {"body_bytes": 0, "headers": [], "body_preview": {"text": ""}},
                "response": {"body_bytes": 1, "headers": [], "body_preview": {"text": ""}},
                "total_bytes": 1,
            }

            _write_jsonl(usage_log, [phone_usage, tablet_usage, "not json\n"])
            _write_jsonl(failure_log, [phone_failure, tablet_failure])
            _write_jsonl(https_log, [phone_https, tablet_https])

            runtime = AppRuntime()
            runtime.configure_usage_log(usage_log)
            runtime.configure_failure_log(failure_log)
            runtime.configure_https_traffic_log(https_log)
            runtime.configure_traffic_quota_manager(usage_log)
            runtime.rehydrate_dashboard_state()
            try:
                result = runtime.clear_client_history(
                    client_ids={"user:phone"},
                    client_ips={"192.168.1.23"},
                )

                self.assertEqual(result, {"usage": 1, "failures": 1, "https_traffic": 1, "total": 3})

                usage_records, invalid_lines = _load_jsonl(usage_log)
                self.assertEqual(invalid_lines, 1)
                self.assertEqual([item["client"] for item in usage_records], ["user:tablet"])
                self.assertEqual(
                    [item["client"] for item in _load_jsonl(failure_log)[0]],
                    ["user:tablet"],
                )
                self.assertEqual(
                    [item["client"] for item in _load_jsonl(https_log)[0]],
                    ["user:tablet"],
                )

                self.assertEqual(
                    runtime.traffic_quota_manager.usage_for_client("user:phone")["1h"]["total_bytes"],
                    0,
                )
                self.assertEqual(
                    runtime.traffic_quota_manager.usage_for_client("user:tablet")["1h"]["total_bytes"],
                    200,
                )

                snapshot = runtime.dashboard_state.snapshot()
                clients = {item["client"]: item for item in snapshot["totals_by_client"]}
                self.assertNotIn("user:phone", clients)
                self.assertEqual(clients["user:tablet"]["total_bytes"], 200)
                self.assertEqual([item["client"] for item in snapshot["recent_failures"]], ["user:tablet"])
            finally:
                runtime.close()


if __name__ == "__main__":
    unittest.main()
