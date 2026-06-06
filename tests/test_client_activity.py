import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from proxy_router.records import ClientActivityCache, ClientBlockHistoryStore


class ClientActivityTests(unittest.TestCase):
    def _write_jsonl(self, path, records):
        path.write_text("".join(json.dumps(item) + "\n" for item in records), encoding="utf-8")

    def test_block_history_store_deduplicates_snapshots(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "blocks.log"
            store = ClientBlockHistoryStore(path)
            blocks = [{"client": "user:phone", "duration": "always", "enabled": True}]

            self.assertTrue(store.record_snapshot(blocks, timestamp="2026-06-06T00:00:00+00:00"))
            self.assertFalse(store.record_snapshot(blocks, timestamp="2026-06-06T00:01:00+00:00"))
            self.assertTrue(store.record_snapshot([], timestamp="2026-06-06T00:02:00+00:00"))

            records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(records), 2)
            self.assertEqual(records[0]["blocks"][0]["client"], "user:phone")
            self.assertEqual(records[1]["blocks"], [])

    def test_activity_builds_presence_segments_and_block_precedence(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            presence = root / "presence.log"
            blocks = root / "blocks.log"
            failures = root / "failures.log"
            self._write_jsonl(
                presence,
                [
                    {"timestamp": "2026-06-05T23:00:00+00:00", "client": "user:phone", "state": "offline"},
                    {"timestamp": "2026-06-06T01:00:00+00:00", "client": "user:phone", "state": "online"},
                    {"timestamp": "2026-06-06T04:00:00+00:00", "client": "user:phone", "state": "offline"},
                ],
            )
            self._write_jsonl(
                blocks,
                [
                    {"timestamp": "2026-06-06T00:00:00+00:00", "blocks": []},
                    {
                        "timestamp": "2026-06-06T02:00:00+00:00",
                        "blocks": [
                            {
                                "client": "user:phone",
                                "enabled": True,
                                "duration": "always",
                                "expires_at": None,
                            }
                        ],
                    },
                    {"timestamp": "2026-06-06T03:00:00+00:00", "blocks": []},
                ],
            )
            self._write_jsonl(
                failures,
                [
                    {
                        "timestamp": "2026-06-06T02:30:00+00:00",
                        "client": "user:phone",
                        "route_label": "reject:client-access-block",
                        "destination": "example.com:443",
                        "context": "client access block",
                    }
                ],
            )
            cache = ClientActivityCache(presence, blocks, failures)

            payload = cache.query(
                range_key="24h",
                client="user:phone",
                configured_users=[{"username": "phone", "label": "Phone"}],
                current_presence={},
                now=datetime(2026, 6, 6, 6, 0, 0, tzinfo=timezone.utc),
            )

            row = payload["rows"][0]
            self.assertEqual(row["label"], "Phone")
            self.assertEqual(
                [item["state"] for item in row["segments"]],
                ["unknown", "offline", "online", "blocked", "online", "offline"],
            )
            self.assertEqual(row["summary"]["blocked_seconds"], 3600)
            self.assertEqual(row["blocked_attempts"][0]["destination"], "example.com:443")
            self.assertEqual(row["current_state"], "offline")

    def test_temporary_block_ends_at_expiration_without_unblock_snapshot(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            presence = root / "presence.log"
            blocks = root / "blocks.log"
            failures = root / "failures.log"
            self._write_jsonl(
                presence,
                [{"timestamp": "2026-06-06T00:00:00+00:00", "client": "user:phone", "state": "online"}],
            )
            self._write_jsonl(
                blocks,
                [
                    {
                        "timestamp": "2026-06-06T01:00:00+00:00",
                        "blocks": [
                            {
                                "client": "user:phone",
                                "enabled": True,
                                "duration": "1h",
                                "expires_at": "2026-06-06T02:00:00+00:00",
                            }
                        ],
                    }
                ],
            )
            failures.write_text("", encoding="utf-8")
            cache = ClientActivityCache(presence, blocks, failures)

            payload = cache.query(
                range_key="24h",
                client="user:phone",
                configured_users=[],
                current_presence={},
                now=datetime(2026, 6, 6, 3, 0, 0, tzinfo=timezone.utc),
            )

            segments = payload["rows"][0]["segments"]
            self.assertEqual([item["state"] for item in segments[-3:]], ["online", "blocked", "online"])
            self.assertEqual(payload["rows"][0]["summary"]["blocked_seconds"], 3600)


if __name__ == "__main__":
    unittest.main()
