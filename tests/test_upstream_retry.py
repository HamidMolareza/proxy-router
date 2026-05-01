import unittest
from unittest.mock import patch

from proxy_router.proxy_server import retry_upstream_operation
from proxy_router.util import normalize_router_config


class UpstreamRetryConfigTests(unittest.TestCase):
    def test_normalize_router_config_preserves_upstream_retry_policy(self):
        config = normalize_router_config(
            {
                "upstream_retry": {
                    "enabled": True,
                    "attempts": "6",
                    "initial_delay_seconds": "2",
                    "max_delay_seconds": "8",
                },
            }
        )

        self.assertEqual(
            config["upstream_retry"],
            {
                "enabled": True,
                "attempts": 6,
                "initial_delay_seconds": 2,
                "max_delay_seconds": 8,
            },
        )

    def test_normalize_router_config_rejects_retry_max_below_initial_delay(self):
        with self.assertRaisesRegex(ValueError, "max_delay_seconds"):
            normalize_router_config(
                {
                    "upstream_retry": {
                        "initial_delay_seconds": 5,
                        "max_delay_seconds": 2,
                    },
                }
            )

    def test_retry_upstream_operation_uses_configured_delays(self):
        calls = []
        retries = []

        def operation(attempt):
            calls.append(attempt)
            if len(calls) < 3:
                raise TimeoutError("temporary upstream failure")
            return "ok"

        with patch("proxy_router.proxy_server.time.sleep") as sleep:
            result = retry_upstream_operation(
                operation,
                retry_policy={
                    "enabled": True,
                    "attempts": 4,
                    "initial_delay_seconds": 2,
                    "max_delay_seconds": 3,
                },
                on_retry=lambda attempt, attempts, delay, exc: retries.append(
                    (attempt, attempts, delay, type(exc).__name__)
                ),
            )

        self.assertEqual(result, "ok")
        self.assertEqual(calls, [1, 2, 3])
        self.assertEqual(retries, [(1, 4, 2.0, "TimeoutError"), (2, 4, 3.0, "TimeoutError")])
        self.assertEqual([call.args[0] for call in sleep.call_args_list], [2.0, 3.0])

    def test_retry_upstream_operation_can_be_disabled(self):
        calls = []

        def operation(attempt):
            calls.append(attempt)
            raise TimeoutError("temporary upstream failure")

        with patch("proxy_router.proxy_server.time.sleep") as sleep:
            with self.assertRaises(TimeoutError):
                retry_upstream_operation(
                    operation,
                    retry_policy={
                        "enabled": False,
                        "attempts": 4,
                        "initial_delay_seconds": 2,
                        "max_delay_seconds": 3,
                    },
                    on_retry=lambda attempt, attempts, delay, exc: None,
                )

        self.assertEqual(calls, [1])
        sleep.assert_not_called()


if __name__ == "__main__":
    unittest.main()
