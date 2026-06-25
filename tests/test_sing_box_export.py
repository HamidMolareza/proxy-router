import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from proxy_router.config import RouterConfigManager
from proxy_router.sing_box import build_sing_box_config


class SingBoxExportTests(unittest.TestCase):
    def _manager(self, temp_dir, payload):
        manager = RouterConfigManager(Path(temp_dir) / "router-config.json")
        manager.update(payload)
        return manager

    def test_exports_redirect_inbound_and_route_rules(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = self._manager(
                temp_dir,
                {
                    "proxies": [
                        {
                            "id": "gh-proxy",
                            "name": "gh-proxy",
                            "type": "socks5",
                            "host": "127.0.0.1",
                            "port": 8910,
                        }
                    ],
                    "rules": [
                        {"pattern": "github.com", "match": "suffix", "action": "proxy"},
                        {"pattern": "shaparak.ir", "match": "suffix", "action": "direct"},
                        {"pattern": "ads.example.com", "match": "exact", "action": "block"},
                    ],
                },
            )
            try:
                config = build_sing_box_config(manager, listen="0.0.0.0", listen_port=19090)
            finally:
                manager.shutdown()

        self.assertEqual(config["inbounds"][0]["type"], "redirect")
        self.assertEqual(config["inbounds"][0]["listen"], "0.0.0.0")
        self.assertEqual(config["inbounds"][0]["listen_port"], 19090)
        self.assertIn({"type": "socks", "tag": "proxy-gh-proxy", "server": "127.0.0.1", "server_port": 8910, "version": "5"}, config["outbounds"])
        self.assertEqual(config["route"]["final"], "direct")
        self.assertIn(
            {"ip_cidr": ["198.18.0.0/16"], "action": "route", "outbound": "proxy-gh-proxy"},
            config["route"]["rules"],
        )
        self.assertIn(
            {"domain_suffix": ["github.com"], "action": "route", "outbound": "proxy-gh-proxy"},
            config["route"]["rules"],
        )
        self.assertIn(
            {"domain_suffix": ["shaparak.ir"], "action": "route", "outbound": "direct"},
            config["route"]["rules"],
        )
        self.assertIn(
            {"domain": ["ads.example.com"], "action": "route", "outbound": "block"},
            config["route"]["rules"],
        )
    def test_exports_contains_rules(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = self._manager(
                temp_dir,
                {"rules": [{"pattern": "tracking", "match": "contains", "action": "block"}]},
            )
            try:
                config = build_sing_box_config(manager)
            finally:
                manager.shutdown()

        self.assertIn(
            {"domain_keyword": ["tracking"], "action": "route", "outbound": "block"},
            config["route"]["rules"],
        )

    def test_proxy_id_selects_matching_outbound(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            manager = self._manager(
                temp_dir,
                {
                    "proxies": [
                        {"id": "first", "type": "http", "host": "127.0.0.1", "port": 8080, "priority": 1},
                        {"id": "second", "type": "socks5", "host": "127.0.0.1", "port": 8910, "priority": 2},
                    ],
                    "rules": [
                        {"pattern": "example.com", "match": "suffix", "action": "proxy", "proxy_id": "second"},
                    ],
                },
            )
            try:
                config = build_sing_box_config(manager)
            finally:
                manager.shutdown()

        self.assertIn(
            {"domain_suffix": ["example.com"], "action": "route", "outbound": "proxy-second"},
            config["route"]["rules"],
        )

    def test_cli_exports_json(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "router-config.json"
            manager = RouterConfigManager(config_path)
            try:
                manager.update({"rules": [{"pattern": "example.com", "action": "direct"}]})
            finally:
                manager.shutdown()

            result = subprocess.run(
                [
                    sys.executable,
                    "./proxy-router",
                    "sing-box-export",
                    "--router-config-file",
                    str(config_path),
                    "--listen-port",
                    "19091",
                ],
                check=True,
                capture_output=True,
                text=True,
            )

        payload = json.loads(result.stdout)
        self.assertEqual(payload["inbounds"][0]["listen_port"], 19091)
        self.assertIn(
            {"domain_suffix": ["example.com"], "action": "route", "outbound": "direct"},
            payload["route"]["rules"],
        )


if __name__ == "__main__":
    unittest.main()
