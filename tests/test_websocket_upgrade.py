import unittest

from proxy_router.proxy_server import build_websocket_upgrade_request, read_http_response_head


class ChunkedSocket:
    def __init__(self, chunks):
        self._chunks = list(chunks)

    def recv(self, _size):
        if not self._chunks:
            return b""
        return self._chunks.pop(0)


class WebSocketUpgradeTests(unittest.TestCase):
    def test_build_websocket_upgrade_request_preserves_upgrade_headers(self):
        request = build_websocket_upgrade_request(
            "GET",
            "/backend-api/codex/responses",
            {
                "Host": "chatgpt.com",
                "Connection": "keep-alive, Upgrade",
                "Upgrade": "websocket",
                "Sec-WebSocket-Key": "abc123",
                "Sec-WebSocket-Version": "13",
                "Proxy-Authorization": "Basic secret",
                "Content-Length": "10",
                "User-Agent": "codex-test",
            },
            "chatgpt.com",
            443,
        ).decode("iso-8859-1")

        self.assertIn("GET /backend-api/codex/responses HTTP/1.1\r\n", request)
        self.assertIn("Host: chatgpt.com\r\n", request)
        self.assertIn("Upgrade: websocket\r\n", request)
        self.assertIn("Connection: Upgrade\r\n", request)
        self.assertIn("Sec-WebSocket-Key: abc123\r\n", request)
        self.assertIn("Sec-WebSocket-Version: 13\r\n", request)
        self.assertIn("User-Agent: codex-test\r\n", request)
        self.assertNotIn("Proxy-Authorization", request)
        self.assertNotIn("Content-Length", request)

    def test_read_http_response_head_returns_leftover_frame_bytes(self):
        sock = ChunkedSocket(
            [
                b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n",
                b"Connection: Upgrade\r\n\r\n\x81\x02ok",
            ]
        )

        head, leftover, status_code, reason, headers = read_http_response_head(sock)

        self.assertEqual(status_code, 101)
        self.assertEqual(reason, "Switching Protocols")
        self.assertIn(b"HTTP/1.1 101", head)
        self.assertEqual(leftover, b"\x81\x02ok")
        self.assertEqual(headers, [("Upgrade", "websocket"), ("Connection", "Upgrade")])


if __name__ == "__main__":
    unittest.main()
