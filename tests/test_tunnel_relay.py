import socket
import threading
import unittest

from proxy_router.proxy_server import tunnel_bidirectional


class TunnelRelayTests(unittest.TestCase):
    def test_tunnel_bidirectional_relays_both_directions(self):
        left_proxy, left_client = socket.socketpair()
        right_proxy, right_client = socket.socketpair()
        result = {}

        def run_tunnel():
            result["stats"] = tunnel_bidirectional(left_proxy, right_proxy)

        thread = threading.Thread(target=run_tunnel)
        thread.start()
        try:
            left_client.sendall(b"hello")
            self.assertEqual(right_client.recv(5), b"hello")

            right_client.sendall(b"world")
            self.assertEqual(left_client.recv(5), b"world")

            left_client.close()
            left_client = None
            thread.join(timeout=2.0)

            self.assertFalse(thread.is_alive())
            self.assertEqual(result["stats"]["left_to_right_bytes"], 5)
            self.assertEqual(result["stats"]["right_to_left_bytes"], 5)
        finally:
            for sock in (left_client, right_client, left_proxy, right_proxy):
                if sock is None:
                    continue
                try:
                    sock.close()
                except OSError:
                    pass
            thread.join(timeout=2.0)


if __name__ == "__main__":
    unittest.main()
