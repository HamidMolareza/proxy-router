import socket
import threading
import time
import unittest

from proxy_router.proxy_server import tunnel_bidirectional


def close_sockets(*sockets):
    for sock in sockets:
        if sock is None:
            continue
        try:
            sock.close()
        except OSError:
            pass


def recv_exact(sock, size):
    chunks = []
    remaining = size
    while remaining > 0:
        chunk = sock.recv(min(65536, remaining))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def assert_sockets_closed(test_case, *sockets):
    for sock in sockets:
        test_case.assertEqual(sock.fileno(), -1)


class BlockingSendOnceSocket:
    def __init__(self, inner):
        self._inner = inner
        self._blocked_once = False

    def fileno(self):
        return self._inner.fileno()

    def setblocking(self, flag):
        self._inner.setblocking(flag)

    def recv(self, size):
        return self._inner.recv(size)

    def send(self, data):
        if not self._blocked_once:
            self._blocked_once = True
            raise BlockingIOError()
        return self._inner.send(data)

    def shutdown(self, how):
        self._inner.shutdown(how)

    def close(self):
        self._inner.close()


class BlockingSendUntilReleasedSocket:
    def __init__(self, inner, released):
        self._inner = inner
        self._released = released

    def fileno(self):
        return self._inner.fileno()

    def setblocking(self, flag):
        self._inner.setblocking(flag)

    def recv(self, size):
        return self._inner.recv(size)

    def send(self, data):
        if not self._released.is_set():
            raise BlockingIOError()
        return self._inner.send(data)

    def shutdown(self, how):
        self._inner.shutdown(how)

    def close(self):
        self._inner.close()


class TunnelRelayTests(unittest.TestCase):
    def test_tunnel_bidirectional_does_not_timeout_while_both_sides_are_open(self):
        left_proxy, left_client = socket.socketpair()
        right_proxy, right_client = socket.socketpair()
        result = {}

        def run_tunnel():
            result["stats"] = tunnel_bidirectional(
                left_proxy,
                right_proxy,
                half_close_drain_seconds=0.05,
            )

        thread = threading.Thread(target=run_tunnel)
        thread.start()
        try:
            time.sleep(0.15)
            self.assertTrue(thread.is_alive())

            left_client.close()
            left_client = None
            right_client.close()
            right_client = None
            thread.join(timeout=2.0)

            self.assertFalse(thread.is_alive())
            self.assertEqual(result["stats"]["close_reason"], "completed")
        finally:
            close_sockets(left_client, right_client, left_proxy, right_proxy)
            thread.join(timeout=2.0)

    def test_tunnel_bidirectional_times_out_when_idle_timeout_is_configured(self):
        left_proxy, left_client = socket.socketpair()
        right_proxy, right_client = socket.socketpair()
        result = {}

        def run_tunnel():
            result["stats"] = tunnel_bidirectional(
                left_proxy,
                right_proxy,
                idle_timeout_seconds=0.05,
            )

        thread = threading.Thread(target=run_tunnel)
        thread.start()
        try:
            thread.join(timeout=1.0)

            self.assertFalse(thread.is_alive())
            self.assertEqual(result["stats"]["close_reason"], "idle_timeout")
            assert_sockets_closed(self, left_proxy, right_proxy)
        finally:
            close_sockets(left_client, right_client, left_proxy, right_proxy)
            thread.join(timeout=2.0)

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
            right_client.close()
            right_client = None
            thread.join(timeout=2.0)

            self.assertFalse(thread.is_alive())
            self.assertEqual(result["stats"]["left_to_right_bytes"], 5)
            self.assertEqual(result["stats"]["right_to_left_bytes"], 5)
            assert_sockets_closed(self, left_proxy, right_proxy)
        finally:
            close_sockets(left_client, right_client, left_proxy, right_proxy)
            thread.join(timeout=2.0)

    def test_tunnel_bidirectional_retries_transient_nonblocking_send(self):
        left_proxy, left_client = socket.socketpair()
        right_proxy, right_client = socket.socketpair()
        flaky_right_proxy = BlockingSendOnceSocket(right_proxy)
        result = {}

        def run_tunnel():
            result["stats"] = tunnel_bidirectional(left_proxy, flaky_right_proxy)

        thread = threading.Thread(target=run_tunnel)
        thread.start()
        try:
            payload = b"x" * 1024
            left_client.sendall(payload)

            self.assertEqual(recv_exact(right_client, len(payload)), payload)

            left_client.close()
            left_client = None
            right_client.close()
            right_client = None
            thread.join(timeout=2.0)

            self.assertFalse(thread.is_alive())
            self.assertEqual(result["stats"]["left_to_right_bytes"], len(payload))
        finally:
            close_sockets(left_client, right_client, left_proxy, flaky_right_proxy)
            thread.join(timeout=2.0)

    def test_tunnel_bidirectional_drains_response_after_peer_half_close(self):
        left_proxy, left_client = socket.socketpair()
        right_proxy, right_client = socket.socketpair()
        result = {}

        def run_tunnel():
            result["stats"] = tunnel_bidirectional(left_proxy, right_proxy)

        thread = threading.Thread(target=run_tunnel)
        thread.start()
        try:
            request = b"GET /large HTTP/1.1\r\n\r\n"
            response = b"z" * (2 * 1024 * 1024)

            left_client.sendall(request)
            left_client.shutdown(socket.SHUT_WR)
            self.assertEqual(recv_exact(right_client, len(request)), request)

            right_client.sendall(response)
            right_client.shutdown(socket.SHUT_WR)

            self.assertEqual(recv_exact(left_client, len(response)), response)
            thread.join(timeout=2.0)

            self.assertFalse(thread.is_alive())
            self.assertEqual(result["stats"]["left_to_right_bytes"], len(request))
            self.assertEqual(result["stats"]["right_to_left_bytes"], len(response))
            self.assertEqual(result["stats"]["close_reason"], "completed")
        finally:
            close_sockets(left_client, right_client, left_proxy, right_proxy)
            thread.join(timeout=2.0)

    def test_tunnel_bidirectional_times_out_when_peer_stays_open_after_half_close(self):
        left_proxy, left_client = socket.socketpair()
        right_proxy, right_client = socket.socketpair()
        result = {}

        def run_tunnel():
            result["stats"] = tunnel_bidirectional(
                left_proxy,
                right_proxy,
                half_close_drain_seconds=0.05,
            )

        thread = threading.Thread(target=run_tunnel)
        thread.start()
        try:
            request = b"request"
            left_client.sendall(request)
            left_client.shutdown(socket.SHUT_WR)
            self.assertEqual(recv_exact(right_client, len(request)), request)

            thread.join(timeout=1.0)

            self.assertFalse(thread.is_alive())
            self.assertEqual(result["stats"]["left_to_right_bytes"], len(request))
            self.assertEqual(result["stats"]["right_to_left_bytes"], 0)
            self.assertEqual(result["stats"]["close_reason"], "half_close_timeout")
            assert_sockets_closed(self, left_proxy, right_proxy)
        finally:
            close_sockets(left_client, right_client, left_proxy, right_proxy)
            thread.join(timeout=2.0)

    def test_tunnel_bidirectional_starts_half_close_timeout_after_buffer_drains(self):
        left_proxy, left_client = socket.socketpair()
        right_proxy, right_client = socket.socketpair()
        released = threading.Event()
        blocked_right_proxy = BlockingSendUntilReleasedSocket(right_proxy, released)
        result = {}

        def run_tunnel():
            result["stats"] = tunnel_bidirectional(
                left_proxy,
                blocked_right_proxy,
                half_close_drain_seconds=0.05,
            )

        thread = threading.Thread(target=run_tunnel)
        thread.start()
        try:
            request = b"buffered request"
            left_client.sendall(request)
            left_client.shutdown(socket.SHUT_WR)

            time.sleep(0.15)
            self.assertTrue(thread.is_alive())

            released.set()
            self.assertEqual(recv_exact(right_client, len(request)), request)
            thread.join(timeout=1.0)

            self.assertFalse(thread.is_alive())
            self.assertEqual(result["stats"]["left_to_right_bytes"], len(request))
            self.assertEqual(result["stats"]["close_reason"], "half_close_timeout")
        finally:
            released.set()
            close_sockets(left_client, right_client, left_proxy, blocked_right_proxy)
            thread.join(timeout=2.0)

    def test_tunnel_bidirectional_relays_large_payload_with_slow_receiver(self):
        left_proxy, left_client = socket.socketpair()
        right_proxy, right_client = socket.socketpair()
        result = {}
        received = bytearray()

        def run_tunnel():
            result["stats"] = tunnel_bidirectional(left_proxy, right_proxy)

        def read_slowly():
            while True:
                chunk = right_client.recv(32768)
                if not chunk:
                    return
                received.extend(chunk)
                time.sleep(0.001)

        thread = threading.Thread(target=run_tunnel)
        reader = threading.Thread(target=read_slowly)
        thread.start()
        reader.start()
        try:
            payload = b"a" * (10 * 1024 * 1024)
            left_client.sendall(payload)
            left_client.shutdown(socket.SHUT_WR)

            reader.join(timeout=10.0)
            right_client.close()
            right_client = None
            thread.join(timeout=2.0)

            self.assertFalse(reader.is_alive())
            self.assertFalse(thread.is_alive())
            self.assertEqual(bytes(received), payload)
            self.assertEqual(result["stats"]["left_to_right_bytes"], len(payload))
        finally:
            close_sockets(left_client, right_client, left_proxy, right_proxy)
            reader.join(timeout=2.0)
            thread.join(timeout=2.0)


if __name__ == "__main__":
    unittest.main()
