import unittest

from proxy_router.runtime import TunnelLimitManager, UpstreamSetupLimitManager


class TunnelLimitManagerTests(unittest.TestCase):
    def test_enforces_global_and_client_limits(self):
        manager = TunnelLimitManager(
            max_active=2,
            max_per_client=1,
            max_per_admin_client=2,
            idle_timeout_seconds=30,
        )

        user_ticket, rejection = manager.try_acquire(client="user:regular")
        self.assertIsNotNone(user_ticket)
        self.assertIsNone(rejection)

        second_user_ticket, rejection = manager.try_acquire(client="user:regular")
        self.assertIsNone(second_user_ticket)
        self.assertEqual(rejection["reason"], "client_limit")

        admin_ticket, rejection = manager.try_acquire(client="user:admin")
        self.assertIsNotNone(admin_ticket)
        self.assertIsNone(rejection)

        second_admin_ticket, rejection = manager.try_acquire(client="user:admin")
        self.assertIsNone(second_admin_ticket)
        self.assertEqual(rejection["reason"], "global_limit")

        snapshot = manager.snapshot()
        self.assertEqual(snapshot["active_total"], 2)
        self.assertEqual(snapshot["active_by_client"], {"user:admin": 1, "user:regular": 1})
        self.assertEqual(snapshot["rejected_by_reason"], {"client_limit": 1, "global_limit": 1})
        self.assertEqual(snapshot["limits"]["idle_timeout_seconds"], 30.0)

        user_ticket.release()
        admin_ticket.release()
        self.assertEqual(manager.snapshot()["active_total"], 0)

    def test_admin_clients_use_admin_per_client_limit(self):
        manager = TunnelLimitManager(max_active=10, max_per_client=1, max_per_admin_client=2)

        first_ticket, rejection = manager.try_acquire(client="user:admin-mobile")
        self.assertIsNotNone(first_ticket)
        self.assertIsNone(rejection)
        second_ticket, rejection = manager.try_acquire(client="user:admin-mobile")
        self.assertIsNotNone(second_ticket)
        self.assertIsNone(rejection)
        third_ticket, rejection = manager.try_acquire(client="user:admin-mobile")
        self.assertIsNone(third_ticket)
        self.assertEqual(rejection["reason"], "client_limit")

        first_ticket.release()
        second_ticket.release()

    def test_enforces_per_client_destination_limit(self):
        manager = TunnelLimitManager(
            max_active=10,
            max_per_client=10,
            max_per_admin_client=10,
            max_per_client_destination=2,
        )

        first_ticket, rejection = manager.try_acquire(client="user:admin", destination="Example.COM:443")
        self.assertIsNotNone(first_ticket)
        self.assertIsNone(rejection)
        second_ticket, rejection = manager.try_acquire(client="user:admin", destination="example.com:443")
        self.assertIsNotNone(second_ticket)
        self.assertIsNone(rejection)

        third_ticket, rejection = manager.try_acquire(client="user:admin", destination="example.com:443")
        self.assertIsNone(third_ticket)
        self.assertEqual(rejection["reason"], "client_destination_limit")
        self.assertEqual(rejection["client_destination_active"], 2)
        self.assertEqual(rejection["client_destination_limit"], 2)

        other_destination_ticket, rejection = manager.try_acquire(client="user:admin", destination="other.example:443")
        self.assertIsNotNone(other_destination_ticket)
        self.assertIsNone(rejection)

        snapshot = manager.snapshot()
        self.assertEqual(snapshot["rejected_by_reason"], {"client_destination_limit": 1})
        self.assertEqual(snapshot["active_by_client_destination"]["user:admin example.com:443"], 2)

        first_ticket.release()
        retry_ticket, rejection = manager.try_acquire(client="user:admin", destination="example.com:443")
        self.assertIsNotNone(retry_ticket)
        self.assertIsNone(rejection)

        second_ticket.release()
        other_destination_ticket.release()
        retry_ticket.release()


class UpstreamSetupLimitManagerTests(unittest.TestCase):
    def test_enforces_pending_setup_limit_and_releases_ticket(self):
        manager = UpstreamSetupLimitManager(max_pending=2)

        first_ticket, rejection = manager.try_acquire()
        self.assertIsNotNone(first_ticket)
        self.assertIsNone(rejection)

        second_ticket, rejection = manager.try_acquire()
        self.assertIsNotNone(second_ticket)
        self.assertIsNone(rejection)

        third_ticket, rejection = manager.try_acquire()
        self.assertIsNone(third_ticket)
        self.assertEqual(rejection["reason"], "setup_limit")
        self.assertEqual(rejection["pending"], 2)
        self.assertEqual(rejection["max_pending"], 2)

        snapshot = manager.snapshot()
        self.assertEqual(snapshot["pending"], 2)
        self.assertEqual(snapshot["rejected_total"], 1)
        self.assertEqual(snapshot["limits"]["max_pending"], 2)

        first_ticket.release()
        self.assertEqual(manager.snapshot()["pending"], 1)
        second_ticket.release()
        self.assertEqual(manager.snapshot()["pending"], 0)


if __name__ == "__main__":
    unittest.main()
