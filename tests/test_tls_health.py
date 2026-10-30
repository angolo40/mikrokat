import json
import os
import sys
import time
import unittest

sys.path.insert(0, "/app")
import health  # noqa: E402
import store  # noqa: E402
from test_tls_settings import Base  # noqa: E402

MESSAGE = "HTTPS inspection has stopped. Devices are browsing without inspection."


class Decrypted(Base):
    def test_marker(self):
        self.assertTrue(store.is_decrypted({"vlan": [3900]}))
        self.assertFalse(store.is_decrypted({"vlan": [10]}))
        self.assertFalse(store.is_decrypted({}))

    def test_count_both_ends(self):
        store.pending_decrypted.clear()
        store.count_alert({"src_ip": "10.0.0.5", "dest_ip": "198.51.100.7", "vlan": [3900], "alert": {"severity": 1, "signature_id": 9}}, "198.51.100.7")
        store.count_alert({"src_ip": "10.0.0.5", "dest_ip": "198.51.100.7", "vlan": [10], "alert": {"severity": 1, "signature_id": 9}}, "198.51.100.7")
        hour = time.strftime("%Y-%m-%d %H")
        self.assertEqual(store.pending_decrypted, {(hour, "10.0.0.5"): 1, (hour, "198.51.100.7"): 1})
        store.pending_decrypted.clear()


class Health(Base):
    def write(self, at):
        with open(os.path.join(store.TLS_DIR, "state", "stats.json"), "w") as target:
            json.dump({"at": at}, target)

    def test_off_never_alarms(self):
        self.assertIsNone(health.tls_problem())

    def test_fresh_stats_ok(self):
        store.settings["tls_enabled"] = True
        self.write(time.time() - 5)
        self.assertIsNone(health.tls_problem())

    def test_stale_stats_alarm(self):
        store.settings["tls_enabled"] = True
        self.write(time.time() - 61)
        self.assertEqual(health.tls_problem(), MESSAGE)

    def test_missing_stats_alarm(self):
        store.settings["tls_enabled"] = True
        self.assertEqual(health.tls_problem(), MESSAGE)

    def test_bad_at_alarms(self):
        store.settings["tls_enabled"] = True
        self.write("soon")
        self.assertEqual(health.tls_problem(), MESSAGE)
