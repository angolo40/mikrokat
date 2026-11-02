import json
import os
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0, "/app")
import health  # noqa: E402
import store  # noqa: E402
import web  # noqa: E402
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
    def write(self, at, **more):
        with open(os.path.join(store.TLS_DIR, "state", "stats.json"), "w") as target:
            json.dump({"at": at, **more}, target)

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

    def test_port_closed_alarms(self):
        store.settings["tls_enabled"] = True
        self.write(time.time() - 5, listening=False, error="listen tcp :1080: bind: address already in use")
        problem = health.tls_problem()
        self.assertIn("port", problem)
        self.assertIn("listen tcp :1080: bind: address already in use", problem)

    def test_port_closed_without_a_reason(self):
        store.settings["tls_enabled"] = True
        self.write(time.time() - 5, listening=False, error="")
        self.assertIn("port", health.tls_problem())

    def test_listening_is_fine(self):
        store.settings["tls_enabled"] = True
        self.write(time.time() - 5, listening=True, error="")
        self.assertIsNone(health.tls_problem())

    def test_port_may_be_closed_without_socks(self):
        store.settings.update(tls_enabled=True, tls_socks=False)
        self.write(time.time() - 5, listening=False, error="")
        self.assertIsNone(health.tls_problem())

    def test_port_may_be_closed_when_off(self):
        self.write(time.time() - 5, listening=False, error="")
        self.assertIsNone(health.tls_problem())

    def test_stale_stats_beat_the_old_port_state(self):
        store.settings["tls_enabled"] = True
        self.write(time.time() - 61, listening=True, error="")
        self.assertEqual(health.tls_problem(), MESSAGE)

    def test_long_error_is_cut(self):
        store.settings["tls_enabled"] = True
        self.write(time.time() - 5, listening=False, error="x" * 5000)
        self.assertLess(len(health.tls_problem()), 400)

    def test_error_is_escaped_on_the_page(self):
        store.settings["tls_enabled"] = True
        self.write(time.time() - 5, listening=False, error="<script>alert(1)</script>")
        store.problems["tls"] = health.tls_problem()
        try:
            page = web.layout("/", "Overview", "", "mikrokat.lan")
        finally:
            store.problems.clear()
        self.assertNotIn("<script>alert(1)", page)
        self.assertIn("&lt;script&gt;alert(1)", page)

    def test_ca_far_from_expiry(self):
        store.settings["tls_enabled"] = True
        self.write(time.time() - 5, ca_expires=time.time() + 31 * 86400)
        self.assertIsNone(health.ca_problem())

    def test_ca_close_to_expiry(self):
        store.settings["tls_enabled"] = True
        self.write(time.time() - 5, ca_expires=time.time() + 29 * 86400)
        self.assertIn("expires in", health.ca_problem())

    def test_ca_expired(self):
        store.settings["tls_enabled"] = True
        self.write(time.time() - 5, ca_expires=time.time() - 60)
        self.assertIn("has expired", health.ca_problem())

    def test_own_ca_close_to_expiry_asks_for_an_upload(self):
        store.settings["tls_enabled"] = True
        self.write(time.time() - 5, ca_own=True, ca_expires=time.time() + 29 * 86400)
        problem = health.ca_problem()
        self.assertIn("expires in", problem)
        self.assertIn("Upload", problem)
        self.assertNotIn("Regenerate", problem)

    def test_own_ca_expired_asks_for_an_upload(self):
        store.settings["tls_enabled"] = True
        self.write(time.time() - 5, ca_own=True, ca_expires=time.time() - 60)
        problem = health.ca_problem()
        self.assertIn("has expired", problem)
        self.assertIn("Upload", problem)
        self.assertNotIn("Regenerate", problem)

    def test_own_ca_that_cannot_load_fires_the_port_alarm(self):
        store.settings["tls_enabled"] = True
        self.write(time.time() - 5, ca_own=True, ca_expires=0, listening=False, error="CA failed: own CA: the key does not match the first certificate")
        self.assertIn("the key does not match", health.tls_problem())
        self.assertIsNone(health.ca_problem())

    def test_no_ca_yet(self):
        store.settings["tls_enabled"] = True
        for value in (0, None, "soon", True):
            self.write(time.time() - 5, ca_expires=value)
            self.assertIsNone(health.ca_problem(), value)

    def test_ca_ignored_when_off(self):
        self.write(time.time() - 5, ca_expires=time.time() + 86400)
        self.assertIsNone(health.ca_problem())

    def test_check_reports_each_problem(self):
        store.settings["tls_enabled"] = True
        self.write(time.time() - 5, listening=False, error="taken", ca_expires=time.time() + 86400)
        with mock.patch.object(web, "suricata", return_value=None):
            found = health.check()
        self.assertIn("taken", found["tls"])
        self.assertIn("expires in", found["tls_ca"])
