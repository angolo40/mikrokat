import sys
import unittest
from unittest import mock

sys.path.insert(0, "/app")
import actions  # noqa: E402
import geo  # noqa: E402
import mikrokat  # noqa: E402
import store  # noqa: E402
from test_tls_settings import Base  # noqa: E402


def event(vlan=None, sid=2024):
    record = {"src_ip": "198.51.100.7", "dest_ip": "10.0.0.5", "src_port": 80, "dest_port": 50000,
              "alert": {"severity": 1, "gid": 1, "signature_id": sid, "signature": "A rule"}}
    if vlan:
        record["vlan"] = [vlan]
    return record


class Decrypted(Base):
    """A page can put any URL in a request to a CDN, so an alert on decrypted traffic must not cut that CDN off."""

    def setUp(self):
        super().setUp()
        mikrokat.seen.clear()
        store.settings.update(mode="block", severities=["1", "2"], ignore_sids=[], dedupe_seconds=0)
        for name in ("block", "notify", "export_alert"):
            patcher = mock.patch.object(actions, name, return_value=True)
            setattr(self, name, patcher.start())
            self.addCleanup(patcher.stop)
        for target, name, value in ((store, "allowed", False), (store, "count_alert", None), (store, "activity_add", None), (geo, "country", ""),
                                    (store, "note_strike", None), (store, "block_time_for", "1h")):
            patcher = mock.patch.object(target, name, return_value=value)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = mock.patch.object(store, "record_action")
        self.record = patcher.start()
        self.addCleanup(patcher.stop)

    def test_real_traffic_is_blocked(self):
        mikrokat.handle(event(vlan=10))
        self.block.assert_called_once()
        self.assertTrue(self.record.call_args.args[2].startswith("Blocked"))

    def test_decrypted_alert_never_blocks(self):
        mikrokat.handle(event(vlan=store.DECRYPTED_VLAN))
        self.block.assert_not_called()
        self.assertEqual(self.record.call_args.args[2], "Would block")
        self.assertIn("Would block", self.notify.call_args.args[0])

    def test_decrypted_alert_in_monitor(self):
        store.settings["mode"] = "monitor"
        mikrokat.handle(event(vlan=store.DECRYPTED_VLAN))
        self.block.assert_not_called()
        self.assertEqual(self.record.call_args.args[2], "Would block")


if __name__ == "__main__":
    unittest.main()
