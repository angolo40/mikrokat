import copy
import json
import os
import re
import sys
import tempfile
import unittest

sys.path.insert(0, "/app")
import store  # noqa: E402
import web  # noqa: E402


def full_form(**changes):
    """A complete settings form built from the current settings, with changes on top."""
    s = store.settings
    form = {"mode": s["mode"], "router_host": s["router_host"], "router_user": s["router_user"], "address_list": s["address_list"],
            "block_timeout": s["block_timeout"], "block_steps": s["block_steps"], "rules_auto": s["rules_auto"],
            "dedupe_seconds": str(s["dedupe_seconds"]), "retention_days": str(s["retention_days"]), "router_port": str(s["router_port"]),
            "severity1": "on", "severity2": "on", "tls_socks_port": str(s["tls_socks_port"]),
            "tls_devices": "\n".join(s["tls_devices"]), "tls_bypass": "\n".join(s["tls_bypass"])}
    if s["tls_enabled"]:
        form["tls_enabled"] = "on"
    if s["tls_socks"]:
        form["tls_socks"] = "on"
    form.update(changes)
    return form


class Base(unittest.TestCase):
    def setUp(self):
        self.saved = copy.deepcopy(store.settings)
        self.dir = tempfile.TemporaryDirectory()
        self.old = (store.DATA_DIR, store.SETTINGS_FILE, store.TLS_DIR)
        store.DATA_DIR = self.dir.name
        store.SETTINGS_FILE = os.path.join(self.dir.name, "settings.json")
        store.TLS_DIR = os.path.join(self.dir.name, "tls")
        os.makedirs(os.path.join(store.TLS_DIR, "control"))
        os.makedirs(os.path.join(store.TLS_DIR, "state"))
        store.settings.clear()
        store.settings.update(copy.deepcopy(self.saved))
        store.settings.update(tls_enabled=False, tls_socks=True, tls_socks_port=1080, tls_devices=[], tls_bypass=[], tls_ca_generation=0, tls_auto_remove=[])

    def tearDown(self):
        store.settings.clear()
        store.settings.update(self.saved)
        store.DATA_DIR, store.SETTINGS_FILE, store.TLS_DIR = self.old
        self.dir.cleanup()

    def control(self):
        with open(os.path.join(store.TLS_DIR, "control", "config.json")) as source:
            return json.load(source)


class TlsSettings(Base):
    def test_off_by_default(self):
        store.write_tls_control()
        self.assertIs(self.control()["enabled"], False)

    def test_bad_device_is_refused(self):
        self.assertTrue(store.save_settings(full_form(tls_devices="not an ip")))

    def test_enabled_needs_a_device(self):
        self.assertTrue(store.save_settings(full_form(tls_enabled="on")))
        self.assertFalse(store.settings["tls_enabled"])

    def test_port_conflict_is_refused(self):
        for port in ("8088", "5636", "37008", "8443", "80", "70000", "x"):
            self.assertTrue(store.save_settings(full_form(tls_socks_port=port)), port)

    def test_bad_bypass_name_is_refused(self):
        self.assertTrue(store.save_settings(full_form(tls_bypass="bad name/")))

    def test_control_file_keys(self):
        error = store.save_settings(full_form(tls_enabled="on", tls_devices="10.0.0.5\r\n10.0.0.5\n\nfe80::1\n", tls_bypass="Bank.Example.com\n*.pay.example"))
        self.assertIsNone(error)
        self.assertEqual(self.control(), {"enabled": True, "socks": True, "socks_port": 1080, "devices": ["10.0.0.5", "fe80::1"],
                                          "bypass": ["bank.example.com", "*.pay.example"], "ca_generation": 0, "auto_remove": []})

    def test_status_survives_bad_json(self):
        self.assertEqual(store.tls_status(), {})
        with open(os.path.join(store.TLS_DIR, "state", "stats.json"), "w") as target:
            target.write("{not json")
        self.assertEqual(store.tls_status(), {})
        with open(os.path.join(store.TLS_DIR, "state", "stats.json"), "w") as target:
            target.write('{"inspected": 3}')
        self.assertEqual(store.tls_status(), {"inspected": 3})

    def test_regenerate_raises_generation(self):
        store.regenerate_ca()
        self.assertEqual(store.settings["tls_ca_generation"], 1)
        self.assertEqual(self.control()["ca_generation"], 1)

    def test_remove_auto_bypass_is_capped(self):
        for i in range(60):
            store.remove_auto_bypass("10.0.0.5", f"h{i}.example")
        entries = store.settings["tls_auto_remove"]
        self.assertEqual(len(entries), 50)
        self.assertEqual(entries[-1]["name"], "h59.example")
        self.assertIsInstance(entries[-1]["at"], int)
        self.assertEqual(len(self.control()["auto_remove"]), 50)


class Pac(Base):
    def on(self):
        store.settings.update(tls_enabled=True, tls_devices=["10.0.0.5"])
        return web.pac_text("mikrokat.lan:8088")

    def test_on(self):
        self.assertIn("SOCKS5 mikrokat.lan:1080; DIRECT", self.on())

    def test_off(self):
        self.assertIn('return "DIRECT"', web.pac_text("mikrokat.lan:8088"))

    def test_hostile_host_is_direct(self):
        store.settings.update(tls_enabled=True, tls_devices=["10.0.0.5"])
        for host in ('a"; evil(); "', "a b", "", "x\\y", "a:99999999"):
            text = web.pac_text(host)
            self.assertNotIn("SOCKS", text, host)
            self.assertIn('return "DIRECT"', text)

    def test_socks_off_is_direct(self):
        store.settings.update(tls_enabled=True, tls_socks=False, tls_devices=["10.0.0.5"])
        self.assertNotIn("SOCKS", web.pac_text("mikrokat.lan"))

    def test_ipv6_host(self):
        store.settings.update(tls_enabled=True, tls_devices=["10.0.0.5"])
        self.assertIn("SOCKS5 [fd00::1]:1080; DIRECT", web.pac_text("[fd00::1]:8088"))

    def test_only_https_and_wss_reach_the_proxy(self):
        lines = self.on().splitlines()
        first = lines[1]
        self.assertIn('"https:"', first)
        self.assertIn('"wss:"', first)
        self.assertIn('return "DIRECT"', first)
        self.assertNotIn("http:", first)

    def test_plain_names_and_local_addresses_are_direct(self):
        text = self.on()
        self.assertIn('if (isPlainHostName(host)) return "DIRECT";', text)
        self.assertIn(f"if (/{web.PAC_LOCAL}/i.test(host)) return \"DIRECT\";", text)
        self.assertLess(text.index("PlainHostName"), text.index("SOCKS5"))
        self.assertLess(text.index(".test(host)"), text.index("SOCKS5"))

    def test_local_address_pattern(self):
        local = ("10.0.0.1", "10.255.255.254", "127.0.0.1", "169.254.169.254", "172.16.0.1", "172.31.255.1", "192.168.88.1",
                 "100.64.0.1", "100.127.255.254", "fc00::1", "fd12:3456::1", "[fd00::1]", "FD00::1", "fe80::1", "::1", "[::1]")
        public = ("8.8.8.8", "11.0.0.1", "172.15.0.1", "172.32.0.1", "192.167.0.1", "100.63.0.1", "100.128.0.1", "2001:db8::1",
                  "example.com", "10.example.com", "10.0.0.1.example.com", "192.168.1.1.example.com", "fd00.example.com", "fc.example")
        for host in local:
            self.assertRegex(host, re.compile(web.PAC_LOCAL, re.I))
        for host in public:
            self.assertNotRegex(host, re.compile(web.PAC_LOCAL, re.I))


class Page(Base):
    def test_warnings_next_to_the_switch(self):
        page = web.settings_page("mikrokat.lan:8088", tab="https")
        self.assertIn("Any other bank, payment or health site is decrypted", page)
        self.assertLess(page.index("Any other bank"), page.index('name="tls_enabled"'))

    def test_regenerate_says_the_old_ca_stays_trusted(self):
        page = web.settings_page("mikrokat.lan:8088", tab="https")
        self.assertIn("does not revoke the old one", page)
        self.assertIn("does not revoke the old one", web.NOTICES["ca-regenerated"])

    def test_names_from_the_proxy_are_escaped(self):
        with open(os.path.join(store.TLS_DIR, "state", "stats.json"), "w") as target:
            json.dump({"at": 1, "relayed": {"<b>x</b>": 1}, "auto_bypass": [{"device": "10.0.0.5", "name": "<script>alert(1)</script>", "until": 2}]}, target)
        store.names["10.0.0.5"] = "<img src=x>"
        try:
            page = web.settings_page("mikrokat.lan:8088", tab="https")
        finally:
            store.names.pop("10.0.0.5")
        self.assertNotIn("<script>alert(1)", page)
        self.assertNotIn("<img src=x>", page)
        self.assertNotIn("<b>x</b>", page)
        self.assertIn("&lt;script&gt;alert(1)", page)


if __name__ == "__main__":
    unittest.main()
