import contextlib
import copy
import html.parser
import http.client
import io
import json
import os
import re
import socket
import stat
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

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
        os.makedirs(os.path.join(store.TLS_DIR, "incoming"))
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


CHAIN = b"-----BEGIN CERTIFICATE-----\nnot really a chain\n-----END CERTIFICATE-----\n"
KEY = b"-----BEGIN PRIVATE KEY-----\ne2UtdmFsdWUtdGhhdC1tdXN0LXN0YXktc2VjcmV0\n-----END PRIVATE KEY-----\n"
BOUNDARY = "----boundary1234"
MULTIPART = f"multipart/form-data; boundary={BOUNDARY}"
OVER_LIMIT = 256 * 1024 + 1


def multipart(**parts):
    """A form as a browser sends it: each value is bytes, and file fields carry a file name."""
    out = b""
    for name, value in parts.items():
        filename = f'; filename="{name}.pem"' if name in ("chain", "key") else ""
        out += f'--{BOUNDARY}\r\nContent-Disposition: form-data; name="{name}"{filename}\r\n'.encode()
        out += b"Content-Type: application/octet-stream\r\n\r\n" if filename else b"\r\n"
        out += value + b"\r\n"
    return out + f"--{BOUNDARY}--\r\n".encode()


class Web(Base):
    """The real handler, over a real socket, because the limits are about what crosses it."""

    def setUp(self):
        super().setUp()
        self.server = web.ThreadingHTTPServer(("127.0.0.1", 0), web.Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.cookie = f"{web.SESSION_COOKIE}={web.new_session()}"
        self.token = web.csrf_token.encode()
        self.stats()  # the proxy writes this every 10 seconds, and the upload needs it

    def post(self, path, body=b"", content_type=MULTIPART, cookie=None, length=None):
        """Return status, Location and text, with the Content-Length as given when one is."""
        client = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=20)
        self.addCleanup(client.close)
        client.putrequest("POST", path)
        client.putheader("Content-Type", content_type)
        client.putheader("Content-Length", str(len(body)) if length is None else length)
        client.putheader("Cookie", self.cookie if cookie is None else cookie)
        client.endheaders()
        client.send(body)
        reply = client.getresponse()
        return reply.status, reply.getheader("Location"), reply.read().decode()

    def upload(self, **changes):
        return self.post("/tls/own-ca", multipart(**{"token": self.token, "chain": CHAIN, "key": KEY, **changes}))

    def incoming(self):
        return sorted(os.listdir(os.path.join(store.TLS_DIR, "incoming")))

    def stats(self, **values):
        with open(os.path.join(store.TLS_DIR, "state", "stats.json"), "w") as target:
            json.dump({"at": int(time.time()), **values}, target)


class OwnCaUpload(Web):
    def test_proxy_not_running_stores_nothing(self):
        # With the proxy down the key would stay in incoming, and the page would say it was deleted.
        silent = [None, {"at": int(time.time()) - store.TLS_SILENCE - 5}, {"at": "soon"}, {"at": True}, {"at": None}, {}, []]
        os.remove(os.path.join(store.TLS_DIR, "state", "stats.json"))
        for stats in silent:
            with self.subTest(stats=stats):
                if stats is not None:
                    with open(os.path.join(store.TLS_DIR, "state", "stats.json"), "w") as target:
                        json.dump(stats, target)
                status, location, text = self.upload()
                self.assertEqual(status, 200)
                self.assertIn("The proxy is not running, so nothing was stored. Start it and upload again.", text)
                self.assertEqual(self.incoming(), [])
        with open(os.path.join(store.TLS_DIR, "state", "stats.json"), "w") as target:
            target.write("{broken")
        self.assertIn("The proxy is not running", self.upload()[2])
        self.assertEqual(self.incoming(), [])

    def test_proxy_running_takes_the_upload(self):
        self.stats(at=int(time.time()) - store.TLS_SILENCE + 5)
        self.assertEqual(self.upload()[0], 303)

    def test_writes_both_files(self):
        status, location, _ = self.upload()
        self.assertEqual((status, location), (303, "/settings?ok=ca-uploaded&tab=https"))
        self.assertEqual(self.incoming(), ["own-ca.key", "own-ca.pem"])
        folder = os.path.join(store.TLS_DIR, "incoming")
        with open(os.path.join(folder, "own-ca.pem"), "rb") as source:
            self.assertEqual(source.read(), CHAIN)
        with open(os.path.join(folder, "own-ca.key"), "rb") as source:
            self.assertEqual(source.read(), KEY)

    def test_key_has_mode_600_from_the_start(self):
        old = os.umask(0)  # so the mode comes from the code, not from the process
        try:
            self.upload()
        finally:
            os.umask(old)
        mode = stat.S_IMODE(os.stat(os.path.join(store.TLS_DIR, "incoming", "own-ca.key")).st_mode)
        self.assertEqual(mode, 0o600)

    def test_certificate_lands_last_and_through_a_rename(self):
        moves = []
        real = os.replace

        def replace(source, target):
            seen = sorted(os.listdir(os.path.dirname(target)))
            moves.append((os.path.basename(target), seen))
            real(source, target)

        with mock.patch.object(store.os, "replace", replace):
            self.upload()
        self.assertEqual([name for name, _ in moves], ["own-ca.key", "own-ca.pem"])
        # When the certificate has not landed yet, it is not there under its own name.
        self.assertNotIn("own-ca.pem", moves[1][1])
        self.assertNotIn("own-ca.key", moves[0][1])

    def test_any_bytes_arrive_unchanged(self):
        # A PKCS#12 file must reach the proxy whole, for it to name the mistake.
        data = bytes(range(256)) * 8 + b"\r\n\r\r\n\n--" + BOUNDARY.encode()[:-1] + b"\r\n"
        self.upload(key=data)
        with open(os.path.join(store.TLS_DIR, "incoming", "own-ca.key"), "rb") as source:
            self.assertEqual(source.read(), data)

    def test_nothing_is_logged(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            self.assertEqual(self.upload()[0], 303)
            self.assertEqual(self.upload(token=b"wrong")[0], 403)
            self.upload(key=b"")
            self.post("/tls/own-ca", multipart(key=KEY)[:-20])
        self.assertEqual(output.getvalue(), "")
        self.assertNotIn(KEY.decode().splitlines()[1], json.dumps(list(store.activity)))

    def test_upload_is_in_the_activity_feed(self):
        self.upload()
        self.assertIn("own CA", store.activity[-1]["text"])

    def test_no_token_is_403(self):
        for parts in ({"chain": CHAIN, "key": KEY}, {"token": b"wrong", "chain": CHAIN, "key": KEY}, {"token": b"", "chain": CHAIN, "key": KEY}):
            self.assertEqual(self.post("/tls/own-ca", multipart(**parts))[0], 403, parts["key"])
        self.assertEqual(self.incoming(), [])

    def test_no_session_goes_to_login(self):
        status, location, _ = self.post("/tls/own-ca", multipart(token=self.token, chain=CHAIN, key=KEY), cookie="mikrokat_session=wrong")
        self.assertEqual((status, location), (303, "/login"))
        self.assertEqual(self.incoming(), [])

    def test_over_the_limit_is_an_error_page(self):
        body = multipart(token=self.token, chain=CHAIN, key=b"x" * OVER_LIMIT)
        status, _, text = self.post("/tls/own-ca", body)
        self.assertEqual(status, 200)
        self.assertIn("256 KiB", text)
        self.assertIn('class="note error"', text)
        self.assertEqual(self.incoming(), [])

    def test_a_file_too_big_for_the_socket_buffers_still_gets_its_page(self):
        # Closed unread, the connection resets, and a browser shows that instead of the reason.
        status, _, text = self.post("/tls/own-ca", b"x" * (8 * 1024 * 1024))
        self.assertEqual(status, 200)
        self.assertIn("256 KiB", text)

    def test_exactly_the_limit_is_taken(self):
        body = multipart(token=self.token, chain=CHAIN, key=b"x")
        padding = 256 * 1024 - len(body)
        body = multipart(token=self.token, chain=CHAIN, key=b"x" * (padding + 1))
        self.assertEqual(len(body), 256 * 1024)
        self.assertEqual(self.post("/tls/own-ca", body)[0], 303)

    def test_over_the_limit_without_a_session_goes_to_login(self):
        status, location, _ = self.post("/tls/own-ca", b"x" * OVER_LIMIT, cookie="")
        self.assertEqual((status, location), (303, "/login"))

    def test_bad_length_is_an_error_page(self):
        for length in ("", "abc", "-5", "9" * 5000):
            output = io.StringIO()
            with contextlib.redirect_stderr(output):
                status, _, text = self.post("/tls/own-ca", b"", length=length)
            self.assertEqual(status, 200, length)
            self.assertIn('class="note error"', text, length)
            self.assertNotIn("Traceback", output.getvalue())

    def test_malformed_body_is_an_error_page(self):
        good = multipart(token=self.token, chain=CHAIN, key=KEY)
        nested = b""
        for level in range(2000):  # past the recursion limit of the parser, and under the size limit
            nested += f'--b{level}\r\nContent-Type: multipart/mixed; boundary="b{level + 1}"\r\n\r\n'.encode()
        self.assertLess(len(nested), web.MAX_UPLOAD)
        for name, body, content_type in (("empty", b"", MULTIPART),
                                         ("no boundary", good, "multipart/form-data"),
                                         ("other boundary", good, "multipart/form-data; boundary=other"),
                                         ("not multipart", b"token=" + self.token, "application/x-www-form-urlencoded"),
                                         ("cut short", good[:-20], MULTIPART),
                                         ("no parts", f"--{BOUNDARY}--\r\n".encode(), MULTIPART),
                                         ("noise", bytes(range(256)) * 10, MULTIPART),
                                         ("nested too deep", nested, 'multipart/form-data; boundary="b0"'),
                                         ("bad header", good, "multipart/form-data; boundary=\"unclosed"),
                                         ("not ascii", good, "multipart/form-data; boundary=é")):
            output = io.StringIO()
            with contextlib.redirect_stderr(output):
                status, _, text = self.post("/tls/own-ca", body, content_type.encode("latin-1").decode("latin-1"))
            self.assertEqual(status, 200, name)
            self.assertIn('class="note error"', text, name)
            self.assertNotIn("Traceback", output.getvalue(), name)
        self.assertEqual(self.incoming(), [])

    def test_a_file_is_missing(self):
        for parts in ({"chain": CHAIN}, {"key": KEY}, {"chain": CHAIN, "key": b""}, {"chain": b"", "key": KEY}):
            status, _, text = self.post("/tls/own-ca", multipart(token=self.token, **parts))
            self.assertEqual(status, 200)
            self.assertIn("both", text)
        self.assertEqual(self.incoming(), [])

    def test_nothing_stays_when_the_second_write_fails(self):
        real = os.replace

        def replace(source, target):
            if target.endswith("own-ca.pem"):
                raise OSError("disk full")
            real(source, target)

        with mock.patch.object(store.os, "replace", replace), contextlib.redirect_stdout(io.StringIO()):
            status, _, text = self.upload()
        self.assertEqual(status, 200)
        self.assertIn('class="note error"', text)
        self.assertEqual(self.incoming(), [])

    def test_no_folder_is_an_error_page(self):
        os.rmdir(os.path.join(store.TLS_DIR, "incoming"))
        with contextlib.redirect_stdout(io.StringIO()):
            status, _, text = self.upload()
        self.assertEqual(status, 200)
        self.assertIn('class="note error"', text)


class OwnCaRemove(Web):
    def form(self, token=None):
        return f"token={web.csrf_token if token is None else token}".encode(), "application/x-www-form-urlencoded"

    def test_asks_the_proxy(self):
        status, location, _ = self.post("/tls/own-ca/remove", *self.form())
        self.assertEqual((status, location), (303, "/settings?ok=ca-removed&tab=https"))
        self.assertEqual(self.incoming(), ["remove-own-ca"])
        self.assertIn("generated CA", web.NOTICES["ca-removed"])

    def test_no_token_is_403(self):
        self.assertEqual(self.post("/tls/own-ca/remove", *self.form("wrong"))[0], 403)
        self.assertEqual(self.incoming(), [])

    def test_no_session_goes_to_login(self):
        body, content_type = self.form()
        self.assertEqual(self.post("/tls/own-ca/remove", body, content_type, cookie="")[1], "/login")
        self.assertEqual(self.incoming(), [])

    def test_no_folder_is_an_error_page(self):
        os.rmdir(os.path.join(store.TLS_DIR, "incoming"))
        with contextlib.redirect_stdout(io.StringIO()):
            status, _, text = self.post("/tls/own-ca/remove", *self.form())
        self.assertEqual(status, 200)
        self.assertIn('class="note error"', text)

    def test_regenerate_is_refused_while_an_own_ca_is_in_use(self):
        # A page opened before the upload still has the button. Taken later, the
        # request would replace the generated CA when the owner goes back to it.
        self.stats(ca_own=True, ca_subject="CN=Own", ca_chain=1)
        status, _, text = self.post("/tls/regenerate", *self.form())
        self.assertEqual(status, 200)
        self.assertIn('class="note error"', text)
        self.assertEqual(store.settings["tls_ca_generation"], 0)

    def test_regenerate_still_works_without_one(self):
        self.stats(ca_own=False)
        self.assertEqual(self.post("/tls/regenerate", *self.form())[1], "/settings?ok=ca-regenerated&tab=https")
        self.assertEqual(store.settings["tls_ca_generation"], 1)


class Forms(html.parser.HTMLParser):
    """What the browser would make of the page: which control belongs to which form."""

    def __init__(self):
        super().__init__()
        self.forms, self.open, self.controls, self.nested = {}, [], [], False

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self.nested = self.nested or bool(self.open)
            key = a.get("id") or a.get("action")
            self.forms[key] = a
            self.open.append(key)
        elif tag in ("input", "button"):
            self.controls.append({**a, "tag": tag, "owner": a.get("form") or (self.open[-1] if self.open else None)})

    def handle_endtag(self, tag):
        if tag == "form":
            self.open.pop()


class OwnCaTab(Web):
    def page(self):
        return web.settings_page("mikrokat.lan:8088", tab="https")

    def forms(self):
        parser = Forms()
        parser.feed(self.page())
        return parser

    def test_upload_form_stands_alone(self):
        parser = self.forms()
        self.assertFalse(parser.nested)
        form = next((f for f in parser.forms.values() if f.get("action") == "/tls/own-ca"), None)
        self.assertIsNotNone(form)
        self.assertEqual(form["method"], "post")
        self.assertEqual(form["enctype"], "multipart/form-data")
        owner = form["id"]
        mine = [c for c in parser.controls if c["owner"] == owner]
        self.assertEqual(sorted(c["name"] for c in mine if c.get("type") == "file"), ["chain", "key"])
        self.assertTrue(any(c.get("name") == "token" and c.get("value") == web.csrf_token for c in mine))
        self.assertTrue(any(c["tag"] == "button" for c in mine))
        self.assertFalse([c for c in parser.controls if c.get("type") == "file" and c["owner"] != owner])

    def test_upload_is_off_while_the_proxy_is_silent(self):
        for values in ({"at": 1}, {"at": "soon"}):
            self.stats(**values)
            page = self.page()
            self.assertIn("The proxy is not running", page)
            parser = self.forms()
            mine = [c for c in parser.controls if c.get("name") in ("chain", "key") or (c["tag"] == "button" and c.get("form") == "own-ca")]
            self.assertTrue(mine)
            self.assertTrue(all("disabled" in c for c in mine), mine)

    def test_upload_is_on_while_the_proxy_runs(self):
        self.stats(ca_own=False)
        page = self.page()
        self.assertNotIn("The proxy is not running", page)
        self.assertTrue(all("disabled" not in c for c in self.forms().controls if c.get("name") in ("chain", "key")))

    def test_warns_that_the_key_crosses_the_network(self):
        page = self.page()
        self.assertIn("plain HTTP unless you reached it through HTTPS", page)
        self.assertIn("the private key crosses the network unencrypted", page)
        self.assertIn("Upload only from a trusted network", page)

    def test_generated_ca(self):
        self.stats(ca_own=False, ca_subject="CN=Mikrokat local CA", ca_chain=1, ca_expires=1893456000)
        page = self.page()
        self.assertIn("CN=Mikrokat local CA", page)
        self.assertIn("/tls/regenerate", page)
        self.assertNotIn("/tls/own-ca/remove", page)

    def test_own_ca(self):
        self.stats(ca_own=True, ca_subject="CN=Own CA", ca_chain=3, ca_expires=1893456000, listening=True, error="")
        page = self.page()
        self.assertIn("CN=Own CA", page)
        self.assertIn(web.time.strftime("%Y-%m-%d", web.time.localtime(1893456000)), page)
        self.assertNotIn("/tls/regenerate", page)
        self.assertIn("Regenerate does not apply", page)
        self.assertIn('href="/tls/ca.pem"', page)

    def test_stop_button(self):
        self.stats(ca_own=True, ca_subject="CN=Own CA", ca_chain=1, ca_expires=1893456000)
        parser = self.forms()
        button = next(c for c in parser.controls if c.get("formaction") == "/tls/own-ca/remove")
        self.assertIn("confirm(", button["onclick"])
        self.assertIn("generated CA", button["onclick"])
        self.assertIn("Stop using my CA", self.page())
        self.assertTrue(any(c.get("name") == "token" and c["owner"] == button["owner"] for c in parser.controls))

    def test_own_ca_that_cannot_load(self):
        self.stats(ca_own=True, ca_subject="", ca_chain=0, ca_expires=0, listening=False, error="CA failed: own CA: the first certificate has expired")
        page = self.page()
        self.assertIn("the first certificate has expired", page)
        self.assertIn("/tls/own-ca/remove", page)
        self.assertNotIn("/tls/regenerate", page)

    def test_refused_upload(self):
        self.stats(ca_own=False, ca_import_error="the key does not match the first certificate")
        self.assertIn("the key does not match the first certificate", self.page())

    def test_strings_from_the_file_are_escaped(self):
        self.stats(ca_own=True, ca_subject="CN=<img src=x onerror=alert(1)>", ca_chain=1, ca_expires=1893456000,
                   ca_import_error="<script>alert(2)</script>", error="<script>alert(3)</script>")
        page = self.page()
        self.assertNotIn("<img src=x", page)
        self.assertNotIn("<script>alert(2)", page)
        self.assertIn("CN=&lt;img src=x", page)
        self.assertIn("&lt;script&gt;alert(2)", page)
        self.stats(ca_own=True, ca_subject="", ca_chain=0, error="<script>alert(3)</script>")
        page = self.page()
        self.assertNotIn("<script>alert(3)", page)
        self.assertIn("&lt;script&gt;alert(3)", page)

    def test_odd_values_do_not_break_the_page(self):
        self.stats(ca_own="yes", ca_subject=["x"], ca_chain="many", ca_expires="soon", ca_import_error=5)
        self.assertIn("HTTPS inspection", self.page())


class Upload(Base):
    def test_parser_needs_no_session(self):
        self.assertEqual(web.parse_upload(MULTIPART, multipart(token=b"t", key=KEY)), {"token": b"t", "key": KEY})

    def test_parser_says_none_for_anything_else(self):
        self.assertIsNone(web.parse_upload("text/plain", b"x"))
        self.assertIsNone(web.parse_upload(MULTIPART, b"x"))


class Socket(Web):
    def test_a_huge_declared_length_gets_an_answer(self):
        # The body stops early and the client waits, so the answer must not need all of it.
        with socket.create_connection(self.server.server_address, timeout=20) as client:
            client.sendall(f"POST /tls/own-ca HTTP/1.1\r\nHost: x\r\nCookie: {self.cookie}\r\nContent-Length: {2**40}\r\n\r\n".encode())
            client.sendall(b"x" * 1024)
            client.shutdown(socket.SHUT_WR)
            reply = client.makefile("rb").read()
        self.assertIn(b'class="note error"', reply)

class Tabs(unittest.TestCase):
    def test_every_tab_has_a_rule_that_shows_it(self):
        for key, _ in web.SETTINGS_TABS:
            self.assertIn(f"#tab-{key}:checked ~ #pane-{key}", web.STYLE)
            self.assertIn(f"#tab-{key}:checked ~ .tabbar label[for=tab-{key}]", web.STYLE)


if __name__ == "__main__":
    unittest.main()
