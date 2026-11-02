import http.client
import subprocess
import sys
import threading
import unittest

sys.path.insert(0, "/app")
import health  # noqa: E402
import store  # noqa: E402
import web  # noqa: E402
from test_tls_connections import Conn  # noqa: E402
from test_tls_settings import full_form  # noqa: E402


class Server(Conn):
    def setUp(self):
        super().setUp()
        self.server = web.ThreadingHTTPServer(("127.0.0.1", 0), web.Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def send(self, method, path, cookie=None, body=b""):
        client = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=20)
        self.addCleanup(client.close)
        client.putrequest(method, path)
        if cookie:
            client.putheader("Cookie", cookie)
        client.putheader("Content-Length", str(len(body)))
        client.endheaders()
        client.send(body)
        reply = client.getresponse()
        return reply.status, reply.getheader("Location"), reply.read().decode()

    def get(self, path, cookie=None):
        return self.send("GET", path, cookie)


class Off(Server):
    """The HTTPS inspection profile is not on: COMPOSE_PROFILES does not hold https."""

    def setUp(self):
        super().setUp()
        store.tls_available = False
        self.cookie = f"{web.SESSION_COOKIE}={web.new_session()}"

    def test_the_environment_decides(self):
        for value, expected in (("", False), ("https", True), ("a, https", True), ("httpsx", False), ("other", False)):
            run = subprocess.run([sys.executable, "-I", "-c", "import sys; sys.path.insert(0, '/app'); import store; print(store.tls_available)"],
                                 env={"COMPOSE_PROFILES": value, "DATA_DIR": self.dir.name}, capture_output=True, text=True, check=True)
            self.assertEqual(run.stdout.strip(), str(expected), value)

    def test_no_tab_and_no_guide_block(self):
        page = web.settings_page("mikrokat.lan:8088")
        self.assertNotIn('id="pane-https"', page)
        self.assertNotIn('guide-block guide-https', page)
        self.assertNotIn('id="tab-https"', page)
        self.assertNotIn(">HTTPS inspection<", page)
        self.assertNotIn('name="tls_devices"', page)
        self.assertIn('id="pane-account"', page)

    def test_the_https_tab_name_falls_back_to_the_first(self):
        page = web.settings_page("mikrokat.lan:8088", tab="https")
        self.assertRegex(page, r'id="tab-protection" value="protection" checked')

    def test_no_menu_item_and_no_tile_even_with_the_setting_on(self):
        store.settings["tls_enabled"] = True
        self.assertEqual(web.overview_tile(), "")
        self.assertNotIn('href="/connections"', web.overview_page("mikrokat.lan:8088"))

    def test_the_connections_page_says_how_to_enable_it(self):
        status, _, body = self.get("/connections", self.cookie)
        self.assertEqual(status, 200)
        self.assertIn("COMPOSE_PROFILES=https", body)
        self.assertNotIn("Recent connections", body)

    def test_the_connections_page_still_needs_a_login(self):
        self.assertEqual(self.get("/connections")[:2], (303, "/login"))

    def test_tls_routes_answer_404(self):
        for path in ("/tls/ca.pem", "/tls/own-ca.csr", "/tls/own-ca.ext"):
            self.assertEqual(self.get(path, self.cookie)[0], 404, path)
            self.assertEqual(self.get(path)[0], 404, path)

    def test_tls_posts_answer_404(self):
        for path in ("/tls/regenerate", "/tls/log/delete", "/tls/bypass/remove", "/tls/own-ca/remove"):
            self.assertEqual(self.send("POST", path, self.cookie, ("token=" + web.csrf_token).encode())[0], 404, path)
            self.assertEqual(self.send("POST", path)[0], 404, path)

    def test_the_pac_file_answers_direct(self):
        store.settings.update(tls_enabled=True, tls_socks=True, tls_devices=["10.0.0.5"])
        self.assertNotIn("SOCKS", web.pac_text("mikrokat.lan:8088"))

    def test_the_health_alarm_stays_quiet(self):
        store.settings["tls_enabled"] = True
        self.assertIsNone(health.tls_problem())
        self.assertIsNone(health.ca_problem())

    def test_saving_leaves_the_tls_settings_alone(self):
        store.settings.update(tls_enabled=True, tls_devices=["10.0.0.5"], tls_bypass=["a.example"], tls_socks_port=1999, tls_log=False, tls_bank_list=False)
        self.assertFalse(store.save_settings(full_form(tls_enabled="", tls_devices="", tls_bypass="", tls_socks_port="")))
        s = store.settings
        self.assertEqual((s["tls_enabled"], s["tls_devices"], s["tls_bypass"], s["tls_socks_port"], s["tls_log"], s["tls_bank_list"]),
                         (True, ["10.0.0.5"], ["a.example"], 1999, False, False))

    def test_saving_does_not_check_the_tls_fields(self):
        self.assertFalse(store.save_settings(full_form(tls_devices="not an ip", tls_socks_port="x")))


class On(Server):
    def test_the_tab_is_there(self):
        page = web.settings_page("mikrokat.lan:8088")
        self.assertIn('id="pane-https"', page)
        self.assertIn('guide-block guide-https', page)

    def test_the_tab_name_is_kept(self):
        self.assertRegex(web.settings_page("mikrokat.lan:8088", tab="https"), r'id="tab-https" value="https" checked')


if __name__ == "__main__":
    unittest.main()
