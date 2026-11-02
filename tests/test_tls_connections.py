import http.client
import json
import os
import re
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, "/app")
import store  # noqa: E402
import web  # noqa: E402
from test_tls_settings import Base, full_form  # noqa: E402

HOST = "mikrokat.lan:8088"


def line(name="site.example", device="10.0.0.5", action="inspected", reason="", up=100, down=900, at=None, ip="198.51.100.7", port=443, ms=20):
    return {"at": int(time.time()) if at is None else at, "device": device, "name": name, "ip": ip, "port": port,
            "action": action, "reason": reason, "up": up, "down": down, "ms": ms}


class Conn(Base):
    """A Base with a database of its own and a connection log to write into."""

    def setUp(self):
        super().setUp()
        self.old_db = store.DATABASE
        store.DATABASE = os.path.join(self.dir.name, "stats.db")
        store.create_tables()
        self.path = os.path.join(store.TLS_DIR, "state", "connections.jsonl")
        self.addCleanup(setattr, store, "DATABASE", self.old_db)
        self.saved_names = dict(store.names)
        self.addCleanup(lambda: (store.names.clear(), store.names.update(self.saved_names)))

    def write(self, *records, path=None, raw=None, mode="a"):
        with open(path or self.path, mode, encoding="utf-8") as target:
            for record in records:
                target.write((json.dumps(record) if isinstance(record, dict) else record) + "\n")
            if raw:
                target.write(raw)

    def rows(self, table):
        with store.database() as db:
            return sorted(db.execute(f"SELECT * FROM {table}").fetchall())

    def total(self, table, column):
        with store.database() as db:
            return db.execute(f"SELECT COALESCE(SUM({column}), 0) FROM {table}").fetchone()[0]


class Settings(Base):
    def test_log_is_on_by_default(self):
        self.assertIs(store.settings["tls_log"], True)

    def test_control_file_carries_it(self):
        store.settings["tls_log"] = True
        store.write_tls_control()
        self.assertIs(self.control()["log_connections"], True)
        store.settings["tls_log"] = False
        store.write_tls_control()
        self.assertIs(self.control()["log_connections"], False)

    def test_the_switch_is_saved(self):
        self.assertIsNone(store.save_settings(full_form(tls_log="on")))
        self.assertIs(store.settings["tls_log"], True)
        self.assertIs(self.control()["log_connections"], True)
        self.assertIsNone(store.save_settings(full_form()))
        self.assertIs(store.settings["tls_log"], False)
        self.assertIs(self.control()["log_connections"], False)

    def test_the_tab_has_the_switch_and_the_consent_note(self):
        page = web.settings_page(HOST, tab="https")
        self.assertIn('name="tls_log" checked', page)
        self.assertIn("Keep a log of connections", page)
        self.assertIn("which sites each listed device visited", page)
        self.assertIn("no URLs or content", page)
        self.assertIn('href="/connections"', page)
        store.settings["tls_log"] = False
        self.assertNotIn('name="tls_log" checked', web.settings_page(HOST, tab="https"))


class Reading(Conn):
    def test_counts_by_hour_device_action_and_reason(self):
        at = int(time.time())
        self.write(line(at=at), line(at=at, up=1, down=2), line(action="relayed", reason="bypass", name="bank.example", up=10, down=20, at=at),
                   line(action="refused", reason="not_listed", device="10.0.0.99", name="", up=0, down=0, at=at))
        self.assertEqual(store.read_connections(), 4)
        hour = time.strftime("%Y-%m-%d %H", time.localtime(at))
        self.assertEqual(self.rows("hourly_conn"), [
            (hour, "(refused)", "refused", "not_listed", 1, 0),
            (hour, "10.0.0.5", "inspected", "", 2, 1003),
            (hour, "10.0.0.5", "relayed", "bypass", 1, 30)])
        self.assertEqual(self.rows("hourly_sites"), [
            (hour, "10.0.0.5", "bank.example", 1, 30),
            (hour, "10.0.0.5", "site.example", 2, 1003)])

    def test_new_lines_only(self):
        self.write(line())
        store.read_connections()
        self.assertEqual(store.read_connections(), 0)
        self.write(line(), line())
        self.assertEqual(store.read_connections(), 2)
        self.assertEqual(self.total("hourly_conn", "count"), 3)

    def test_a_restart_does_not_count_again(self):
        self.write(line(), line())
        store.read_connections()
        store.read_connections()  # a new process starts from what the database says
        self.assertEqual(self.total("hourly_conn", "count"), 2)

    def test_a_half_written_line_waits(self):
        self.write(line(), raw=json.dumps(line(name="half.example"))[:30])
        self.assertEqual(store.read_connections(), 1)
        with open(self.path, "a") as target:
            target.write(json.dumps(line(name="half.example"))[30:] + "\n")
        self.assertEqual(store.read_connections(), 1)
        self.assertIn("half.example", [r[2] for r in self.rows("hourly_sites")])

    def test_bad_lines_are_skipped(self):
        self.write("not json", "[1, 2]", '{"at": "x"}', json.dumps(line(action="deleted")), json.dumps({**line(), "up": -5}),
                   json.dumps({**line(), "device": 7}), "", line(name="good.example"))
        self.assertEqual(store.read_connections(), 1)
        self.assertEqual([r[2] for r in self.rows("hourly_sites")], ["good.example"])

    def test_a_missing_file_is_nothing(self):
        self.assertEqual(store.read_connections(), 0)

    def test_rotation_loses_nothing_and_counts_nothing_twice(self):
        self.write(line(name="a.example"))
        store.read_connections()
        self.write(line(name="b.example"))  # the proxy wrote this, then rotated before we looked
        os.rename(self.path, self.path + ".1")
        self.write(line(name="c.example"), mode="w")
        self.assertEqual(store.read_connections(), 2)
        self.assertEqual(sorted(r[2] for r in self.rows("hourly_sites")), ["a.example", "b.example", "c.example"])
        self.assertEqual(store.read_connections(), 0)
        self.write(line(name="d.example"))
        self.assertEqual(store.read_connections(), 1)

    def test_rotation_twice_between_looks_reads_the_new_file_only(self):
        self.write(line(name="a.example"))
        store.read_connections()
        self.write(line(name="lost.example"))
        os.rename(self.path, self.path + ".1")
        self.write(line(name="x.example"), mode="w")
        os.rename(self.path, self.path + ".1")  # the backup is replaced: lost.example is gone
        self.write(line(name="y.example"), mode="w")
        self.assertEqual(store.read_connections(), 2)
        self.assertEqual(sorted(r[2] for r in self.rows("hourly_sites")), ["a.example", "x.example", "y.example"])

    def test_a_file_deleted_does_not_bring_back_the_backup(self):
        self.write(line(name="a.example"))
        store.read_connections()
        os.rename(self.path, self.path + ".1")
        self.write(line(name="b.example"), mode="w")
        store.read_connections()
        os.remove(self.path)  # the owner cleans up, and the proxy starts a new file
        self.write(line(name="c.example"), mode="w")
        self.assertEqual(store.read_connections(), 1)
        self.assertEqual(sorted(r[2] for r in self.rows("hourly_sites")), ["a.example", "b.example", "c.example"])

    def test_a_first_look_reads_the_backup_too(self):
        self.write(line(name="old.example"), path=self.path + ".1")
        self.write(line(name="new.example"))
        self.assertEqual(store.read_connections(), 2)

    def test_a_cut_file_starts_again(self):
        self.write(line(name="a.example"), line(name="b.example"))
        store.read_connections()
        self.write(line(name="c.example"), mode="w")
        self.assertEqual(store.read_connections(), 1)

    def test_lines_older_than_the_retention_are_not_stored(self):
        self.write(line(at=int(time.time()) - 8 * 86400), line())
        self.assertEqual(store.read_connections(), 1)

    def test_sites_keep_the_200_biggest_of_an_hour(self):
        self.write(*[line(name=f"s{n:03d}.example", down=1000 + n) for n in range(260)])
        store.read_connections()
        rows = self.rows("hourly_sites")
        self.assertEqual(len(rows), 200)
        self.assertNotIn("s000.example", [r[2] for r in rows])
        self.assertIn("s259.example", [r[2] for r in rows])
        self.assertEqual(self.total("hourly_conn", "count"), 260)  # the totals keep every connection

    def test_a_name_is_kept_short(self):
        self.write(line(name="x" * 1000))
        store.read_connections()
        self.assertLessEqual(len(self.rows("hourly_sites")[0][2]), 253)

    def test_old_databases_get_the_tables(self):
        with store.database() as db:
            db.executescript("DROP TABLE hourly_conn; DROP TABLE hourly_sites; DROP TABLE hourly_decrypted_alerts;")
        store.create_tables()
        self.assertEqual(self.rows("hourly_conn"), [])

    def test_retention_is_seven_days(self):
        old = time.strftime("%Y-%m-%d %H", time.localtime(time.time() - 8 * 86400))
        new = time.strftime("%Y-%m-%d %H")
        with store.database() as db:
            for table, values in (("hourly_conn", "'{h}', 'd', 'inspected', '', 1, 1"), ("hourly_sites", "'{h}', 'd', 'n', 1, 1"), ("hourly_decrypted_alerts", "'{h}', 1")):
                for h in (old, new):
                    db.execute(f"INSERT INTO {table} VALUES ({values.format(h=h)})")
        store.prune()
        for table in ("hourly_conn", "hourly_sites", "hourly_decrypted_alerts"):
            self.assertEqual([r[0] for r in self.rows(table)], [new], table)


class Flood(Conn):
    def test_refused_sources_collapse_into_one_row(self):
        at = int(time.time())
        self.write(*[line(action="refused", reason="not_listed", device=f"10.1.{i // 250}.{i % 250}", name="", up=0, down=0, at=at) for i in range(600)],
                   line(action="refused", reason="cap", device="10.9.9.9", name="", up=0, down=0, at=at))
        store.read_connections()
        hour = time.strftime("%Y-%m-%d %H", time.localtime(at))
        self.assertEqual(self.rows("hourly_conn"), [(hour, "(refused)", "refused", "cap", 1, 0), (hour, "(refused)", "refused", "not_listed", 600, 0)])

    def test_the_recent_list_keeps_the_real_source(self):
        self.write(line(action="refused", reason="not_listed", device="10.9.9.9", name="", up=0, down=0))
        store.read_connections()
        self.assertEqual([r["device"] for r in store.conn_recent()], ["10.9.9.9"])

    def test_devices_seen_leaves_out_refused_and_stops_at_100(self):
        at = int(time.time())
        self.write(*[line(device=f"10.2.0.{i}", at=at) for i in range(150)], line(action="refused", reason="cap", device="10.9.9.9", name="", at=at))
        store.read_connections()
        seen = store.conn_devices_seen()
        self.assertEqual(len(seen), 100)
        self.assertNotIn("10.9.9.9", seen)
        self.assertNotIn("(refused)", seen)


class DecryptedAlerts(Conn):
    def test_each_alert_counts_once(self):
        store.pending_decrypted_alerts.clear()
        decrypted = {"src_ip": "10.0.0.5", "dest_ip": "198.51.100.7", "vlan": [3900], "alert": {"severity": 1, "signature_id": 9}}
        store.count_alert(decrypted, "198.51.100.7")
        store.count_alert(decrypted, "198.51.100.7")
        store.count_alert({**decrypted, "vlan": [10]}, "198.51.100.7")
        store.flush()
        self.assertEqual(store.decrypted_alerts(), 2)
        self.assertEqual(store.decrypted_count("10.0.0.5"), 2)  # both ends stay as they were
        self.assertEqual(self.total("hourly_decrypted", "count"), 4)


class Queries(Conn):
    def fill(self):
        self.write(line(name="a.example", device="10.0.0.5", down=5000), line(name="a.example", device="10.0.0.5", down=5000),
                   line(name="b.example", device="10.0.0.6", down=100, action="relayed", reason="bypass"),
                   line(name="c.example", device="10.0.0.6", down=100, action="relayed", reason="auto_bypass"),
                   line(name="", device="10.0.0.7", action="refused", reason="not_listed", up=0, down=0))
        store.read_connections()

    def test_hourly_has_24_rows_with_two_series(self):
        self.fill()
        rows = store.conn_hourly()
        self.assertEqual(len(rows), 24)
        self.assertEqual((rows[-1][1], rows[-1][2]), (2, 2))  # inspected, passed
        self.assertEqual(sum(r[1] + r[2] for r in rows), 4)

    def test_totals(self):
        self.fill()
        t = store.conn_totals(1)
        self.assertEqual((t["inspected"], t["relayed"], t["refused"], t["bytes"]), (2, 2, 1, 10000 + 200 + 400))

    def test_reasons(self):
        self.fill()
        self.assertEqual(sorted((r[0], r[1], r[2]) for r in store.conn_reasons()),
                         [("refused", "not_listed", 1), ("relayed", "auto_bypass", 1), ("relayed", "bypass", 1)])

    def test_top_sites_by_count_and_by_data(self):
        self.fill()
        self.assertEqual(store.conn_sites("count")[0][0:2], ("a.example", 2))
        self.assertEqual(store.conn_sites("bytes")[0][2], 10200)

    def test_devices(self):
        self.fill()
        self.assertEqual(store.conn_devices()[0][0:2], ("10.0.0.5", 10200))

    def test_only_the_last_24_hours_in_the_tables(self):
        old = time.strftime("%Y-%m-%d %H", time.localtime(time.time() - 3 * 86400))
        with store.database() as db:
            db.execute("INSERT INTO hourly_conn VALUES (?, 'd', 'inspected', '', 7, 700)", (old,))
        self.assertEqual(store.conn_totals(1)["inspected"], 0)
        self.assertEqual(store.conn_totals(7)["inspected"], 7)

    def test_recent_newest_first_and_filters(self):
        now = int(time.time())
        self.write(line(name="a.example", device="10.0.0.5", at=now - 30), line(name="b.example", device="10.0.0.6", at=now - 20),
                   line(name="A2.example", device="10.0.0.5", at=now - 10))
        names = [r["name"] for r in store.conn_recent()]
        self.assertEqual(names, ["A2.example", "b.example", "a.example"])
        self.assertEqual([r["name"] for r in store.conn_recent(device="10.0.0.5")], ["A2.example", "a.example"])
        self.assertEqual([r["name"] for r in store.conn_recent(site="a2")], ["A2.example"])
        self.assertEqual([r["name"] for r in store.conn_recent(site="B.EXAMPLE")], ["b.example"])
        self.assertEqual(store.conn_recent(device="10.0.0.5", site="b"), [])

    def test_recent_is_200_at_most_and_skips_bad_lines(self):
        self.write("garbage", *[line(name=f"s{n}.example", at=int(time.time()) + n) for n in range(300)], raw='{"at": 1')
        recent = store.conn_recent()
        self.assertEqual(len(recent), 200)
        self.assertEqual(recent[0]["name"], "s299.example")

    def test_recent_goes_back_into_the_backup(self):
        self.write(line(name="old.example"), path=self.path + ".1")
        self.write(line(name="new.example"))
        self.assertEqual([r["name"] for r in store.conn_recent()], ["new.example", "old.example"])

    def test_recent_without_a_file(self):
        self.assertEqual(store.conn_recent(), [])


class Page(Conn):
    def setUp(self):
        super().setUp()
        store.settings.update(tls_enabled=True, tls_devices=["10.0.0.5"])
        with open(os.path.join(store.TLS_DIR, "state", "stats.json"), "w") as target:
            json.dump({"at": int(time.time()), "auto_bypass": [{"device": "10.0.0.5", "name": "pinned.example", "until": int(time.time()) + 600}]}, target)

    def fill(self):
        self.write(line(name="a.example", device="10.0.0.5", down=5000), line(name="b.example", device="10.0.0.6", action="relayed", reason="bypass"),
                   line(name="", device="10.0.0.7", action="refused", reason="not_listed", up=0, down=0))
        store.read_connections()
        store.names["10.0.0.5"] = "laptop"

    def page(self, **query):
        return web.connections_page(HOST, query={k: [v] for k, v in query.items()})

    def test_with_data(self):
        self.fill()
        page = self.page()
        for text in ("Connections", "Inspected", "Passed", "a.example", "b.example", "laptop", "Name on the skip list", "Not on the device list",
                     "pinned.example", "7 days", "Data through the proxy", "Alerts on decrypted traffic"):
            self.assertIn(text, page)
        self.assertIn('href="/host?ip=10.0.0.5"', page)
        self.assertNotIn("Nothing has passed", page)

    def test_the_chart_has_two_series_a_legend_and_bars(self):
        self.fill()
        page = self.page()
        self.assertIn("bar-1", page)
        self.assertIn("bar-2", page)
        self.assertRegex(page, r'class="legend".*Inspected.*Passed')
        self.assertEqual(len(re.findall(r'<path class="bar-[12]"', page)), 2)

    def test_empty_state(self):
        page = self.page()
        self.assertIn("Nothing has passed through the proxy in the last 24 hours", page)
        self.assertIn("Keep a log of connections", page)
        self.assertIn("/settings?tab=https", page)

    def test_the_log_switch_off_is_said(self):
        store.settings["tls_log"] = False
        self.assertIn("The log is off", self.page())

    def test_filters(self):
        now = int(time.time())
        self.write(line(name="a.example", device="10.0.0.5", at=now), line(name="b.example", device="10.0.0.6", at=now))
        recent = lambda page: page[page.index("Recent connections"):]
        self.assertIn("b.example", recent(self.page(device="10.0.0.6")))
        self.assertNotIn("a.example", recent(self.page(device="10.0.0.6")))
        self.assertNotIn("b.example", recent(self.page(site="A.exam")))
        self.assertIn("a.example", recent(self.page(site="A.exam")))
        self.assertIn("Nothing matches", self.page(site="nothing-like-this"))

    def test_the_filter_is_kept_in_the_form(self):
        self.write(line())
        page = self.page(site='"><script>alert(1)</script>')
        self.assertNotIn("<script>alert(1)", page)
        self.assertIn("&quot;&gt;&lt;script&gt;", page)

    def test_everything_from_traffic_is_escaped(self):
        evil = '<img src=x onerror=alert(1)>'
        self.write(line(name=evil, device=evil, action="relayed", reason=evil), line(name=evil, device="10.0.0.5", ip=evil, port=443))
        store.read_connections()
        with open(os.path.join(store.TLS_DIR, "state", "stats.json"), "w") as target:
            json.dump({"at": int(time.time()), "auto_bypass": [{"device": evil, "name": evil, "until": evil}]}, target)
        page = self.page()
        self.assertNotIn("<img", page)
        self.assertIn("&lt;img src=x", page)

    def test_refused_rows_show_the_source(self):
        self.fill()
        page = self.page()
        recent = page[page.index("Recent connections"):]
        self.assertIn("10.0.0.7", recent)
        self.assertIn("Refused", recent)

    def test_the_nav_item_follows_the_switch(self):
        self.assertIn('href="/connections"', web.layout("/", "x", "", HOST))
        store.settings["tls_enabled"] = False
        self.assertNotIn('/connections', web.layout("/", "x", "", HOST))

    def test_the_overview_tile_follows_the_switch(self):
        self.fill()
        tile = web.overview_tile()
        self.assertIn('href="/connections"', tile)
        self.assertIn("Decrypted, 24h", tile)
        self.assertIn(">1<", tile)
        store.settings["tls_enabled"] = False
        self.assertEqual(web.overview_tile(), "")

    def test_the_guide_says_what_the_page_does_not_show(self):
        self.assertIn("never URLs", web.GUIDE["https"])
        self.assertIn("10 MiB", web.GUIDE["https"])


class Http(Conn):
    def setUp(self):
        super().setUp()
        self.server = web.ThreadingHTTPServer(("127.0.0.1", 0), web.Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def get(self, path, cookie=None):
        client = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=20)
        self.addCleanup(client.close)
        client.putrequest("GET", path)
        if cookie:
            client.putheader("Cookie", cookie)
        client.endheaders()
        reply = client.getresponse()
        return reply.status, reply.getheader("Location"), reply.read().decode()

    def test_login_is_required(self):
        status, location, _ = self.get("/connections")
        self.assertEqual((status, location), (303, "/login"))

    def test_a_session_gets_the_page_and_the_filters_work(self):
        self.write(line(name="a.example"), line(name="b.example"))
        cookie = f"{web.SESSION_COOKIE}={web.new_session()}"
        status, _, body = self.get("/connections?site=b.exa", cookie)
        self.assertEqual(status, 200)
        recent = body[body.index("Recent connections"):]
        self.assertIn("b.example", recent)
        self.assertNotIn("a.example", recent)


class DeleteLog(Http):
    def post(self, path, fields, cookie=True):
        body = "&".join(f"{k}={v}" for k, v in fields.items()).encode()
        client = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=20)
        self.addCleanup(client.close)
        client.putrequest("POST", path)
        client.putheader("Content-Type", "application/x-www-form-urlencoded")
        client.putheader("Content-Length", str(len(body)))
        if cookie:
            client.putheader("Cookie", f"{web.SESSION_COOKIE}={self.session}")
        client.endheaders()
        client.send(body)
        reply = client.getresponse()
        return reply.status, reply.getheader("Location"), reply.read().decode()

    def setUp(self):
        super().setUp()
        self.session = web.new_session()
        self.marker = os.path.join(store.TLS_DIR, "incoming", "delete-conn-log")
        self.write(line(), line(name="b.example"))
        store.read_connections()
        self.assertTrue(self.total("hourly_conn", "count"))

    def test_the_button_is_on_the_tab_with_a_confirmation(self):
        page = web.settings_page("mikrokat.lan:8088", "", "", "https")
        self.assertIn('formaction="/tls/log/delete"', page)
        self.assertRegex(page, r'formaction="/tls/log/delete"[^>]*confirm\(')

    def test_delete_asks_the_proxy_and_empties_the_tables(self):
        status, location, _ = self.post("/tls/log/delete", {"token": web.csrf_token})
        self.assertEqual((status, location), (303, "/settings?ok=log-deleted&tab=https"))
        self.assertTrue(os.path.exists(self.marker))
        for table in ("hourly_conn", "hourly_sites"):
            self.assertEqual(self.rows(table), [], table)

    def test_without_the_token_nothing_happens(self):
        for fields in ({}, {"token": "wrong"}):
            self.assertEqual(self.post("/tls/log/delete", fields)[0], 403)
        self.assertFalse(os.path.exists(self.marker))
        self.assertTrue(self.rows("hourly_conn"))

    def test_without_a_session_nothing_happens(self):
        status, location, _ = self.post("/tls/log/delete", {"token": web.csrf_token}, cookie=False)
        self.assertEqual((status, location), (303, "/login"))
        self.assertFalse(os.path.exists(self.marker))
        self.assertTrue(self.rows("hourly_conn"))

    def test_lines_still_in_the_old_file_are_not_counted_again(self):
        self.post("/tls/log/delete", {"token": web.csrf_token})
        self.assertEqual(store.read_connections(), 0)  # the proxy has not removed the file yet
        self.assertEqual(self.rows("hourly_conn"), [])


if __name__ == "__main__":
    unittest.main()
