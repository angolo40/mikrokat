import json
import os
import sys
import time
import unittest

sys.path.insert(0, "/app")
import store  # noqa: E402
import web  # noqa: E402
from test_tls_settings import Base, full_form  # noqa: E402

HOST = "mikrokat.lan:8088"


class BankSwitch(Base):
    def stats(self, **values):
        with open(os.path.join(store.TLS_DIR, "state", "stats.json"), "w") as target:
            json.dump({"at": int(time.time()), **values}, target)

    def test_on_by_default(self):
        self.assertIs(store.settings["tls_bank_list"], True)

    def test_control_file_carries_it(self):
        store.settings["tls_bank_list"] = True
        store.write_tls_control()
        self.assertIs(self.control()["bank_list"], True)
        store.settings["tls_bank_list"] = False
        store.write_tls_control()
        self.assertIs(self.control()["bank_list"], False)

    def test_the_switch_is_saved(self):
        self.assertIsNone(store.save_settings(full_form(tls_bank_list="on")))
        self.assertIs(store.settings["tls_bank_list"], True)
        self.assertIs(self.control()["bank_list"], True)
        self.assertIsNone(store.save_settings(full_form()))
        self.assertIs(store.settings["tls_bank_list"], False)
        self.assertIs(self.control()["bank_list"], False)

    def test_the_tab_has_the_switch_and_the_source(self):
        page = web.settings_page(HOST, tab="https")
        self.assertIn('name="tls_bank_list" checked', page)
        self.assertIn("Skip the bank list", page)
        self.assertIn("Université Toulouse Capitole", page)
        self.assertIn("not all", page)
        self.assertIn("not shown in the field below", page)
        self.assertLess(page.index("Skip the bank list"), page.index('name="tls_bypass"'))
        store.settings["tls_bank_list"] = False
        self.assertNotIn('name="tls_bank_list" checked', web.settings_page(HOST, tab="https"))

    def test_the_status_shows_names_and_date(self):
        self.stats(bank_list_names=6543, bank_list_at=1_800_000_000)
        page = web.settings_page(HOST, tab="https")
        self.assertIn("6 543 names", page)
        self.assertIn(time.strftime("%Y-%m-%d", time.localtime(1_800_000_000)), page)

    def test_no_copy_yet(self):
        self.stats(bank_list_names=0, bank_list_at=0)
        self.assertIn("No copy yet", web.settings_page(HOST, tab="https"))

    def test_an_error_is_shown_and_escaped(self):
        self.stats(bank_list_names=1200, bank_list_at=1_800_000_000, bank_list_error="<script>alert(1)</script> failed")
        page = web.settings_page(HOST, tab="https")
        self.assertNotIn("<script>alert(1)", page)
        self.assertIn("&lt;script&gt;alert(1)", page)
        self.assertIn("The old copy stays in use", page)

    def test_bad_values_from_the_proxy_do_not_break_the_page(self):
        self.stats(bank_list_names="x", bank_list_at=[1], bank_list_error=5)
        self.assertIn("Skip the bank list", web.settings_page(HOST, tab="https"))

    def test_the_connections_page_names_the_reason(self):
        self.assertIn("bank list", web.PASSED_REASONS["bank_list"].lower())


if __name__ == "__main__":
    unittest.main()
