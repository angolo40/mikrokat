import contextlib
import http.client
import http.server
import io
import json
import re
import sys
import threading
import unittest
import urllib.parse
from unittest import mock

sys.path.insert(0, "/app")
import store  # noqa: E402
import web  # noqa: E402
from test_tls_settings import Base, full_form  # noqa: E402

HOST = "mikrokat.lan:8088"
KEY = "sk-test-0123456789-secret"
PRESETS = {
    "ollama": ("Ollama", "http://host:11434/v1", "llama3.2"),
    "lmstudio": ("LM Studio", "http://host:1234/v1", ""),
    "openai": ("OpenAI", "https://api.openai.com/v1", "gpt-5.6-luna"),
    "gemini": ("Google Gemini", "https://generativelanguage.googleapis.com/v1beta/openai", "gemini-3.1-flash-lite"),
    "anthropic": ("Anthropic", "https://api.anthropic.com/v1", "claude-haiku-5-5"),
    "openrouter": ("OpenRouter", "https://openrouter.ai/api/v1", ""),
    "custom": ("Custom", "", ""),
}


class Model(http.server.BaseHTTPRequestHandler):
    """A model server that answers with whatever the test set."""
    reply = (200, {"choices": [{"message": {"content": "Looks like a scan.\nCheck the logs."}}]})
    seen = []

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        Model.seen.append((self.path, self.headers.get("Authorization"), json.loads(body)))
        status, payload = Model.reply
        data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


class Presets(Base):
    def page(self, **settings):
        store.settings.update(settings)
        return web.settings_page(HOST, "", "", "ai")

    def select(self, page):
        found = re.search(r'<select id="ai-preset"[^>]*>(.*?)</select>', page, re.S)
        self.assertTrue(found, "no preset select")
        return found

    def test_the_presets_are_listed_in_order(self):
        options = re.findall(r'<option value="(\w+)"[^>]*>([^<]+)</option>', self.select(self.page()).group(1))
        self.assertEqual(options, [(k, v[0]) for k, v in PRESETS.items()])

    def test_every_preset_carries_its_suggestion(self):
        page = self.page()
        for key, (_, url, model) in PRESETS.items():
            if key != "custom":
                self.assertIn(f'data-url="{url}"', page)
                self.assertRegex(page, rf'<option value="{key}"[^>]*data-model="{re.escape(model)}"')

    def test_the_select_is_never_submitted_so_nothing_is_stored(self):
        self.assertNotRegex(self.select(self.page()).group(0).split(">")[0], r"\bname=")

    def test_the_matching_preset_is_chosen_on_load(self):
        for key, (_, url, _) in PRESETS.items():
            if key in ("custom", "ollama", "lmstudio"):
                continue
            chosen = re.findall(r'<option value="(\w+)"[^>]*selected', self.select(self.page(ai_url=url)).group(1))
            self.assertEqual(chosen, [key], url)
        for url, key in (("http://192.0.2.7:11434/v1", "ollama"), ("http://ollama.lan:11434/v1", "ollama"), ("http://192.0.2.7:1234/v1", "lmstudio")):
            chosen = re.findall(r'<option value="(\w+)"[^>]*selected', self.select(self.page(ai_url=url)).group(1))
            self.assertEqual(chosen, [key], url)

    def test_anything_else_is_custom(self):
        for url in ("", "http://192.0.2.7:8000/v1", "https://api.openai.com.evil.example/v1", "https://example.org/v1"):
            chosen = re.findall(r'<option value="(\w+)"[^>]*selected', self.select(self.page(ai_url=url)).group(1))
            self.assertEqual(chosen, ["custom"], url)

    def test_the_saved_values_stay_intact(self):
        page = self.page(ai_url="http://192.0.2.7:11434/v1", ai_model="mistral", ai_key=KEY)
        self.assertIn('name="ai_url" autocomplete="off" value="http://192.0.2.7:11434/v1"', page)
        self.assertIn('name="ai_model" autocomplete="off" value="mistral"', page)
        self.assertNotIn(KEY, page)

    def test_the_hint_of_the_chosen_preset_is_the_one_shown(self):
        page = self.page(ai_url="https://api.openai.com/v1")
        shown = re.findall(r'<p class="hint preset-hint" data-preset="(\w+)"(?! hidden)>', page)
        self.assertEqual(shown, ["openai"])
        self.assertEqual(len(re.findall(r'class="hint preset-hint"', page)), len(PRESETS))
        self.assertRegex(page, r'data-preset="ollama" hidden>[^<]*no key')

    def test_the_script_is_small_and_leaves_the_key_alone(self):
        script = re.search(r"<script>(.*?)</script>", self.page(), re.S).group(1)
        self.assertLess(len(script), 1200)
        self.assertNotIn("ai_key", script)


class Test(Base):
    """The Test button, against a real server."""

    def setUp(self):
        super().setUp()
        Model.reply = (200, {"choices": [{"message": {"content": "Looks like a scan.\nCheck the logs."}}]})
        Model.seen = []
        self.model = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Model)
        threading.Thread(target=self.model.serve_forever, daemon=True).start()
        self.addCleanup(self.model.server_close)
        self.addCleanup(self.model.shutdown)
        self.server = web.ThreadingHTTPServer(("127.0.0.1", 0), web.Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        self.cookie = f"{web.SESSION_COOKIE}={web.new_session()}"
        self.url = f"http://127.0.0.1:{self.model.server_address[1]}/v1"

    def press(self, path="/test/explain", **changes):
        form = full_form(**{"ai_enabled": "on", "ai_url": self.url, "ai_model": "tiny", "ai_key": KEY, "tab": "ai", "token": web.csrf_token, **changes})
        body = urllib.parse.urlencode(form).encode()
        client = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=30)
        self.addCleanup(client.close)
        client.putrequest("POST", path)
        client.putheader("Content-Type", "application/x-www-form-urlencoded")
        client.putheader("Content-Length", str(len(body)))
        client.putheader("Cookie", self.cookie)
        client.endheaders()
        client.send(body)
        reply = client.getresponse()
        return reply.status, reply.read().decode()

    def notes(self, page):
        return re.findall(r'<p class="note(?: error)?">(.*?)</p>', page, re.S)

    def test_success_reports_the_time_and_the_first_line(self):
        status, page = self.press()
        self.assertEqual(status, 200)
        text = " ".join(self.notes(page))
        self.assertRegex(text, r"answered in \d+ ms")
        self.assertIn("Looks like a scan.", text)
        self.assertNotIn("Check the logs.", text)
        path, auth, body = Model.seen[0]
        self.assertEqual((path, auth, body["model"]), ("/v1/chat/completions", f"Bearer {KEY}", "tiny"))
        self.assertLess(len(json.dumps(body)), 1500)  # one short request about a sample rule

    def test_it_saves_what_is_on_screen_first(self):
        self.press(ai_model="saved-by-test")
        self.assertEqual(store.settings["ai_model"], "saved-by-test")

    def test_the_answer_is_escaped(self):
        Model.reply = (200, {"choices": [{"message": {"content": "<script>alert(1)</script> hi"}}]})
        page = self.press()[1]
        self.assertNotIn("<script>alert(1)", page)
        self.assertIn("&lt;script&gt;alert(1)", page)

    def test_an_error_status_is_reported_without_the_key(self):
        Model.reply = (401, {"error": {"message": f"Incorrect API key provided: {KEY}"}})
        status, page = self.press()
        self.assertEqual(status, 200)
        errors = re.findall(r'<p class="note error">(.*?)</p>', page, re.S)
        self.assertTrue(errors and "401" in errors[0], errors)
        self.assertNotIn(KEY, page)

    def test_a_server_that_is_not_there_is_an_error(self):
        self.model.shutdown()
        self.model.server_close()
        page = self.press()[1]
        self.assertRegex(page, r'<p class="note error">[^<]*did not answer')
        self.assertNotIn(KEY, page)

    def test_an_empty_answer_is_an_error_with_a_hint(self):
        for content in ("", "   \n", None):
            Model.reply = (200, {"choices": [{"message": {"content": content}}]})
            page = self.press()[1]
            error = re.search(r'<p class="note error">(.*?)</p>', page, re.S)
            self.assertTrue(error, content)
            self.assertIn("reasoning", error.group(1))
            self.assertIn("another model", error.group(1))

    def test_a_reply_that_is_not_a_chat_completion_is_an_error(self):
        for reply in (b"<html>nope</html>", {"choices": []}, {"x": 1}, [1]):
            Model.reply = (200, reply)
            self.assertIn('class="note error"', self.press()[1], reply)

    def test_it_needs_an_address_and_a_model(self):
        page = self.press(ai_model="")[1]
        self.assertIn('class="note error"', page)
        self.assertEqual(Model.seen, [])

    def test_the_key_is_in_no_page_and_no_log(self):
        out = io.StringIO()
        with mock.patch.object(sys, "stdout", out), mock.patch.object(sys, "stderr", out):
            pages = [self.press()[1]]
            Model.reply = (500, b"boom " + KEY.encode())
            pages.append(self.press()[1])
            Model.reply = (200, {"choices": [{"message": {"content": ""}}]})
            pages.append(self.press()[1])
            pages.append(web.settings_page(HOST, "", "", "ai"))
        for page in pages:
            self.assertNotIn(KEY, page)
        self.assertNotIn(KEY, out.getvalue())

    def test_the_button_is_on_the_ai_tab(self):
        page = web.settings_page(HOST, "", "", "ai")
        self.assertRegex(page, r'<button class="ghost" formaction="/test/explain">')

    def test_login_is_required(self):
        self.cookie = ""
        client = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=10)
        self.addCleanup(client.close)
        client.request("POST", "/test/explain", body=b"token=x", headers={"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(client.getresponse().status, 303)
        self.assertEqual(Model.seen, [])


class Guide(Base):
    def test_every_tab_has_a_guide_block(self):
        missing = [k for k, _ in web.SETTINGS_TABS if not web.GUIDE.get(k, "").strip()]
        self.assertEqual(missing, [], "tabs with no guide block")

    def test_there_is_no_block_for_a_tab_that_does_not_exist(self):
        self.assertEqual(set(web.GUIDE) - {k for k, _ in web.SETTINGS_TABS}, set())

    def test_the_page_holds_one_block_per_tab(self):
        page = web.settings_page(HOST, "", "", "protection")
        for key, _ in web.SETTINGS_TABS:
            self.assertEqual(len(re.findall(rf'<div class="guide-block guide-{key}">', page)), 1, key)

    def test_a_tab_with_no_guide_block_fails_loudly(self):
        tabs = web.SETTINGS_TABS + (("zzz", "Zzz"),)
        with mock.patch.object(web, "SETTINGS_TABS", tabs), self.assertRaises(KeyError):
            web.settings_page(HOST, "", "", "protection")

    def test_the_rules_follow_the_tabs(self):
        tabs = (("one", "One"), ("two", "Two"))
        css = web.tab_css(tabs)
        for key, _ in tabs:
            self.assertIn(f"#tab-{key}:checked ~ #pane-{key} {{ display: block; }}", css)
            self.assertIn(f".with-guide:has(#tab-{key}:checked) .guide-{key} {{ display: block; }}", css)
            self.assertIn(f"label[for=tab-{key}]", css)

    def test_the_style_has_the_rules_of_every_real_tab(self):
        for key, _ in web.SETTINGS_TABS:
            self.assertIn(f".with-guide:has(#tab-{key}:checked) .guide-{key} {{ display: block; }}", web.STYLE)
            self.assertIn(f"#tab-{key}:checked ~ #pane-{key}", web.STYLE)

    def test_blocks_are_hidden_unless_their_tab_is_open(self):
        self.assertRegex(web.STYLE, r"\.guide-block \{ display: none; \}")

    def test_the_blocks_hold_what_the_brief_asks_for(self):
        wanted = {"protection": ("Monitor", "Block", "allowlist", "repeat"), "notifications": ("Telegram", "chat ID", "webhook"),
                  "router": ("/ip firewall mangle", "/user group add", "/ip firewall raw"), "data": ("EveBox", "EVE", "SIEM"),
                  "ai": ("never", "local", "cost", "Test"), "https": ("Firefox", "own CA", "consent", "Connections"),
                  "account": ("password", "single sign-on", "session")}
        for key, words in wanted.items():
            for word in words:
                self.assertIn(word.lower(), web.GUIDE[key].lower(), f"{key}: {word}")

    def test_no_private_address_in_the_guide(self):
        self.assertNotRegex("".join(web.GUIDE.values()), r"\b(10\.0\.10|192\.168)\.")


if __name__ == "__main__":
    unittest.main()
