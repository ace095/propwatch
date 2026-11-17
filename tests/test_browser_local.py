"""Real-browser tests against a tiny local site (no internet, no third-party sites).

Skipped automatically when Edge or Chrome / Playwright is not available.
"""
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import browser_audit

SHELL = """<!doctype html><html lang="en"><head><title>App</title></head><body>
<div id="root"></div>
<script>document.getElementById('root').innerHTML =
  '<h1>Built by script</h1><p>%s</p><img src="x.png">';</script></body></html>""" % ("Real content. " * 30)

BAD_FOCUS = """<!doctype html><html lang="en"><head><title>t</title>
<style>a:focus, button:focus { outline: none; }</style></head><body><h1>Focus</h1>
<a href="#a">First link</a> <button>Press</button></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = (BAD_FOCUS if self.path == "/focus" else SHELL).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("X-Test-Header", "present")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def browser_available() -> bool:
    try:
        from playwright.sync_api import sync_playwright
        browser_audit._axe_source()
        with sync_playwright() as p:
            browser_audit._launch(p).close()
        return True
    except Exception:
        return False


@unittest.skipUnless(browser_available(), "no usable Edge/Chrome or Playwright")
class LocalBrowser(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), Handler)
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_script_built_page_is_detected_and_then_read_correctly(self):
        import audit
        status, _, raw = audit._get(self.base + "/", retries=0)
        self.assertEqual(status, 200)
        self.assertIn('<div id="root"></div>', raw)        # plain fetch sees an empty shell
        self.assertTrue(browser_audit.looks_js_rendered(raw))
        status, headers, html = browser_audit.render_page(self.base + "/")
        self.assertEqual(status, 200)
        self.assertIn('<div id="root"><h1>Built by script</h1>', html)  # the browser ran the script
        self.assertFalse(browser_audit.looks_js_rendered(html))
        self.assertEqual(headers["x-test-header"], "present")  # and gives the real headers

    def test_axe_and_keyboard_audit_find_real_problems(self):
        result = browser_audit.run_browser_audit(self.base + "/")
        self.assertNotIn("_unavailable", result)
        self.assertIn("image-alt", {v["id"] for v in result["violations"]})
        self.assertEqual(result["by_impact"]["critical"], 1)

    def test_missing_focus_outline_is_reported(self):
        result = browser_audit.run_browser_audit(self.base + "/focus")
        self.assertEqual(result["keyboard"]["reached_by_tab"], 2)
        self.assertEqual(len(result["keyboard"]["no_visible_focus_style"]), 2)
        self.assertIsNone(result["keyboard"]["possible_keyboard_trap"])

    def test_unreachable_page_is_explained_not_passed(self):
        import socket
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            closed_port = s.getsockname()[1]  # free now, and nothing listens on it
        result = browser_audit.run_browser_audit(f"http://127.0.0.1:{closed_port}/")
        self.assertIn("_unavailable", result)
        self.assertEqual(result["reason"], "connection")


if __name__ == "__main__":
    unittest.main()
