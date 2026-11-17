"""Cookie audit: decision logic (pure) and a real browser against a local page."""
import os
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import cookie_audit as ca

NOBANNER = {"found": False, "vendor": None, "text": ""}
BANNER = {"found": True, "vendor": "OneTrust", "text": ""}
DAY = 86400


def cookie(name, domain="x.test", secure=True, http_only=True, days=30):
    return {"name": name, "domain": domain, "secure": secure, "httpOnly": http_only,
            "sameSite": "Lax", "expires": time.time() + days * DAY}


def rules(result):
    return {i["rule"]: i["severity"] for i in result["issues"]}


class Domains(unittest.TestCase):
    def test_registrable_domain(self):
        cases = {"www.example.com": "example.com", "a.b.example.com": "example.com", "example.com": "example.com",
                 "shop.example.co.uk": "example.co.uk", "localhost": "localhost", "127.0.0.1": "127.0.0.1",
                 "www.google-analytics.com": "google-analytics.com"}
        for host, expected in cases.items():
            with self.subTest(host=host):
                self.assertEqual(ca.registrable_domain(host), expected)

    def test_cookies_are_classified_by_domain_and_by_name(self):
        c = ca.classify_cookie
        self.assertEqual(c("sid", ".x.test", "x.test"), {"party": "first", "category": "functional"})
        self.assertEqual(c("_ga", ".x.test", "x.test"), {"party": "first", "category": "analytics"})
        self.assertEqual(c("_fbp", ".x.test", "x.test"), {"party": "first", "category": "advertising"})
        self.assertEqual(c("x", ".doubleclick.net", "x.test"), {"party": "third", "category": "advertising"})
        self.assertEqual(c("x", ".mystery.example", "x.test"), {"party": "third", "category": "unknown"})

    def test_tracker_domains(self):
        self.assertEqual(ca.tracker_category("google-analytics.com"), "analytics")
        self.assertEqual(ca.tracker_category("facebook.net"), "social")
        self.assertIsNone(ca.tracker_category("cdn.example"))


class Findings(unittest.TestCase):
    def analyze(self, cookies=(), hosts=(), banner=NOBANNER, reject=False, https=True):
        return ca.analyze("www.x.test", list(cookies), list(hosts), banner, reject, https)

    def test_clean_site_has_no_issues(self):
        r = self.analyze([cookie("sid")], ["www.x.test", "x.test"])
        self.assertEqual(r["issues"], [])
        self.assertFalse(r["tracking_before_consent"])

    def test_trackers_with_no_banner_are_high(self):
        r = self.analyze([cookie("_ga")], ["www.googletagmanager.com", "x.test"])
        self.assertEqual(rules(r)["Tracking starts with no cookie consent banner"], "High")
        self.assertEqual(r["trackers"], [{"domain": "googletagmanager.com", "category": "analytics"}])
        self.assertTrue(r["tracking_before_consent"])

    def test_trackers_before_a_click_are_medium_when_a_banner_exists(self):
        r = self.analyze(hosts=["connect.facebook.net"], banner=BANNER, reject=True)
        self.assertEqual(rules(r)["Tracking starts before the visitor agrees"], "Medium")
        self.assertNotIn("Tracking starts with no cookie consent banner", rules(r))

    def test_banner_without_a_way_to_refuse(self):
        r = self.analyze(banner=BANNER, reject=False)
        self.assertEqual(rules(r)["Consent banner offers no clear way to refuse"], "Medium")
        self.assertEqual(self.analyze(banner=BANNER, reject=True)["issues"], [])

    def test_secure_flag_severity_depends_on_what_the_cookie_does(self):
        self.assertEqual(rules(self.analyze([cookie("locale", secure=False)]))["Cookies set without the Secure flag"], "Low")
        self.assertEqual(rules(self.analyze([cookie("session_id", secure=False)]))["Cookies set without the Secure flag"], "Medium")

    def test_secure_flag_is_not_demanded_on_plain_http(self):
        for name in ("locale", "session_id"):
            with self.subTest(cookie=name):
                self.assertNotIn("Cookies set without the Secure flag",
                                 rules(self.analyze([cookie(name, secure=False)], https=False)))

    def test_session_cookie_without_httponly(self):
        r = self.analyze([cookie("auth_token", http_only=False)])
        self.assertEqual(rules(r)["Session-style cookies readable by scripts (no HttpOnly)"], "Medium")
        self.assertEqual(self.analyze([cookie("theme", http_only=False)])["issues"], [])

    def test_long_lived_tracking_cookie(self):
        r = self.analyze([cookie("_ga", days=800)], ["googletagmanager.com"], banner=BANNER, reject=True)
        self.assertIn("Tracking cookies that last more than 13 months", rules(r))
        r = self.analyze([cookie("_ga", days=100)], ["googletagmanager.com"], banner=BANNER, reject=True)
        self.assertNotIn("Tracking cookies that last more than 13 months", rules(r))

    def test_third_parties_are_listed_for_disclosure(self):
        r = self.analyze(hosts=["cdn.fonts.example", "x.test", "api.other.example"])
        self.assertEqual(r["third_party_domains"], ["fonts.example", "other.example"])
        self.assertEqual(rules(r)["Outside companies receive visitor data on load"], "Low")

    def test_counts_and_limits(self):
        many = [cookie(f"c{i}") for i in range(60)]
        r = self.analyze(many + [cookie("t", domain=".doubleclick.net")])
        self.assertEqual((r["cookies_total"], r["first_party"], r["third_party"]), (61, 60, 1))
        self.assertEqual(len(r["cookies"]), 40)

    def test_run_reports_unavailable_when_no_browser(self):
        with mock.patch.object(ca.browser_audit, "_launch", side_effect=RuntimeError("no usable Edge or Chrome found")):
            r = ca.run_cookie_audit("https://x.test/")
        self.assertEqual((r["reason"], "_unavailable" in r), ("missing_tool", True))
        self.assertNotIn("cookies", r)


PAGE = """<!doctype html><html lang="en"><head><title>Shop</title>
<script src="http://localhost:%(other)s/track.js"></script></head><body><h1>Shop</h1>
%(banner)s</body></html>"""
BANNER_HTML = ('<div style="position:fixed;bottom:0;left:0;right:0;background:#eee;padding:12px">We use cookies to improve your '
               'experience. <button>Accept all</button> <button>Reject non-essential</button></div>')


class Local(BaseHTTPRequestHandler):
    other_port = 0

    def do_GET(self):
        if self.path.endswith("track.js"):
            body, ctype = b"/* third party script */", "application/javascript"
        else:
            html = PAGE % {"other": Local.other_port, "banner": BANNER_HTML if "nobanner" not in self.path else ""}
            body, ctype = html.encode(), "text/html"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        for c in ("sid=abc; Path=/; HttpOnly", "locale=en; Path=/; Max-Age=31536000", "_ga=GA1.1.1; Path=/; Max-Age=63072000"):
            self.send_header("Set-Cookie", c)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def browser_available():
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            ca.browser_audit._launch(p).close()
        return True
    except Exception:
        return False


@unittest.skipUnless(browser_available(), "no usable Edge/Chrome or Playwright")
class RealBrowser(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.third = HTTPServer(("127.0.0.1", 0), Local)
        Local.other_port = cls.third.server_port
        cls.site = HTTPServer(("127.0.0.1", 0), Local)
        for s in (cls.third, cls.site):
            threading.Thread(target=s.serve_forever, daemon=True).start()
        cls.url = f"http://127.0.0.1:{cls.site.server_port}"
        patch = mock.patch.object(ca, "SETTLE_MS", 300)
        patch.start()
        cls.addClassCleanup(patch.stop)

    @classmethod
    def tearDownClass(cls):
        for s in (cls.third, cls.site):
            s.shutdown()
            s.server_close()

    def test_cookies_third_parties_and_banner_are_observed(self):
        r = ca.run_cookie_audit(self.url + "/")
        self.assertNotIn("_unavailable", r)
        names = {c["name"]: c for c in r["cookies"]}
        self.assertEqual(set(names), {"sid", "locale", "_ga"})
        self.assertTrue(names["sid"]["http_only"])
        self.assertFalse(names["locale"]["http_only"])
        self.assertEqual(names["_ga"]["category"], "analytics")
        self.assertGreater(names["_ga"]["lifetime_days"], ca.LONG_LIVED_DAYS)  # Chrome caps lifetimes at 400 days
        self.assertEqual(r["third_party_domains"], ["localhost"])  # the script came from another host
        self.assertTrue(r["consent_banner"]["found"])
        self.assertTrue(r["consent_banner"]["offers_reject_or_settings"])

    def test_page_without_a_banner_is_reported_as_such(self):
        r = ca.run_cookie_audit(self.url + "/nobanner")
        self.assertFalse(r["consent_banner"]["found"])
        self.assertIn("Tracking starts with no cookie consent banner", rules(r))

    def test_each_visit_starts_with_an_empty_profile(self):
        first = ca.run_cookie_audit(self.url + "/")["cookies_total"]
        second = ca.run_cookie_audit(self.url + "/")["cookies_total"]
        self.assertEqual(first, second)  # cookies from visit one never leak into visit two


if __name__ == "__main__":
    unittest.main()
