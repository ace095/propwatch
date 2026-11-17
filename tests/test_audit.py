"""Offline tests: network is mocked, so they run anywhere."""
import os, socket, ssl, sys, threading, unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import audit

FAIL = (None, {"_error": "boom"}, "")


class FailedFetchIsUnknownNotMissing(unittest.TestCase):
    def test_headers(self):
        with mock.patch.object(audit, "_get", return_value=FAIL):
            r = audit.check_headers("x.test")
        self.assertIn("_unavailable", r)
        self.assertNotIn("missing", r)

    def test_http_redirect(self):
        with mock.patch.object(audit, "_get", return_value=FAIL):
            r = audit.check_http_redirect("x.test")
        self.assertIn("_unavailable", r)
        self.assertNotIn("redirects_to_https", r)

    def test_privacy(self):
        with mock.patch.object(audit, "_get", return_value=FAIL):
            r = audit.check_privacy("x.test")
        self.assertIn("_unavailable", r)

    def test_email_dns_failure(self):
        with mock.patch.object(audit, "_txt_records", return_value=None):
            r = audit.check_email_auth("x.test")
        self.assertIn("_unavailable", r)
        self.assertNotIn("spf", r)

    def test_dmarc_lookup_failure_not_reported_as_missing(self):
        def fake(name, must_exist=False):
            return ["v=spf1 -all"] if not name.startswith("_dmarc") else None
        with mock.patch.object(audit, "_txt_records", side_effect=fake):
            r = audit.check_email_auth("x.test")
        self.assertEqual(r["spf"], "v=spf1 -all")
        self.assertIn("dmarc_unavailable", r)


class RealFindingsStillReported(unittest.TestCase):
    def test_missing_headers_detected_on_success(self):
        with mock.patch.object(audit, "_get",
                               return_value=(200, {"strict-transport-security": "x"}, "")):
            r = audit.check_headers("x.test")
        self.assertIn("strict-transport-security", r["present"])
        self.assertIn("content-security-policy", r["missing"])

    def test_http_redirect_detected(self):
        with mock.patch.object(audit, "_get",
                               return_value=(301, {"location": "https://x.test/"}, "")):
            self.assertTrue(audit.check_http_redirect("x.test")["redirects_to_https"])
        with mock.patch.object(audit, "_get", return_value=(200, {}, "")):
            self.assertFalse(audit.check_http_redirect("x.test")["redirects_to_https"])

    def test_no_dmarc_record_is_a_real_finding(self):
        def fake(name, must_exist=False):
            return ["v=spf1 -all"] if not name.startswith("_dmarc") else []
        with mock.patch.object(audit, "_txt_records", side_effect=fake):
            r = audit.check_email_auth("x.test")
        self.assertIsNone(r["dmarc"])
        self.assertNotIn("dmarc_unavailable", r)

    def test_norm(self):
        self.assertEqual(audit._norm("https://Example.EDU/a/b"), "example.edu")


class _RedirectServer(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            self.send_response(308)
            self.send_header("Location", "/final")
            self.end_headers()
        else:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


class RedirectHandling(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), _RedirectServer)
        cls.url = f"http://127.0.0.1:{cls.server.server_port}/"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_get_follows_redirects_by_default(self):
        status, _, body = audit._get(self.url)
        self.assertEqual((status, body), (200, "ok"))

    def test_get_can_surface_the_redirect(self):
        status, headers, _ = audit._get(self.url, follow_redirects=False)
        self.assertEqual(status, 308)
        self.assertEqual(headers["location"], "/final")

    def test_http_redirect_check_does_not_follow(self):
        with mock.patch.object(audit, "_get", return_value=(200, {}, "")) as spy:
            audit.check_http_redirect("x.test")
        self.assertIs(spy.call_args.kwargs["follow_redirects"], False)

    def test_http_redirect_detects_https_location_on_308(self):
        resp = (308, {"location": "https://x.test/"}, "")
        with mock.patch.object(audit, "_get", return_value=resp):
            self.assertTrue(audit.check_http_redirect("x.test")["redirects_to_https"])


class HomepageFetchedOnce(unittest.TestCase):
    def test_run_audit_downloads_homepage_once(self):
        home = (200, {}, "<html lang='en'><title>t</title></html>")
        calls = []

        def fake_get(url, follow_redirects=True):
            calls.append(url)
            return home if url == "https://x.test/" else (404, {}, "")

        with mock.patch.object(audit, "_get", side_effect=fake_get), \
             mock.patch.object(audit, "load_allowlist", return_value=["x.test"]), \
             mock.patch.object(audit, "check_tls", return_value={}), \
             mock.patch.object(audit, "check_browser_accessibility", return_value={}), \
             mock.patch.object(audit, "check_email_auth", return_value={}):
            audit.run_audit("x.test")
        self.assertEqual(calls.count("https://x.test/"), 1)


class CertificateProblems(unittest.TestCase):
    def classify(self, code):
        err = ssl.SSLCertVerificationError(1, "verify failed")
        err.verify_code = code
        with mock.patch.object(audit.socket, "create_connection", side_effect=err):
            return audit.check_tls("x.test")

    def test_known_codes_are_named(self):
        for code, name in {10: "expired", 18: "self_signed", 20: "untrusted_issuer",
                           62: "hostname_mismatch"}.items():
            with self.subTest(code=code):
                r = self.classify(code)
                self.assertEqual(r["cert_problem"], name)
                self.assertFalse(r["cert_valid"])

    def test_unknown_code_is_generic(self):
        self.assertEqual(self.classify(999)["cert_problem"], "invalid")


class RetryOnTransientFailure(unittest.TestCase):
    def test_retries_once_then_reports_failure(self):
        opener = mock.Mock()
        opener.open.side_effect = socket.timeout("slow")
        with mock.patch.object(audit, "build_opener", return_value=opener):
            status, headers, _ = audit._get("http://x.test/")
        self.assertIsNone(status)
        self.assertEqual(opener.open.call_count, 2)

    def test_certificate_errors_are_not_retried(self):
        from urllib.error import URLError
        opener = mock.Mock()
        opener.open.side_effect = URLError(ssl.SSLCertVerificationError(1, "bad"))
        with mock.patch.object(audit, "build_opener", return_value=opener):
            audit._get("https://x.test/")
        self.assertEqual(opener.open.call_count, 1)


class ReportOutputEncoding(unittest.TestCase):
    def test_unicode_report_is_written_as_utf8(self):
        import json, tempfile, report
        with tempfile.TemporaryDirectory() as d:
            findings, out = os.path.join(d, "f.json"), os.path.join(d, "r.md")
            with open(findings, "w", encoding="utf-8") as f:
                json.dump({"target": "x.test"}, f)
            argv = ["report.py", "--json", findings, "--single", "--out", out]
            with mock.patch.object(sys, "argv", argv),                  mock.patch.object(report, "_client"),                  mock.patch.object(report, "report_single", return_value="HTTP → HTTPS"):
                report.main()
            with open(out, encoding="utf-8") as f:
                self.assertEqual(f.read(), "HTTP → HTTPS")


class RateLimit(unittest.TestCase):
    def setUp(self):
        audit._last_request.clear()

    def test_second_request_to_same_host_waits(self):
        with mock.patch.object(audit.time, "sleep") as sleep:
            audit._throttle("a.test")
            audit._throttle("a.test")
        sleep.assert_called_once()
        self.assertLessEqual(sleep.call_args.args[0], audit.MIN_REQUEST_INTERVAL)

    def test_different_hosts_do_not_wait(self):
        with mock.patch.object(audit.time, "sleep") as sleep:
            audit._throttle("a.test")
            audit._throttle("b.test")
        sleep.assert_not_called()


class PdfExport(unittest.TestCase):
    MD = chr(10).join([
        "# Audit Report",
        "",
        "A → B — “quoted” ✅",
        "",
        "| Item | Count |",
        "|---|---|",
        "| `code` cell | 1 |",
        "",
        "- one",
        "- two",
    ])

    def render(self, md):
        import tempfile, pdf_export
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "r.pdf")
            pdf_export.markdown_to_pdf(md, out)
            with open(out, "rb") as f:
                return f.read()

    def test_produces_a_pdf_from_unicode_markdown_with_tables(self):
        data = self.render(self.MD)
        self.assertTrue(data.startswith(b"%PDF"))
        self.assertGreater(len(data), 1000)

    def test_every_sample_report_converts(self):
        import glob
        samples = glob.glob(os.path.join(os.path.dirname(__file__), "..",
                                         "sample_reports", "*.md"))
        self.assertTrue(samples)
        for path in samples:
            with self.subTest(path=os.path.basename(path)), open(path, encoding="utf-8") as f:
                self.assertTrue(self.render(f.read()).startswith(b"%PDF"))

    def test_report_cli_writes_pdf_flag(self):
        import json, tempfile, report
        with tempfile.TemporaryDirectory() as d:
            findings, pdf = os.path.join(d, "f.json"), os.path.join(d, "r.pdf")
            with open(findings, "w", encoding="utf-8") as f:
                json.dump({"target": "x.test"}, f)
            argv = ["report.py", "--json", findings, "--single", "--pdf", pdf]
            with mock.patch.object(sys, "argv", argv), \
                 mock.patch.object(report, "_client"), \
                 mock.patch.object(report, "report_single", return_value="# Title text"):
                report.main()
            with open(pdf, "rb") as f:
                self.assertTrue(f.read().startswith(b"%PDF"))


class TargetAllowlist(unittest.TestCase):
    def write(self, text):
        import tempfile
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        path = os.path.join(d.name, "allow.txt")
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        return path

    def test_file_ignores_comments_and_blank_lines(self):
        path = self.write("# header\n\nExample.COM  # client, signed 2026-01-01\n  \nowasp.org\n")
        self.assertEqual(audit.load_allowlist(path), ["example.com", "owasp.org"])

    def test_listed_domain_and_its_subdomains_match(self):
        allow = ["badssl.com"]
        self.assertTrue(audit.is_authorized("badssl.com", allow))
        self.assertTrue(audit.is_authorized("expired.badssl.com", allow))
        self.assertTrue(audit.is_authorized("BADSSL.com.", allow))

    def test_lookalike_domains_do_not_match(self):
        allow = ["example.com"]
        for host in ("evilexample.com", "example.com.evil.test", "example.org", "com"):
            with self.subTest(host=host):
                self.assertFalse(audit.is_authorized(host, allow))

    def test_unlisted_target_is_refused_before_any_request(self):
        path = self.write("example.com\n")
        with mock.patch.object(audit, "_get") as get, \
             mock.patch.object(audit.socket, "create_connection") as conn:
            with self.assertRaises(audit.TargetNotAuthorized):
                audit.run_audit("https://stranger.test/page", path)
        get.assert_not_called()
        conn.assert_not_called()

    def test_missing_allowlist_authorizes_nothing(self):
        self.assertEqual(audit.load_allowlist(os.path.join("nope", "missing.txt")), [])

    def test_env_var_selects_the_allowlist(self):
        path = self.write("env.test\n")
        with mock.patch.dict(os.environ, {"WEBAUDIT_ALLOWLIST": path}):
            self.assertEqual(audit.load_allowlist(), ["env.test"])

    def test_cli_exits_2_for_unauthorized_target(self):
        path = self.write("example.com\n")
        argv = ["audit.py", "stranger.test", "--allowlist", path]
        with mock.patch.object(sys, "argv", argv), \
             mock.patch.object(audit, "_get") as get:
            with self.assertRaises(SystemExit) as cm:
                audit.main()
        self.assertEqual(cm.exception.code, 2)
        get.assert_not_called()

    def test_shipped_allowlist_covers_the_live_test_sites(self):
        allow = audit.load_allowlist()
        for host in ("example.com", "owasp.org", "neverssl.com", "expired.badssl.com"):
            self.assertTrue(audit.is_authorized(host, allow), host)


class AccessibilityChecks(unittest.TestCase):
    GOOD = """<html lang="en"><head><title>Ok</title>
      <meta name="viewport" content="width=device-width, initial-scale=1"></head><body>
      <a href="#main">Skip to content</a><h1>Title</h1><h2>Sub</h2>
      <img src="a.png" alt="A cat"><img src="deco.png" alt="">
      <label for="e">Email</label><input id="e" type="text">
      <label>Name <input type="text"></label><input type="hidden" name="t">
      <a href="/x">Read more</a><button>Save</button><input type="submit" value="Go">
      <iframe src="/f" title="Map"></iframe></body></html>"""

    BAD = """<html><head><meta name="viewport" content="width=device-width, user-scalable=no"></head><body>
      <h1>One</h1><h1>Two</h1><h4>Skipped</h4><h3></h3>
      <img src="a.png"><input type="text" name="q"><a href="/x"></a><button></button>
      <iframe src="/f"></iframe><div id="d"></div><div id="d"></div>
      <video autoplay src="v.mp4"></video>
      <table><tr><td>a</td></tr><tr><td>b</td></tr></table></body></html>"""

    def analyze(self, html):
        from bs4 import BeautifulSoup
        return audit.analyze_html(BeautifulSoup(html, "html.parser"))

    def rules(self, result):
        return {i["rule"] for i in result["issues"]}

    def test_accessible_page_has_no_issues(self):
        r = self.analyze(self.GOOD)
        self.assertEqual(r["issues"], [], r["issues"])
        self.assertEqual(r["images_missing_alt"], 0)  # alt="" is valid for decorative images
        self.assertEqual(r["images_total"], 2)

    def test_bad_page_reports_each_problem(self):
        r = self.analyze(self.BAD)
        expected = {
            "Images missing alt attribute", "Form fields without a label",
            "Links without an accessible name", "Buttons without an accessible name",
            "Iframes without a title", "Empty headings", "Duplicate id values",
            "Page should have exactly one h1", "Heading levels skipped",
            "Viewport blocks zoom", "Media that autoplays",
            "Data tables without header cells", "No skip-to-content link near top of page",
            "Page language not set", "Page has no title",
        }
        self.assertEqual(self.rules(r), expected)
        self.assertEqual(r["issue_count"], sum(i["count"] for i in r["issues"]))
        for issue in r["issues"]:
            self.assertTrue(issue["wcag"])
            self.assertLessEqual(len(issue["examples"]), 3)

    def test_aria_label_counts_as_a_name(self):
        r = self.analyze('<html lang="en"><title>t</title><h1>x</h1>'
                         '<a href="/" aria-label="Home"></a><button aria-label="Close"></button>'
                         '<input aria-label="Search" type="text">')
        self.assertNotIn("Links without an accessible name", self.rules(r))
        self.assertNotIn("Buttons without an accessible name", self.rules(r))
        self.assertNotIn("Form fields without a label", self.rules(r))


AXE_SAMPLE = {
    "testEngine": {"version": "4.x"},
    "passes": [{}, {}, {}],
    "incomplete": [{}],
    "violations": [
        {"id": "image-alt", "impact": "critical", "help": "Images need alt text",
         "tags": ["cat.text-alternatives", "wcag2a", "wcag111"], "helpUrl": "https://dequeuniversity.com/x",
         "nodes": [{"target": ["img"], "html": "<img src=a>"}, {"target": ["#b", "img"], "html": "<img src=b>"}]},
        {"id": "color-contrast", "impact": "serious", "help": "Contrast too low",
         "tags": ["wcag2aa", "wcag143"], "nodes": [{"target": ["p"], "html": "<p>x</p>"}]},
        {"id": "x", "impact": None, "help": "no impact given",
         "tags": ["wcag21aa", "wcag1410"], "nodes": [{"target": ["a"], "html": "<a>" + "y" * 400}]},
    ],
}


class BrowserAudit(unittest.TestCase):
    def test_wcag_criteria_from_axe_tags(self):
        import browser_audit
        self.assertEqual(browser_audit._wcag_criteria(["wcag2aa", "wcag143", "wcag1410", "best-practice"]),
                         ["1.4.3", "1.4.10"])

    def test_summary_orders_by_impact_and_counts_elements(self):
        import browser_audit
        s = browser_audit.summarize_axe(AXE_SAMPLE)
        self.assertEqual([v["id"] for v in s["violations"]], ["image-alt", "color-contrast", "x"])
        self.assertEqual(s["by_impact"], {"critical": 2, "serious": 1, "moderate": 0, "minor": 1})
        self.assertEqual((s["violation_rules"], s["violation_elements"]), (3, 4))
        self.assertEqual((s["rules_passed"], s["needs_manual_review"]), (3, 1))
        self.assertEqual(s["violations"][0]["wcag"], ["1.1.1"])
        self.assertEqual(s["violations"][0]["examples"][1]["target"], "#b img")
        self.assertLessEqual(len(s["violations"][2]["examples"][0]["html"]), 160)

    def test_no_browser_means_unavailable_not_a_clean_pass(self):
        import browser_audit
        with mock.patch.object(browser_audit, "_launch", side_effect=RuntimeError("no browser")):
            r = browser_audit.run_browser_audit("https://x.test/")
        self.assertIn("_unavailable", r)
        self.assertNotIn("violations", r)

    def test_browser_step_can_be_skipped(self):
        steps = []
        with mock.patch.object(audit, "load_allowlist", return_value=["x.test"]), \
             mock.patch.object(audit, "_get", return_value=(404, {}, "")), \
             mock.patch.object(audit, "check_tls", return_value={}), \
             mock.patch.object(audit, "check_email_auth", return_value={}), \
             mock.patch.object(audit, "check_browser_accessibility") as browser:
            result = audit.run_audit("x.test", browser=False, on_step=lambda n, s: steps.append((n, s)))
        browser.assert_not_called()
        self.assertNotIn("accessibility_browser", result)
        self.assertIn(("browser_a11y", "skipped"), steps)

    def test_browser_result_is_included_by_default(self):
        with mock.patch.object(audit, "load_allowlist", return_value=["x.test"]), \
             mock.patch.object(audit, "_get", return_value=(404, {}, "")), \
             mock.patch.object(audit, "check_tls", return_value={}), \
             mock.patch.object(audit, "check_email_auth", return_value={}), \
             mock.patch.object(audit, "check_browser_accessibility", return_value={"violations": []}):
            result = audit.run_audit("x.test")
        self.assertEqual(result["accessibility_browser"], {"violations": []})


class TlsRetry(unittest.TestCase):
    def test_retries_transient_failure_then_succeeds(self):
        results = [{"reachable": False, "error": "timed out"}, {"reachable": True}]
        with mock.patch.object(audit, "_tls_once", side_effect=results) as once:
            self.assertTrue(audit.check_tls("x.test")["reachable"])
        self.assertEqual(once.call_count, 2)

    def test_certificate_problem_is_final_and_not_retried(self):
        bad = {"reachable": False, "cert_problem": "expired"}
        with mock.patch.object(audit, "_tls_once", return_value=bad) as once:
            self.assertEqual(audit.check_tls("x.test")["cert_problem"], "expired")
        self.assertEqual(once.call_count, 1)

    def test_gives_up_after_the_retry(self):
        with mock.patch.object(audit, "_tls_once", return_value={"reachable": False, "error": "x"}) as once:
            self.assertFalse(audit.check_tls("x.test")["reachable"])
        self.assertEqual(once.call_count, 2)


class UnknownsExplained(unittest.TestCase):
    def test_classify_known_failures(self):
        import unknowns
        cases = {
            "<urlopen error [Errno 11001] getaddrinfo failed>": "dns",
            "net::ERR_NAME_NOT_RESOLVED at https://x.test/": "dns",
            "<urlopen error timed out>": "timeout",
            "Timeout 25000ms exceeded": "timeout",
            "[SSL: CERTIFICATE_VERIFY_FAILED] certificate has expired": "tls",
            "net::ERR_CERT_COMMON_NAME_INVALID": "tls",
            "Remote end closed connection without response": "connection",
            "[WinError 10061] No connection could be made": "connection",
            "no usable Edge or Chrome found": "missing_tool",
            "something odd": "unknown_error",
        }
        for text, reason in cases.items():
            with self.subTest(text=text):
                self.assertEqual(unknowns.classify(text), reason)

    def test_status_beats_text(self):
        import unknowns
        for status in (401, 403, 429):
            self.assertEqual(unknowns.classify("whatever", status), "blocked")
        self.assertEqual(unknowns.classify("", 503), "server_error")

    def test_every_reason_has_a_why_and_an_action(self):
        import unknowns
        for reason in unknowns.REASONS:
            r = unknowns.unavailable("m", reason)
            self.assertTrue(r["why"] and r["client_action"], reason)
            self.assertEqual((r["_unavailable"], r["reason"]), ("m", reason))

    def test_collectors_explain_why_they_could_not_check(self):
        err = (None, {"_error": "<urlopen error timed out>"}, "")
        with mock.patch.object(audit, "_get", return_value=err):
            for name in ("check_headers", "check_http_redirect", "check_privacy", "check_accessibility"):
                with self.subTest(check=name):
                    r = getattr(audit, name)("x.test")
                    self.assertEqual(r["reason"], "timeout")
                    self.assertIn("re-run", r["client_action"].lower())

    def test_dns_failure_for_email_is_explained(self):
        with mock.patch.object(audit, "_txt_records", return_value=None):
            self.assertEqual(audit.check_email_auth("x.test")["reason"], "dns")

    def test_a_refusal_is_reported_as_blocked_not_as_missing_headers(self):
        for status in (403, 429):
            with self.subTest(status=status), \
                 mock.patch.object(audit, "_get", return_value=(status, {"server": "waf"}, "denied")):
                home = audit._fetch_home("x.test")
                r = audit.check_headers("x.test", home)
                self.assertNotIn("missing", r)
                self.assertEqual(r["reason"], "blocked")
                self.assertEqual(audit.check_privacy("x.test", home)["reason"], "blocked")
                self.assertEqual(audit.check_accessibility("x.test", home)["reason"], "blocked")


class BrowserFallback(unittest.TestCase):
    EMPTY_SHELL = '<html><body><div id="root"></div><script src="/app.js"></script></body></html>'
    REAL_TEXT = "<html><body><p>" + "A real paragraph of content. " * 20 + "</p><script src='/a.js'></script></body></html>"

    def test_detects_script_built_pages(self):
        import browser_audit
        self.assertTrue(browser_audit.looks_js_rendered(self.EMPTY_SHELL))
        self.assertFalse(browser_audit.looks_js_rendered(self.REAL_TEXT))
        self.assertFalse(browser_audit.looks_js_rendered("<html><title>t</title></html>"))  # tiny but no scripts
        self.assertFalse(browser_audit.looks_js_rendered(""))

    def test_empty_shell_is_re_read_in_the_browser(self):
        import browser_audit
        rendered = (200, {"strict-transport-security": "max-age=1"}, "<html>" + "real " * 80 + "</html>")
        with mock.patch.object(audit, "_get", return_value=(200, {}, self.EMPTY_SHELL)), \
             mock.patch.object(browser_audit, "render_page", return_value=rendered) as render:
            status, headers, body = audit._fetch_home("x.test")
        render.assert_called_once_with("https://x.test/")
        self.assertIn("real", body)
        self.assertEqual(headers["_rendered"], "browser")

    def test_normal_page_is_not_sent_to_the_browser(self):
        import browser_audit
        with mock.patch.object(audit, "_get", return_value=(200, {}, self.REAL_TEXT)), \
             mock.patch.object(browser_audit, "render_page") as render:
            audit._fetch_home("x.test")
        render.assert_not_called()

    def test_browser_can_be_switched_off(self):
        import browser_audit
        with mock.patch.object(audit, "_get", return_value=(200, {}, self.EMPTY_SHELL)), \
             mock.patch.object(browser_audit, "render_page") as render:
            self.assertEqual(audit._fetch_home("x.test", render=False)[2], self.EMPTY_SHELL)
        render.assert_not_called()

    def test_failed_render_keeps_the_original_page(self):
        import browser_audit
        with mock.patch.object(audit, "_get", return_value=(200, {"a": "b"}, self.EMPTY_SHELL)), \
             mock.patch.object(browser_audit, "render_page", return_value=None):
            self.assertEqual(audit._fetch_home("x.test"), (200, {"a": "b"}, self.EMPTY_SHELL))

    def test_a_refusal_is_never_retried_in_the_browser(self):
        import browser_audit
        with mock.patch.object(audit, "_get", return_value=(403, {}, self.EMPTY_SHELL)), \
             mock.patch.object(browser_audit, "render_page") as render:
            self.assertIsNone(audit._fetch_home("x.test")[0])
        render.assert_not_called()


class Logging(unittest.TestCase):
    def test_failed_fetch_is_logged(self):
        with self.assertLogs("webaudit", level="WARNING") as cm:
            audit._get("https://127.0.0.1:1/")
        self.assertIn("failed", cm.output[0])


if __name__ == "__main__":
    unittest.main()
