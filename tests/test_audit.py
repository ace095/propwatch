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


class Logging(unittest.TestCase):
    def test_failed_fetch_is_logged(self):
        with self.assertLogs("webaudit", level="WARNING") as cm:
            audit._get("https://127.0.0.1:1/")
        self.assertIn("failed", cm.output[0])


if __name__ == "__main__":
    unittest.main()
