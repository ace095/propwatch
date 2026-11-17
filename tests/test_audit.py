"""Offline tests: network is mocked, so they run anywhere."""
import os, sys, unittest
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


if __name__ == "__main__":
    unittest.main()
