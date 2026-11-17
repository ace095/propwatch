"""Live tests: passive scans of sites that are public, stable, and meant for testing.

Run:  python -m unittest tests.test_live -v      (add WEBAUDIT_LOG=1 for request logs)

Each site is scanned once and shared across tests. Tests skip, not fail, when
there is no network, and neverssl.com (slow and flaky by design) is tolerated.
"""
import functools
import logging
import os
import socket
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import audit

if os.environ.get("WEBAUDIT_LOG"):
    logging.basicConfig(level=logging.DEBUG, format="%(levelname)s %(message)s")


def online() -> bool:
    try:
        socket.create_connection(("example.com", 443), timeout=5).close()
        return True
    except OSError:
        return False


@functools.lru_cache(maxsize=None)
def scan(host: str) -> dict:
    return audit.run_audit(host)


@unittest.skipUnless(online(), "no network")
class BrokenCertificates(unittest.TestCase):
    """badssl.com serves deliberately broken certificates for exactly this."""

    def check(self, host, problem):
        tls = scan(host)["tls"]
        self.assertFalse(tls["reachable"])
        self.assertFalse(tls["cert_valid"])
        self.assertEqual(tls["cert_problem"], problem)

    def test_expired(self):
        self.check("expired.badssl.com", "expired")

    def test_self_signed(self):
        self.check("self-signed.badssl.com", "self_signed")

    def test_wrong_host(self):
        self.check("wrong.host.badssl.com", "hostname_mismatch")

    def test_unreachable_page_is_unknown_not_missing(self):
        r = scan("expired.badssl.com")
        for section in ("headers", "privacy", "accessibility"):
            self.assertIn("_unavailable", r[section], section)


@unittest.skipUnless(online(), "no network")
class ExampleCom(unittest.TestCase):
    """IANA's example.com: valid TLS, no security headers, strict mail policy."""

    def setUp(self):
        self.r = scan("example.com")

    def test_tls_is_valid(self):
        self.assertTrue(self.r["tls"]["reachable"])
        self.assertGreater(self.r["tls"]["days_until_expiry"], 0)

    def test_all_security_headers_missing(self):
        self.assertEqual(self.r["headers"]["present"], {})
        self.assertEqual(len(self.r["headers"]["missing"]), len(audit.SECURITY_HEADERS))

    def test_http_does_not_redirect(self):
        self.assertFalse(self.r["http_redirect"]["redirects_to_https"])

    def test_browser_audit_finds_no_wcag_failures(self):
        b = self.r["accessibility_browser"]
        if "_unavailable" in b:
            self.skipTest(b["_unavailable"])
        self.assertEqual(b["violations"], [])
        self.assertGreater(b["rules_passed"], 0)
        self.assertEqual(b["keyboard"]["reached_by_tab"], b["keyboard"]["focusable_elements"])

    def test_mail_policy(self):
        self.assertEqual(self.r["email_auth"]["spf"], "v=spf1 -all")
        self.assertIn("p=reject", self.r["email_auth"]["dmarc"])


@unittest.skipUnless(online(), "no network")
class OwaspOrg(unittest.TestCase):
    """OWASP follows its own advice: full header set and an HTTPS redirect."""

    def setUp(self):
        self.r = scan("owasp.org")

    def test_all_security_headers_present(self):
        self.assertEqual(self.r["headers"]["missing"], {})

    def test_http_redirects_to_https(self):
        redirect = self.r["http_redirect"]
        self.assertTrue(redirect["redirects_to_https"])
        self.assertIn(redirect["http_status"], (301, 302, 307, 308))

    def test_browser_audit_runs_axe_and_keyboard_test(self):
        b = self.r["accessibility_browser"]
        if "_unavailable" in b:
            self.skipTest(b["_unavailable"])
        self.assertIn("axe-core", b["engine"])
        self.assertGreater(b["rules_passed"], 5)
        self.assertGreater(b["keyboard"]["reached_by_tab"], 0)
        self.assertIsNone(b["keyboard"]["possible_keyboard_trap"])

    def test_homepage_is_parsed(self):
        self.assertTrue(self.r["accessibility"]["has_lang_attribute"])
        self.assertGreater(self.r["accessibility"]["images_total"], 0)


@unittest.skipUnless(online(), "no network")
class NeverSslCom(unittest.TestCase):
    """neverssl.com is plain HTTP on purpose, but is often slow, so be tolerant."""

    def test_plain_http_is_not_upgraded(self):
        redirect = scan("neverssl.com")["http_redirect"]
        if "_unavailable" in redirect:
            self.skipTest("neverssl.com did not answer in time")
        self.assertFalse(redirect["redirects_to_https"])


class ReportShape(unittest.TestCase):
    @unittest.skipUnless(online(), "no network")
    def test_result_has_every_section(self):
        r = scan("example.com")
        for key in ("target", "scanned_at", "scan_type", "robots", "tls", "headers",
                    "http_redirect", "email_auth", "privacy", "accessibility"):
            self.assertIn(key, r)
        self.assertEqual(r["scan_type"], "passive")


if __name__ == "__main__":
    unittest.main()
