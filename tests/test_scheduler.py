"""Scheduler tests: temporary SQLite database, fake scanner, injected clock."""
import contextlib
import io
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import audit
import scheduler

BAD = {
    "tls": {"reachable": True, "days_until_expiry": 12},
    "headers": {"missing": {"content-security-policy": "CSP", "referrer-policy": "RP"}, "present": {}},
    "http_redirect": {"redirects_to_https": False},
    "email_auth": {"spf": None, "dmarc": "v=DMARC1; p=none"},
    "privacy": {"policy_pages_found": [], "policy_links_found": []},
    "accessibility": {"issues": [{"rule": "Empty headings", "wcag": "1.3.1", "count": 1}]},
    "accessibility_browser": {"violations": [{"id": "color-contrast"}]},
    "pages": [{"url": "https://x.test/donate", "mixed_content_count": 2,
               "a11y_issues": [{"rule": "Form fields without a label"}],
               "axe": {"violations": [{"id": "label"}]}}],
}
CLEAN = {
    "tls": {"reachable": True, "days_until_expiry": 80},
    "headers": {"missing": {}, "present": {"a": "b"}},
    "http_redirect": {"redirects_to_https": True},
    "email_auth": {"spf": "v=spf1 -all", "dmarc": "v=DMARC1; p=reject"},
    "privacy": {"policy_pages_found": ["/privacy"]},
    "accessibility": {"issues": []},
}
T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


class IssueKeys(unittest.TestCase):
    def test_every_kind_of_problem_gets_a_key(self):
        self.assertEqual(scheduler.issue_keys(BAD), sorted([
            "tls:expiring_soon", "headers:missing:content-security-policy", "headers:missing:referrer-policy",
            "redirect:http_not_upgraded", "email:no_spf", "email:dmarc_not_enforced", "privacy:no_policy_page",
            "a11y:Empty headings", "axe:color-contrast", "page:/donate:mixed_content",
            "page:/donate:a11y:Form fields without a label", "page:/donate:axe:label"]))

    def test_clean_site_has_no_keys(self):
        self.assertEqual(scheduler.issue_keys(CLEAN), [])

    def test_unknown_is_not_reported_as_a_problem(self):
        unknown = {"tls": {"reachable": False, "error": "x"}, "headers": {"_unavailable": "no"},
                   "email_auth": {"_unavailable": "no"}, "privacy": {"_unavailable": "no"},
                   "http_redirect": {"_unavailable": "no"}, "accessibility": {"_unavailable": "no"}}
        self.assertEqual(scheduler.issue_keys(unknown), ["tls:unreachable"])

    def test_certificate_problem_is_named(self):
        self.assertEqual(scheduler.issue_keys({"tls": {"reachable": False, "cert_problem": "expired"}}), ["tls:expired"])

    def test_diff(self):
        self.assertEqual(scheduler.diff_issues(["a", "b"], ["b", "c"]), {"new": ["c"], "resolved": ["a"], "unchanged": 1})


class WithDb(unittest.TestCase):
    def setUp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.conn = scheduler.connect(os.path.join(d.name, "t.db"))
        self.addCleanup(self.conn.close)
        patch = mock.patch.object(audit, "load_allowlist", return_value=["x.test", "y.test"])
        patch.start()
        self.addCleanup(patch.stop)


class Storage(WithDb):
    def test_add_requires_authorization_and_normalizes(self):
        with self.assertRaises(audit.TargetNotAuthorized):
            scheduler.add_target(self.conn, "stranger.test")
        self.assertEqual(scheduler.add_target(self.conn, "https://X.test/page", 24, "School"), "x.test")
        scheduler.add_target(self.conn, "x.test", 48)  # updates, no duplicate
        rows = scheduler.summarize_targets(self.conn)
        self.assertEqual([(r["domain"], r["every_hours"]) for r in rows], [("x.test", 48)])

    def test_first_scan_then_diff_against_previous(self):
        first = scheduler.record_run(self.conn, "x.test", BAD)
        self.assertTrue(first["first_scan"])
        self.assertEqual(first["total"], 12)
        second = scheduler.record_run(self.conn, "x.test", CLEAN)
        self.assertFalse(second["first_scan"])
        self.assertEqual((len(second["new"]), len(second["resolved"])), (0, 12))
        third = scheduler.record_run(self.conn, "x.test", BAD)
        self.assertEqual((len(third["new"]), len(third["resolved"])), (12, 0))

    def test_failed_run_is_recorded_and_not_used_as_baseline(self):
        scheduler.record_run(self.conn, "x.test", BAD)
        scheduler.record_run(self.conn, "x.test", error="timeout")
        diff = scheduler.record_run(self.conn, "x.test", BAD)
        self.assertEqual((diff["new"], diff["resolved"]), ([], []))
        statuses = [h["status"] for h in scheduler.history(self.conn, "x.test")]
        self.assertEqual(statuses, ["ok", "error", "ok"])

    def test_history_shows_what_changed_each_time(self):
        scheduler.record_run(self.conn, "x.test", BAD)
        scheduler.record_run(self.conn, "x.test", CLEAN)
        newest, oldest = scheduler.history(self.conn, "x.test")
        self.assertEqual((newest["total"], len(newest["resolved"])), (0, 12))
        self.assertEqual((oldest["total"], len(oldest["new"])), (12, 12))

    def test_remove(self):
        scheduler.add_target(self.conn, "x.test")
        self.assertTrue(scheduler.remove_target(self.conn, "x.test"))
        self.assertFalse(scheduler.remove_target(self.conn, "x.test"))


class Scheduling(WithDb):
    def test_never_scanned_is_due_and_recent_is_not(self):
        scheduler.add_target(self.conn, "x.test", 24)
        self.assertEqual([t["domain"] for t in scheduler.due_targets(self.conn, T0)], ["x.test"])
        with mock.patch.object(scheduler, "_now", return_value=T0):
            scheduler.record_run(self.conn, "x.test", CLEAN)
        self.assertEqual(scheduler.due_targets(self.conn, T0 + timedelta(hours=23)), [])
        self.assertEqual(len(scheduler.due_targets(self.conn, T0 + timedelta(hours=24))), 1)

    def test_run_due_scans_all_and_one_failure_does_not_stop_the_rest(self):
        scheduler.add_target(self.conn, "x.test", 24)
        scheduler.add_target(self.conn, "y.test", 24)

        def scan(domain):
            if domain == "x.test":
                raise RuntimeError("site down")
            return CLEAN

        results = scheduler.run_due(self.conn, T0, scan=scan)
        self.assertEqual({(r["domain"], r["status"]) for r in results}, {("x.test", "error"), ("y.test", "ok")})
        self.assertEqual(scheduler.history(self.conn, "x.test")[0]["error"], "site down")
        self.assertEqual(scheduler.history(self.conn, "y.test")[0]["status"], "ok")

    def test_failed_site_is_not_hammered_every_run(self):
        scheduler.add_target(self.conn, "x.test", 24)
        with mock.patch.object(scheduler, "_now", return_value=T0):
            scheduler.run_due(self.conn, T0, scan=mock.Mock(side_effect=RuntimeError("down")))
        self.assertEqual(scheduler.due_targets(self.conn, T0 + timedelta(hours=1)), [])


class CommandLine(unittest.TestCase):
    def run_cli(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = scheduler.main(list(argv))
        return code, out.getvalue()

    def setUp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        env = mock.patch.dict(os.environ, {"WEBAUDIT_DB": os.path.join(d.name, "cli.db")})
        env.start()
        self.addCleanup(env.stop)
        allow = mock.patch.object(audit, "load_allowlist", return_value=["x.test"])
        allow.start()
        self.addCleanup(allow.stop)

    def test_add_list_run_due_and_diff(self):
        self.assertEqual(self.run_cli("add", "x.test", "--every", "12")[0], 0)
        self.assertIn("x.test", self.run_cli("list")[1])
        with mock.patch.object(audit, "run_audit", return_value=BAD):
            code, out = self.run_cli("run-due")
        self.assertEqual(code, 0)
        self.assertIn("12 issues (first scan)", out)
        with mock.patch.object(audit, "run_audit", return_value=CLEAN):
            code, out = self.run_cli("run", "x.test")
        self.assertIn("0 new, 12 resolved", out)
        self.assertIn("- tls:expiring_soon", out)
        self.assertIn("0 new, 12 resolved", self.run_cli("diff", "x.test")[1])

    def test_add_unauthorized_exits_2(self):
        self.assertEqual(self.run_cli("add", "stranger.test")[0], 2)

    def test_run_unmonitored_exits_2(self):
        self.assertEqual(self.run_cli("run", "x.test")[0], 2)


if __name__ == "__main__":
    unittest.main()
