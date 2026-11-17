"""UI server tests: real HTTP against a local server, scanner and Claude API mocked."""
import json
import os
import sys
import threading
import time
import unittest
import urllib.error
import urllib.request
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import audit
import ui

RESULT = {"target": "x.test", "scan_type": "passive", "tls": {"reachable": True}}


def fake_run_audit(domain, allowlist_path=None, on_step=None, **kwargs):
    for step in audit.AUDIT_STEPS:
        on_step(step, "running")
        on_step(step, "done")
    audit.log.info("fake scan of %s", domain)
    return dict(RESULT, target=domain)


class UiServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ui.make_server(0)
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.handler = ui.install_log_capture()

    @classmethod
    def tearDownClass(cls):
        audit.log.removeHandler(cls.handler)
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        db_dir = self.enterContext(self.tmp())
        env = mock.patch.dict(os.environ, {"WEBAUDIT_DB": os.path.join(db_dir, "ui.db")})
        env.start()
        self.addCleanup(env.stop)
        patches = [
            mock.patch.object(audit, "load_allowlist", return_value=["x.test"]),
            mock.patch.object(audit, "run_audit", side_effect=fake_run_audit),
            mock.patch.object(ui, "SCANS_DIR", self.enterContext(self.tmp())),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def tmp(self):
        import tempfile
        return tempfile.TemporaryDirectory()

    def call(self, path, data=None):
        req = urllib.request.Request(self.base + path,
                                     data=None if data is None else json.dumps(data).encode(),
                                     method="GET" if data is None else "POST")
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                body = r.read()
                return r.status, r.headers.get("Content-Type"), body
        except urllib.error.HTTPError as e:
            return e.code, e.headers.get("Content-Type"), e.read()

    def json(self, path, data=None):
        status, _, body = self.call(path, data)
        return status, json.loads(body)

    def wait_for(self, job_id, key="status", done=("done", "error")):
        for _ in range(100):
            _, job = self.json(f"/api/jobs/{job_id}")
            value = job[key] if key == "status" else job["report"]["status"]
            if value in done:
                return job
            time.sleep(0.05)
        self.fail("job did not finish")

    def test_index_page_is_served(self):
        status, ctype, body = self.call("/")
        self.assertEqual(status, 200)
        self.assertIn("text/html", ctype)
        self.assertIn(b"WebAudit", body)

    def test_targets_lists_the_allowlist(self):
        status, body = self.json("/api/targets")
        self.assertEqual(body["targets"], ["x.test"])

    def test_unauthorized_domain_is_refused_with_403(self):
        status, body = self.json("/api/scan", {"domain": "stranger.test"})
        self.assertEqual(status, 403)
        self.assertTrue(body["refused"])
        self.assertIn("not in the authorized targets list", body["error"])

    def test_bad_input_is_rejected(self):
        for bad in ("", "no-dot", "a b.test", "x.test:8080", "x.test;rm -rf"):
            with self.subTest(domain=bad):
                status, _ = self.json("/api/scan", {"domain": bad})
                self.assertIn(status, (400, 403))

    def test_scan_runs_reports_steps_and_logs_and_is_saved(self):
        status, job = self.json("/api/scan", {"domain": "https://X.test/page"})
        self.assertEqual(status, 200)
        job = self.wait_for(job["id"])
        self.assertEqual(job["status"], "done")
        self.assertEqual(job["domain"], "x.test")
        self.assertEqual(set(job["steps"].values()), {"done"})
        self.assertTrue(any("fake scan" in l["msg"] for l in job["log"]))
        self.assertTrue(os.path.exists(job["saved_to"]))

    def test_unknown_job_is_404(self):
        self.assertEqual(self.json("/api/jobs/abcdef123456")[0], 404)

    def test_json_download(self):
        _, job = self.json("/api/scan", {"domain": "x.test"})
        self.wait_for(job["id"])
        status, ctype, body = self.call(f"/api/jobs/{job['id']}/download?kind=json")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["target"], "x.test")

    def test_report_is_refused_before_scan_finishes_downloads_404_before_report(self):
        _, job = self.json("/api/scan", {"domain": "x.test"})
        self.wait_for(job["id"])
        self.assertEqual(self.call(f"/api/jobs/{job['id']}/download?kind=pdf")[0], 404)

    def test_report_generation_and_downloads(self):
        _, job = self.json("/api/scan", {"domain": "x.test"})
        self.wait_for(job["id"])
        import report
        with mock.patch.object(report, "_client"), \
             mock.patch.object(report, "report_single", return_value="# Report\n\nHTTP → HTTPS"):
            status, _ = self.json(f"/api/jobs/{job['id']}/report", {"sector": "School"})
            self.assertEqual(status, 200)
            done = self.wait_for(job["id"], key="report")
        self.assertEqual(done["report"]["status"], "done")
        self.assertIn("Report", done["report"]["markdown"])
        self.assertTrue(self.call(f"/api/jobs/{job['id']}/download?kind=pdf")[2].startswith(b"%PDF"))
        self.assertIn(b"# Report", self.call(f"/api/jobs/{job['id']}/download?kind=md")[2])

    def test_report_failure_is_reported_not_raised(self):
        _, job = self.json("/api/scan", {"domain": "x.test"})
        self.wait_for(job["id"])
        import report
        with mock.patch.object(report, "_client", side_effect=SystemExit("ANTHROPIC_API_KEY is not set")):
            self.json(f"/api/jobs/{job['id']}/report", {})
            done = self.wait_for(job["id"], key="report")
        self.assertEqual(done["report"]["status"], "error")
        self.assertIn("ANTHROPIC_API_KEY", done["report"]["error"])

    def test_second_scan_reports_what_changed(self):
        results = [dict(RESULT, headers={"missing": {"csp": "x", "hsts": "y"}}), dict(RESULT, headers={"missing": {"csp": "x"}})]
        with mock.patch.object(audit, "run_audit", side_effect=lambda *a, **k: results.pop(0)):
            _, first = self.json("/api/scan", {"domain": "x.test"})
            first = self.wait_for(first["id"])
            _, second = self.json("/api/scan", {"domain": "x.test"})
            second = self.wait_for(second["id"])
        self.assertTrue(first["diff"]["first_scan"])
        self.assertEqual(second["diff"]["resolved"], ["headers:missing:hsts"])
        self.assertEqual((second["diff"]["new"], second["diff"]["unchanged"]), ([], 1))

    def test_monitor_add_list_and_remove(self):
        status, body = self.json("/api/monitor", {"domain": "https://X.test/", "every_hours": 24})
        self.assertEqual(status, 200)
        self.assertEqual([(m["domain"], m["every_hours"]) for m in body["monitored"]], [("x.test", 24)])
        self.assertEqual(self.json("/api/monitor")[1]["monitored"][0]["domain"], "x.test")
        self.assertEqual(self.json("/api/monitor/remove", {"domain": "x.test"})[1]["monitored"], [])

    def test_monitor_refuses_unauthorized_and_bad_interval(self):
        status, body = self.json("/api/monitor", {"domain": "stranger.test"})
        self.assertEqual((status, body["refused"]), (403, True))
        self.assertEqual(self.json("/api/monitor", {"domain": "x.test", "every_hours": "soon"})[0], 400)

    def test_monitor_interval_is_clamped(self):
        _, body = self.json("/api/monitor", {"domain": "x.test", "every_hours": 999999})
        self.assertEqual(body["monitored"][0]["every_hours"], 24 * 90)

    def test_page_count_is_passed_to_the_scanner(self):
        with mock.patch.object(audit, "run_audit", side_effect=fake_run_audit) as run:
            _, job = self.json("/api/scan", {"domain": "x.test", "pages": 25})
            self.wait_for(job["id"])
            _, job = self.json("/api/scan", {"domain": "x.test"})
            self.wait_for(job["id"])
        self.assertEqual([c.kwargs["pages"] for c in run.call_args_list], [25, 5])

    def test_bad_page_counts_are_rejected(self):
        for bad in (-1, 201, "lots"):
            with self.subTest(pages=bad):
                self.assertEqual(self.json("/api/scan", {"domain": "x.test", "pages": bad})[0], 400)

    def test_scan_error_is_surfaced(self):
        with mock.patch.object(audit, "run_audit", side_effect=RuntimeError("boom")):
            _, job = self.json("/api/scan", {"domain": "x.test"})
            job = self.wait_for(job["id"])
        self.assertEqual((job["status"], job["error"]), ("error", "boom"))


if __name__ == "__main__":
    unittest.main()
