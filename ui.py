#!/usr/bin/env python3
"""Local web UI for webaudit: run a passive scan and watch it happen.

    python ui.py            # then open http://127.0.0.1:8765
    python ui.py --port 9000

Standard library only. Listens on 127.0.0.1, so it is reachable from this
computer only. Scans are still restricted to authorized_targets.txt.
"""
import argparse
import json
import logging
import os
import re
import tempfile
import threading
import time
import uuid
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import audit
import crawler
import scheduler
from contextlib import closing

HERE = os.path.dirname(os.path.abspath(__file__))
SCANS_DIR = os.path.join(HERE, "scans")
STATIC = os.path.join(HERE, "ui_static", "index.html")
log = logging.getLogger("webaudit.ui")

JOBS: dict = {}
_current = threading.local()


class _JobLogHandler(logging.Handler):
    """Copies log lines emitted by a job's worker thread into that job."""

    def emit(self, record):
        job = getattr(_current, "job", None)
        if job is not None:
            job["log"].append({"t": time.strftime("%H:%M:%S"),
                               "level": record.levelname,
                               "msg": record.getMessage()})


def install_log_capture() -> logging.Handler:
    """Send the scanner's log lines (including debug requests) into each job's log."""
    handler = _JobLogHandler()
    logger = logging.getLogger("webaudit")
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    return handler


def _new_job(domain: str) -> dict:
    job = {"id": uuid.uuid4().hex[:12], "domain": domain, "status": "running",
           "steps": {s: "pending" for s in audit.AUDIT_STEPS}, "log": [],
           "result": None, "error": None, "saved_to": None, "diff": None,
           "report": {"status": "none", "markdown": None, "error": None}}
    JOBS[job["id"]] = job
    return job


def _save(result: dict) -> str:
    os.makedirs(SCANS_DIR, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    path = os.path.join(SCANS_DIR, f"{result['target']}-{stamp}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, default=str)
    return path


def _scan_worker(job: dict, pages: int = 5) -> None:
    _current.job = job
    try:
        job["result"] = audit.run_audit(
            job["domain"], pages=pages,
            on_step=lambda name, state: job["steps"].update({name: state}))
        job["saved_to"] = _save(job["result"])
        log.info("Saved %s", job["saved_to"])
        with closing(scheduler.connect()) as conn:
            job["diff"] = scheduler.record_run(conn, job["domain"], result=job["result"])
        log.info("Compared with the previous scan: %d new, %d resolved",
                 len(job["diff"]["new"]), len(job["diff"]["resolved"]))
        job["status"] = "done"
    except Exception as e:  # shown to the user, never silently dropped
        log.exception("scan failed")
        job["error"], job["status"] = str(e), "error"


def _report_worker(job: dict, sector: str) -> None:
    _current.job = job
    rep = job["report"]
    try:
        import report
        log.info("Generating report with the Claude API (sector: %s)", sector)
        rep["markdown"] = report.report_single(report._client(), sector, job["result"])
        rep["status"] = "done"
        log.info("Report ready (%d characters)", len(rep["markdown"]))
    except (Exception, SystemExit) as e:  # _client() exits when the API key is missing
        log.error("report failed: %s", e)
        rep["error"], rep["status"] = str(e) or "report failed", "error"


def targets() -> dict:
    return {"targets": audit.load_allowlist(),
            "file": os.environ.get("WEBAUDIT_ALLOWLIST") or audit.DEFAULT_ALLOWLIST}


def start_scan(domain: str, pages=5) -> dict:
    """Validate, check authorization, then scan in the background."""
    host = audit._norm(domain or "")
    if not re.fullmatch(r"[a-z0-9]([a-z0-9.-]*[a-z0-9])?", host) or "." not in host:
        raise ValueError("Enter a domain like example.com")
    try:
        pages = int(5 if pages is None else pages)
    except (TypeError, ValueError):
        raise ValueError("pages must be a number")
    if not 0 <= pages <= crawler.MAX_PAGE_LIMIT:
        raise ValueError(f"pages must be between 0 and {crawler.MAX_PAGE_LIMIT}")
    audit.require_authorized(host)  # raises TargetNotAuthorized before any request
    job = _new_job(host)
    threading.Thread(target=_scan_worker, args=(job, pages), daemon=True).start()
    return job


def public(job: dict) -> dict:
    return {k: job[k] for k in
            ("id", "domain", "status", "steps", "log", "result", "error", "saved_to", "diff", "report")}


def pdf_bytes(markdown_text: str) -> bytes:
    from pdf_export import markdown_to_pdf
    with tempfile.TemporaryDirectory() as d:
        path = markdown_to_pdf(markdown_text, os.path.join(d, "report.pdf"))
        with open(path, "rb") as f:
            return f.read()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        log.debug("%s %s", self.address_string(), fmt % args)

    def _send(self, code, body, ctype="application/json", extra=None):
        data = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj, default=str))

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}") if n else {}

    def _job(self, job_id):
        job = JOBS.get(job_id)
        if job is None:
            self._json(404, {"error": "unknown job"})
        return job

    def do_GET(self):
        path, _, query = self.path.partition("?")
        if path == "/":
            with open(STATIC, "rb") as f:
                return self._send(200, f.read(), "text/html; charset=utf-8")
        if path == "/api/targets":
            return self._json(200, targets())
        if path == "/api/monitor":
            with closing(scheduler.connect()) as conn:
                return self._json(200, {"monitored": scheduler.summarize_targets(conn)})
        m = re.fullmatch(r"/api/jobs/([0-9a-f]+)", path)
        if m and (job := self._job(m.group(1))):
            return self._json(200, public(job))
        m = re.fullmatch(r"/api/jobs/([0-9a-f]+)/download", path)
        if m and (job := self._job(m.group(1))):
            return self._download(job, query)
        self._json(404, {"error": "not found"})

    def _monitor(self, data):
        domain = data.get("domain") or ""
        with closing(scheduler.connect()) as conn:
            if self.path.endswith("/remove"):
                scheduler.remove_target(conn, domain)
            else:
                try:
                    every = max(1, min(int(data.get("every_hours") or 168), 24 * 90))
                    scheduler.add_target(conn, domain, every, (data.get("sector") or "")[:80] or None)
                except audit.TargetNotAuthorized as e:
                    return self._json(403, {"error": str(e), "refused": True})
                except ValueError:
                    return self._json(400, {"error": "every_hours must be a number"})
            return self._json(200, {"monitored": scheduler.summarize_targets(conn)})

    def _download(self, job, query):
        kind = dict(p.split("=", 1) for p in query.split("&") if "=" in p).get("kind")
        name = f"{job['domain']}-audit"
        if kind == "json" and job["result"]:
            body = json.dumps(job["result"], indent=2, default=str)
            return self._send(200, body, "application/json",
                              {"Content-Disposition": f'attachment; filename="{name}.json"'})
        md = job["report"]["markdown"]
        if kind == "md" and md:
            return self._send(200, md, "text/markdown; charset=utf-8",
                              {"Content-Disposition": f'attachment; filename="{name}.md"'})
        if kind == "pdf" and md:
            return self._send(200, pdf_bytes(md), "application/pdf",
                              {"Content-Disposition": f'attachment; filename="{name}.pdf"'})
        self._json(404, {"error": "nothing to download yet"})

    def do_POST(self):
        try:
            data = self._body()
        except ValueError:
            return self._json(400, {"error": "invalid JSON"})
        if self.path == "/api/scan":
            try:
                return self._json(200, public(start_scan(data.get("domain"), data.get("pages"))))
            except audit.TargetNotAuthorized as e:
                return self._json(403, {"error": str(e), "refused": True})
            except ValueError as e:
                return self._json(400, {"error": str(e)})
        if self.path in ("/api/monitor", "/api/monitor/remove"):
            return self._monitor(data)
        m = re.fullmatch(r"/api/jobs/([0-9a-f]+)/report", self.path)
        if m and (job := self._job(m.group(1))):
            if job["status"] != "done":
                return self._json(409, {"error": "scan has not finished"})
            if job["report"]["status"] == "running":
                return self._json(409, {"error": "report already running"})
            job["report"].update(status="running", error=None, markdown=None)
            sector = (data.get("sector") or "organization")[:80]
            threading.Thread(target=_report_worker, args=(job, sector), daemon=True).start()
            return self._json(200, public(job))
        self._json(404, {"error": "not found"})


def _schedule_loop(every_minutes: int = 15) -> None:
    while True:
        try:
            with closing(scheduler.connect()) as conn:
                scheduler.run_due(conn)
        except Exception:
            log.exception("scheduled run failed")
        time.sleep(every_minutes * 60)


def make_server(port: int = 8765) -> ThreadingHTTPServer:
    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def main():
    ap = argparse.ArgumentParser(description="webaudit local web UI")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--schedule", action="store_true",
                    help="also run monitored sites when they are due (checks every 15 minutes)")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    install_log_capture()
    if args.schedule:
        threading.Thread(target=_schedule_loop, daemon=True).start()
    server = make_server(args.port)
    log.info("webaudit UI on http://127.0.0.1:%d  (Ctrl+C to stop)", args.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
