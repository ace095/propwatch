#!/usr/bin/env python3
"""Recurring scans with history: what is new, and what got fixed, since last time.

    python scheduler.py add client.edu --every 168 --sector "K-12 public school"
    python scheduler.py list
    python scheduler.py run-due          # run from Windows Task Scheduler or cron
    python scheduler.py loop             # or leave this running
    python scheduler.py history client.edu
    python scheduler.py diff client.edu

Data lives in webaudit.db (SQLite, standard library). Only authorized targets can be added.
"""
import argparse
import json
import logging
import os
import sqlite3
import sys
import time
from contextlib import closing
from datetime import datetime, timedelta, timezone

import audit

log = logging.getLogger("webaudit.scheduler")
HERE = os.path.dirname(os.path.abspath(__file__))

SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
  domain TEXT PRIMARY KEY, interval_hours INTEGER NOT NULL, sector TEXT, added_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT, domain TEXT NOT NULL, started_at TEXT NOT NULL,
  finished_at TEXT, status TEXT NOT NULL, error TEXT, issues TEXT, findings TEXT);
CREATE INDEX IF NOT EXISTS runs_domain ON runs(domain, id);
"""


def db_path() -> str:
    return os.environ.get("WEBAUDIT_DB") or os.path.join(HERE, "webaudit.db")


def connect(path: str = None) -> sqlite3.Connection:
    conn = sqlite3.connect(path or db_path())
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat(timespec="seconds")


# ---------- turning a scan into comparable issue keys ----------

def issue_keys(r: dict) -> list:
    """Stable identifiers for every problem in a scan, so two scans can be diffed."""
    keys = set()
    tls = r.get("tls") or {}
    if tls.get("cert_problem"):
        keys.add(f"tls:{tls['cert_problem']}")
    elif tls.get("reachable") is False and tls:
        keys.add("tls:unreachable")
    elif (tls.get("days_until_expiry") or 999) < 30:
        keys.add("tls:expiring_soon")
    headers = r.get("headers") or {}
    for name in headers.get("missing", {}):
        keys.add(f"headers:missing:{name}")
    if (r.get("http_redirect") or {}).get("redirects_to_https") is False:
        keys.add("redirect:http_not_upgraded")
    email = r.get("email_auth") or {}
    if email and "_unavailable" not in email:
        if not email.get("spf"):
            keys.add("email:no_spf")
        if not email.get("dmarc") and "dmarc_unavailable" not in email:
            keys.add("email:no_dmarc")
        elif "p=none" in (email.get("dmarc") or "").replace(" ", "").lower():
            keys.add("email:dmarc_not_enforced")
    privacy = r.get("privacy") or {}
    if privacy and "_unavailable" not in privacy and not privacy.get("policy_pages_found") \
            and not privacy.get("policy_links_found"):
        keys.add("privacy:no_policy_page")
    for issue in (r.get("accessibility") or {}).get("issues", []):
        keys.add(f"a11y:{issue['rule']}")
    for v in (r.get("accessibility_browser") or {}).get("violations", []):
        keys.add(f"axe:{v['id']}")
    for page in r.get("pages") or []:
        path = page["url"].split("//", 1)[-1].split("/", 1)[-1] or "/"
        if page.get("mixed_content_count"):
            keys.add(f"page:/{path}:mixed_content")
        for issue in page.get("a11y_issues", []):
            keys.add(f"page:/{path}:a11y:{issue['rule']}")
        for v in (page.get("axe") or {}).get("violations", []):
            keys.add(f"page:/{path}:axe:{v['id']}")
    return sorted(keys)


def diff_issues(previous: list, current: list) -> dict:
    prev, cur = set(previous), set(current)
    return {"new": sorted(cur - prev), "resolved": sorted(prev - cur), "unchanged": len(cur & prev)}


# ---------- storage ----------

def add_target(conn, domain: str, every_hours: int = 168, sector: str = None) -> str:
    host = audit._norm(domain)
    audit.require_authorized(host)
    with conn:
        conn.execute("INSERT INTO targets(domain, interval_hours, sector, added_at) VALUES (?,?,?,?) "
                     "ON CONFLICT(domain) DO UPDATE SET interval_hours=excluded.interval_hours, sector=excluded.sector",
                     (host, every_hours, sector, _iso(_now())))
    return host


def remove_target(conn, domain: str) -> bool:
    with conn:
        return conn.execute("DELETE FROM targets WHERE domain=?", (audit._norm(domain),)).rowcount > 0


def record_run(conn, domain: str, result: dict = None, error: str = None, started: datetime = None) -> dict:
    """Store one scan (or failure) and return its diff against the previous successful run."""
    keys = issue_keys(result) if result else None
    previous = latest_ok(conn, domain)
    with conn:
        conn.execute("INSERT INTO runs(domain, started_at, finished_at, status, error, issues, findings) "
                     "VALUES (?,?,?,?,?,?,?)",
                     (domain, _iso(started or _now()), _iso(_now()), "error" if error else "ok", error,
                      json.dumps(keys) if keys is not None else None,
                      json.dumps(result, default=str) if result else None))
    if keys is None:
        return {"new": [], "resolved": [], "unchanged": 0, "first_scan": previous is None}
    d = diff_issues(json.loads(previous["issues"]) if previous else [], keys)
    d["first_scan"] = previous is None
    d["total"] = len(keys)
    return d


def latest_ok(conn, domain: str, offset: int = 0):
    return conn.execute("SELECT * FROM runs WHERE domain=? AND status='ok' ORDER BY id DESC LIMIT 1 OFFSET ?",
                        (domain, offset)).fetchone()


def history(conn, domain: str, limit: int = 20) -> list:
    # One extra row, so the oldest row returned can still be compared with its predecessor.
    rows = conn.execute("SELECT id, started_at, status, error, issues FROM runs WHERE domain=? ORDER BY id DESC LIMIT ?",
                        (audit._norm(domain), limit + 1)).fetchall()
    out, newer_to_older = [], list(rows)
    for i, row in enumerate(newer_to_older[:limit]):
        older = next((r for r in newer_to_older[i + 1:] if r["status"] == "ok"), None)
        item = {"id": row["id"], "started_at": row["started_at"], "status": row["status"], "error": row["error"]}
        if row["status"] == "ok":
            cur = json.loads(row["issues"])
            item.update(total=len(cur), **{k: v for k, v in diff_issues(
                json.loads(older["issues"]) if older else [], cur).items()})
        out.append(item)
    return out


def due_targets(conn, now: datetime = None) -> list:
    now = now or _now()
    due = []
    for t in conn.execute("SELECT * FROM targets ORDER BY domain"):
        last = conn.execute("SELECT started_at FROM runs WHERE domain=? ORDER BY id DESC LIMIT 1", (t["domain"],)).fetchone()
        if last is None or datetime.fromisoformat(last["started_at"]) + timedelta(hours=t["interval_hours"]) <= now:
            due.append(t)
    return due


def run_due(conn, now: datetime = None, scan=None) -> list:
    """Scan every target that is due. One failure never stops the others."""
    scan = scan or audit.run_audit
    results = []
    for t in due_targets(conn, now):
        started = _now()
        log.info("scanning %s (every %sh)", t["domain"], t["interval_hours"])
        try:
            diff = record_run(conn, t["domain"], result=scan(t["domain"]), started=started)
            results.append({"domain": t["domain"], "status": "ok", **diff})
        except Exception as e:  # recorded, so a broken site shows up in its history
            log.error("%s failed: %s", t["domain"], e)
            record_run(conn, t["domain"], error=str(e), started=started)
            results.append({"domain": t["domain"], "status": "error", "error": str(e)})
    return results


def summarize_targets(conn) -> list:
    out = []
    for t in conn.execute("SELECT * FROM targets ORDER BY domain"):
        h = history(conn, t["domain"], limit=2)
        last = h[0] if h else None
        out.append({"domain": t["domain"], "every_hours": t["interval_hours"], "sector": t["sector"],
                    "last_run": last["started_at"] if last else None, "last_status": last["status"] if last else None,
                    "total": last.get("total") if last else None,
                    "new": last.get("new", []) if last else [], "resolved": last.get("resolved", []) if last else []})
    return out


# ---------- command line ----------

def _print_diff(domain, d):
    print(f"{domain}: {d.get('total', 0)} issues"
          + (" (first scan)" if d.get("first_scan") else f", {len(d['new'])} new, {len(d['resolved'])} resolved"))
    for k in d.get("new", []):
        print(f"  + {k}")
    for k in d.get("resolved", []):
        print(f"  - {k}")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Recurring passive scans with history.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("add", help="monitor a site (must be authorized)")
    p.add_argument("domain"); p.add_argument("--every", type=int, default=168, metavar="HOURS")
    p.add_argument("--sector")
    sub.add_parser("remove", help="stop monitoring").add_argument("domain")
    sub.add_parser("list", help="monitored sites and their latest state")
    sub.add_parser("run-due", help="scan every site that is due now")
    sub.add_parser("run", help="scan one monitored site right now").add_argument("domain")
    sub.add_parser("history", help="past scans of a site").add_argument("domain")
    sub.add_parser("diff", help="what changed in the latest scan").add_argument("domain")
    p = sub.add_parser("loop", help="run-due forever")
    p.add_argument("--every-minutes", type=int, default=15)
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s", stream=sys.stderr)

    with closing(connect()) as conn:
        if args.cmd == "add":
            try:
                host = add_target(conn, args.domain, args.every, args.sector)
            except audit.TargetNotAuthorized as e:
                log.error("%s", e)
                return 2
            print(f"monitoring {host} every {args.every}h")
        elif args.cmd == "remove":
            print("removed" if remove_target(conn, args.domain) else "not monitored")
        elif args.cmd == "list":
            for t in summarize_targets(conn):
                print(f"{t['domain']:<30} every {t['every_hours']}h  last: {t['last_run'] or 'never'}"
                      f"  issues: {t['total'] if t['total'] is not None else '-'}")
        elif args.cmd in ("run", "run-due"):
            if args.cmd == "run":
                host = audit._norm(args.domain)
                if not conn.execute("SELECT 1 FROM targets WHERE domain=?", (host,)).fetchone():
                    log.error("%s is not monitored; add it first", host)
                    return 2
                results = run_due_one(conn, host)
            else:
                results = run_due(conn)
            for r in results:
                if r["status"] == "ok":
                    _print_diff(r["domain"], r)
                else:
                    print(f"{r['domain']}: FAILED {r['error']}")
            print(f"{len(results)} scan(s) run")
        elif args.cmd == "history":
            for h in history(conn, args.domain):
                print(f"{h['started_at']}  {h['status']:<5}  "
                      + (f"{h['total']} issues, {len(h['new'])} new, {len(h['resolved'])} resolved" if h["status"] == "ok" else h["error"]))
        elif args.cmd == "diff":
            h = history(conn, args.domain, 1)
            if not h or h[0]["status"] != "ok":
                print("no successful scan yet")
                return 1
            _print_diff(audit._norm(args.domain), dict(h[0], first_scan=False))
        elif args.cmd == "loop":
            while True:
                run_due(conn)
                time.sleep(args.every_minutes * 60)
    return 0


def run_due_one(conn, host: str) -> list:
    """Scan one target now, regardless of its schedule."""
    started = _now()
    try:
        diff = record_run(conn, host, result=audit.run_audit(host), started=started)
        return [{"domain": host, "status": "ok", **diff}]
    except Exception as e:
        record_run(conn, host, error=str(e), started=started)
        return [{"domain": host, "status": "error", "error": str(e)}]


if __name__ == "__main__":
    sys.exit(main())
