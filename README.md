# WebAudit — passive website compliance & security audit (MVP)

Reads **public** information about a website and turns it into a client-ready
compliance report. Built to be the front door of an audit service: run the free
passive scan, hand over the findings, close the paid engagement.

## What it checks (all passive)
- TLS/SSL: reachable, version, cert issuer, days-to-expiry
- HTTP→HTTPS redirect
- Security headers: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- Email auth DNS: SPF, DMARC (+ DKIM note)
- Privacy signals: policy pages, cookie mentions, analytics, cookie-banner hint
- Accessibility signals: `lang` attr, page title, images missing alt text

- Real-browser accessibility audit: axe-core (WCAG 2.1 A/AA, including colour contrast)
  plus a keyboard Tab test (reachability, visible focus, keyboard traps). Uses the Edge or
  Chrome already installed; add `--no-browser` to skip it. If no browser is found the
  report says it was not run, never that the page passed.

- Other pages: finds up to 5 important same-site pages (privacy, terms, contact, login...)
  from homepage links and the sitemap, skips anything `robots.txt` disallows, and checks
  each for accessibility issues, insecure `http://` resources and login forms (axe on the
  first 3). Use `--pages N` (0 = homepage only).

- Full-site option: `--full-site` (or `--pages 50`) keeps following links from the pages it
  visits, up to a hard ceiling of 200 pages, still respecting `robots.txt` and the rate
  limit. In the UI, pick the page count next to the domain.
- Script-built sites: if the homepage is an empty shell that scripts fill in, it is re-read
  in a real browser (which also gives the true response headers). This is never used to
  get past a refusal.
- Nothing is silently "unknown": every check that could not run says why (dns, timeout,
  connection, tls, blocked, server_error, missing_tool) and what the client can do about it.
  A site that answers 401/403/429 is reported as *blocked*, not judged from its error page.
  We do not try to defeat bot protection; the client allows our scanner instead.

## What it deliberately does NOT do
No login testing, no vuln probing, no port scans, no payloads. Passive only.
Running active tests on a site you don't own/weren't authorized to test can be
a federal crime (CFAA). Keep it passive until you have signed authorization.

## Setup
```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt   # optional but recommended
```

## Who you may scan
The scanner only scans domains listed in `authorized_targets.txt` (a listed domain
also covers its subdomains). Anything else is refused before any request is sent,
with exit code 2. Add a client only after they have authorized the scan in writing,
and note who and when on the same line:
```
client-school.edu   # signed by J. Smith, 2026-11-20
```
Use another file with `--allowlist FILE` or the `WEBAUDIT_ALLOWLIST` environment variable.

## Web UI (see the process live)
```bash
python ui.py          # then open http://127.0.0.1:8765
```
Type or pick an authorized domain and press **Run scan**. Each check lights up as it
runs, the request log streams underneath, and the results appear as Good / Needs
attention / Problem / Unknown cards. From there you can download the findings (JSON),
generate the written report (uses Claude API credits, asks first) and download it as
Markdown or PDF. Every scan is also saved under `scans/`. The UI listens on this
computer only (127.0.0.1) and still refuses unauthorized targets.

## Scheduled scans and history
```bash
python scheduler.py add client.edu --every 168 --sector "K-12 public school"   # weekly
python scheduler.py run-due      # scan whatever is due (put this in Windows Task Scheduler)
python scheduler.py diff client.edu      # what is new / fixed since the previous scan
python scheduler.py history client.edu
python ui.py --schedule          # or let the UI run due scans itself
```
Results are kept in `webaudit.db` (SQLite). Each scan is compared with the previous
successful one: new problems, fixed problems, unchanged. A site that fails to scan is
recorded as a failure and is not hammered again before its next slot. Only authorized
targets can be added.

## Run a scan
```bash
python audit.py example.edu                 # prints JSON
python audit.py example.edu --json out.json # also saves it
python audit.py example.edu -v              # log every request to stderr
```

## Generate a report
```bash
cp .env.example .env   # then paste your key from https://platform.claude.com/settings/keys
python report.py example.edu --sector "K-12 public school" --single
python report.py example.edu --sector "K-12 public school" --single --pdf report.pdf
python pdf_export.py report.md report.pdf    # convert an existing markdown report
```

## The business flow this supports
1. Passive scan (free) → findings
2. Cold outreach with the findings
3. They sign an engagement (authorization)
4. Deep scan + remediation (the paid part)

## Roadmap (next steps)
- (done) Real-browser WCAG audit with axe-core
- Split the single report prompt into Accessibility / Privacy / Security agents
- (done) Scheduled scans with history (SQLite); move to Postgres and a job queue when scanning hundreds of sites
- (done) Allowlist of authorized targets and per-host rate limiting

## Guardrails to keep
- Respect robots.txt (already fetched)
- Gentle rate limits — hammering a site looks like an attack
- Keep collectors structurally incapable of active testing

## Tests
```bash
python -m unittest tests.test_audit tests.test_crawler tests.test_scheduler tests.test_ui tests.test_browser_local -v
# ^ offline: network and Claude API mocked (about 30 seconds); test_browser_local uses your Edge/Chrome on a local page
python -m unittest tests.test_live -v    # live: scans real test sites (about 2 minutes)
WEBAUDIT_LOG=1 python -m unittest tests.test_live -v   # same, with every request logged
```
Live tests only scan sites that are public and meant for testing: `badssl.com`
(deliberately broken certificates), `example.com`, `owasp.org` and `neverssl.com`.
They skip instead of failing when there is no network. Passive requests only.
