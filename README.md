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
- Add axe-core/Pa11y (Node) for a real WCAG 2.1 AA audit
- Split the single report prompt into Accessibility / Privacy / Security agents
- Add a job queue + Postgres so you can scan many domains on a schedule
- (done) Allowlist of authorized targets and per-host rate limiting

## Guardrails to keep
- Respect robots.txt (already fetched)
- Gentle rate limits — hammering a site looks like an attack
- Keep collectors structurally incapable of active testing

## Tests
```bash
python -m unittest tests.test_audit -v   # offline: network is mocked, runs anywhere (seconds)
python -m unittest tests.test_live -v    # live: scans real test sites (about 2 minutes)
WEBAUDIT_LOG=1 python -m unittest tests.test_live -v   # same, with every request logged
```
Live tests only scan sites that are public and meant for testing: `badssl.com`
(deliberately broken certificates), `example.com`, `owasp.org` and `neverssl.com`.
They skip instead of failing when there is no network. Passive requests only.
