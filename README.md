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

## Run a scan
```bash
python audit.py example.edu                 # prints JSON
python audit.py example.edu --json out.json # also saves it
```

## Generate a report
```bash
cp .env.example .env   # then paste your key from https://platform.claude.com/settings/keys
python report.py example.edu --sector "K-12 public school" --single
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
- PDF export of the report
- Rate limiting + allowlist baked into the crawler

## Guardrails to keep
- Respect robots.txt (already fetched)
- Gentle rate limits — hammering a site looks like an attack
- Keep collectors structurally incapable of active testing

## Tests
```bash
python -m unittest discover -s tests -v   # offline, no network needed
```
