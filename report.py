#!/usr/bin/env python3
"""
Turn passive-scan findings into a client-ready report.

Two modes:
  --single   one model call writes the whole report (simplest)
  default    three specialist agents (security / privacy / accessibility)
             each analyze their slice, then a merge pass assembles the report

Usage:
    python report.py example.edu --sector "K-12 public school"
    python report.py --json out.json --sector "K-12 public school" --single

Needs: anthropic (pip install anthropic) and ANTHROPIC_API_KEY set.
"""

import os
import sys
import json
import argparse
import subprocess

MODEL = "claude-sonnet-5-5"

# Each agent sees only the finding keys listed, plus its own ruleset.
AGENTS = {
    "security": {
        "keys": ["tls", "headers", "http_redirect", "email_auth", "robots"],
        "rules": (
            "You assess transport & infrastructure security from PASSIVE findings.\n"
            "Weigh: expired/invalid TLS cert (Critical); http not redirecting to "
            "https (High); missing HSTS (Medium, High if login/forms present); "
            "no DMARC (High, spoofing/phishing); no SPF (Medium); missing CSP "
            "(Medium); missing X-Frame-Options / X-Content-Type-Options (Low-Medium).\n"
            "Standards: FERPA data-in-transit, PCI-DSS, state breach laws."
        ),
    },
    "privacy": {
        "keys": ["privacy", "headers", "email_auth"],
        "rules": (
            "You assess privacy & data-handling from PASSIVE findings.\n"
            "Weigh: analytics loaded with no cookie banner or policy (Medium, "
            "CCPA/GDPR); no privacy/accessibility policy page (Medium); permissive "
            "referrer-policy leaking URLs (Low-Medium).\n"
            "Standards (schools): FERPA, COPPA (under-13). Broadly: CCPA/GDPR."
        ),
    },
    "accessibility": {
        "keys": ["accessibility"],
        "rules": (
            "You assess accessibility from PASSIVE signals only (a full audit needs "
            "axe-core/Pa11y).\n"
            "Weigh: images missing alt text (Medium); missing html lang attribute "
            "(Low-Medium); no page title (Low-Medium).\n"
            "Standard: ADA / WCAG 2.1 AA. Flag that a full audit is still needed."
        ),
    },
}

COMMON = (
    "Only use facts in the JSON; never invent findings. If a value is "
    '"_unavailable", say it was not checked. These are PASSIVE findings -- say '
    '"indicates"/"suggests"/"no evidence of", never that the site was '
    "pen-tested. For each issue give severity (Critical/High/Medium/Low), a "
    "plain-English explanation, the standard it touches, and a concrete fix."
)


def _load_dotenv():
    """Load KEY=value lines from a .env next to this file (stdlib only).
    Real environment variables win over the file."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if not os.path.isfile(path):
        return
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            key = key.strip().removeprefix("export ").strip()
            val = val.strip().strip('"').strip("'")
            if key and val:
                os.environ.setdefault(key, val)


def _client():
    try:
        import anthropic
    except ImportError:
        sys.exit("Install the SDK first: pip install anthropic")
    _load_dotenv()
    if not os.environ.get("ANTHROPIC_API_KEY"):
        sys.exit("ANTHROPIC_API_KEY is not set. Copy .env.example to .env and "
                 "paste your key from https://platform.claude.com/settings/keys")
    return anthropic.Anthropic()


def _ask(client, system, user, max_tokens=8000):
    msg = client.messages.create(
        model=MODEL, max_tokens=max_tokens, system=system,
        messages=[{"role": "user", "content": user}],
    )
    return "".join(b.text for b in msg.content if b.type == "text")


def collect(domain):
    here = os.path.dirname(os.path.abspath(__file__))
    out = subprocess.run([sys.executable, os.path.join(here, "audit.py"), domain],
                         capture_output=True, text=True)
    if out.returncode != 0:
        sys.exit(f"audit.py failed:\n{out.stderr}")
    return json.loads(out.stdout)


def report_single(client, sector, findings):
    here = os.path.dirname(os.path.abspath(__file__))
    system = open(os.path.join(here, "system_prompt.txt")).read()
    user = (f"Sector: {sector}\nTarget: {findings.get('target')}\n\n"
            f"Raw passive-scan findings:\n{json.dumps(findings, indent=2)}\n\n"
            "Write the audit report.")
    return _ask(client, system, user, max_tokens=12000)


def report_agents(client, sector, findings):
    sections = {}
    for name, cfg in AGENTS.items():
        slice_ = {k: findings[k] for k in cfg["keys"] if k in findings}
        system = f"{cfg['rules']}\n\n{COMMON}"
        user = (f"Sector: {sector}\nTarget: {findings.get('target')}\n\n"
                f"Findings for your area:\n{json.dumps(slice_, indent=2)}\n\n"
                "Write your section: a short intro line, then each issue with "
                "severity, explanation, standard, and fix. If nothing is wrong, "
                "say so briefly.")
        sections[name] = _ask(client, system, user)

    body = "\n\n".join(f"## {n.title()}\n{t}" for n, t in sections.items())
    merge_system = (
        "You assemble a client-facing website audit from three specialist "
        "sections. Keep their findings intact. Add a one-paragraph executive "
        "summary at the top and a prioritized 'Top 5 fixes' list at the bottom, "
        "ordered by severity. Do not invent new findings."
    )
    merge_user = (f"Sector: {sector}\nTarget: {findings.get('target')}\n\n"
                  f"Specialist sections:\n\n{body}")
    return _ask(client, merge_system, merge_user, max_tokens=12000)


def main():
    ap = argparse.ArgumentParser(description="Generate an audit report from findings.")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("domain", nargs="?", help="e.g. example.edu (runs audit.py)")
    src.add_argument("--json", metavar="FILE", help="use existing findings JSON")
    ap.add_argument("--sector", default="organization", help='e.g. "K-12 public school"')
    ap.add_argument("--single", action="store_true", help="one call instead of agents")
    ap.add_argument("--out", metavar="FILE", help="write the report to a file")
    args = ap.parse_args()

    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    findings = (json.load(open(args.json, encoding="utf-8")) if args.json
                else collect(args.domain))
    client = _client()
    report = (report_single if args.single else report_agents)(
        client, args.sector, findings)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"[*] Wrote {args.out}", file=sys.stderr)
    print(report)


if __name__ == "__main__":
    main()
