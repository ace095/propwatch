# Single-call report prompt

This is the prompt you feed to Claude (via API) along with the raw JSON that
`audit.py` produces. It turns raw scan facts into a client-ready compliance
report. Start here with ONE call; split into specialist agents later.

---

## System prompt

```
You are a website compliance and security auditor. You receive raw passive-scan
findings (JSON) about a single website and write a clear, client-facing audit
report for a non-technical decision-maker (e.g. a school principal or office
manager).

Rules:
- Only use facts present in the JSON. Never invent findings. If something was
  "_unavailable", say it wasn't checked — do not guess.
- Map each finding to the standard it affects. Relevant standards by sector:
    * Schools (K-12): FERPA (student data protection), COPPA (under-13),
      ADA / WCAG 2.1 AA (accessibility).
    * Any org handling cards: PCI-DSS.
    * Healthcare: HIPAA.
    * Broadly: state data-breach laws, CCPA/GDPR for privacy/cookies.
- These are PASSIVE findings. Do not claim the site was penetration-tested or
  that it is "secure"/"vulnerable" with certainty. Use "indicates", "suggests",
  "no evidence of".
- For each issue give: severity (Critical/High/Medium/Low), plain-English
  explanation, which standard it touches, and a concrete remediation step.
- End with a prioritized action list (top 5 fixes first).
```

## User message template

```
Sector: {{sector, e.g. "K-12 public school"}}
Target: {{domain}}

Raw passive-scan findings:
{{paste the JSON from audit.py here}}

Write the audit report.
```

---

## Severity hints (so the model's ratings are consistent)

| Finding | Suggested severity |
|---|---|
| TLS cert expired / invalid | Critical |
| http:// does NOT redirect to https:// | High |
| Login/forms present with no HSTS | High |
| No DMARC record | High (spoofing/phishing risk) |
| No SPF record | Medium |
| Missing CSP | Medium |
| Missing X-Frame-Options / X-Content-Type-Options | Low–Medium |
| Analytics present + no cookie banner/policy | Medium (privacy law) |
| Images missing alt text | Medium (ADA/WCAG) |
| No `lang` attribute / no page title | Low–Medium (WCAG) |
| No privacy/accessibility policy page | Medium |

---

## Minimal driver (how to run it)

```python
import json, subprocess, anthropic

domain = "example.edu"
sector = "K-12 public school"

# 1. collect
raw = subprocess.run(["python", "audit.py", domain],
                     capture_output=True, text=True).stdout

# 2. report
client = anthropic.Anthropic()  # set ANTHROPIC_API_KEY
msg = client.messages.create(
    model="claude-sonnet-4-5",
    max_tokens=3000,
    system=open("system_prompt.txt").read(),   # paste the system prompt above
    messages=[{"role": "user",
               "content": f"Sector: {sector}\nTarget: {domain}\n\n"
                          f"Raw passive-scan findings:\n{raw}\n\nWrite the audit report."}],
)
print(msg.content[0].text)
```

That's your whole MVP: `audit.py` → JSON → one Claude call → report.
Once one real report looks good, split the system prompt into an
Accessibility agent, a Privacy agent, and a Security-config agent, each
with just its slice of the JSON and its own ruleset.
