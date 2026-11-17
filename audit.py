#!/usr/bin/env python3
"""
Passive website compliance & security audit — MVP collector.

PASSIVE ONLY. This tool reads publicly-available information about a site
(TLS config, response headers, DNS records, public HTML). It does NOT:
  - test logins or authentication
  - probe for vulnerabilities / inject payloads
  - scan ports or brute-force anything
Running active/intrusive tests against a site you don't own and weren't
authorized to test can be a federal crime (CFAA). Keep this tool passive.

Usage:
    python audit.py example.edu
    python audit.py example.edu --json out.json

Hard dependencies: none (Python stdlib only).
Optional (better results if installed): requests, beautifulsoup4, dnspython.
The script degrades gracefully and tells you what it couldn't check.
"""

import os
import re
import sys
import ssl
import json
import socket
import time
import logging
import http.client
import argparse
import subprocess
from datetime import datetime, timezone
from urllib.parse import urlparse
from urllib.request import Request, HTTPRedirectHandler, build_opener, HTTPSHandler
from urllib.error import URLError, HTTPError

log = logging.getLogger("webaudit")

USER_AGENT = "WebAuditBot/0.1 (passive compliance scan; contact: you@example.com)"
TIMEOUT = 15
MIN_REQUEST_INTERVAL = 0.5  # seconds between requests to one host
_last_request: dict = {}


# ---------- helpers ----------

def _norm(domain: str) -> str:
    """Strip scheme/path, return bare hostname."""
    d = domain.strip()
    if "://" in d:
        d = urlparse(d).netloc
    return d.split("/")[0].strip().lower()


def _ssl_context() -> ssl.SSLContext:
    """TLS context with a complete, up-to-date CA list.

    The OS/Python CA store is often incomplete (notably on Windows), which made
    valid sites fail verification and get reported as broken. Prefer certifi's
    bundle when available; fall back to the system store otherwise.
    """
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


class _NoRedirect(HTTPRedirectHandler):
    """Surface 3xx responses instead of silently following them."""

    def redirect_request(self, *args, **kwargs):
        return None


def _throttle(host: str) -> None:
    wait = _last_request.get(host, 0) + MIN_REQUEST_INTERVAL - time.monotonic()
    if wait > 0:
        log.debug("rate limit: waiting %.2fs for %s", wait, host)
        time.sleep(wait)
    _last_request[host] = time.monotonic()


def _get(url: str, follow_redirects: bool = True, retries: int = 1):
    """Fetch a URL passively. Returns (status, headers_dict, body_text)."""
    req = Request(url, headers={"User-Agent": USER_AGENT})
    handlers = [HTTPSHandler(context=_ssl_context())]
    if not follow_redirects:
        handlers.append(_NoRedirect())
    for attempt in range(retries + 1):
        _throttle(urlparse(url).netloc)
        try:
            with build_opener(*handlers).open(req, timeout=TIMEOUT) as r:
                body = r.read(500_000).decode("utf-8", "replace")
                log.debug("GET %s -> %s", url, r.status)
                return r.status, {k.lower(): v for k, v in r.headers.items()}, body
        except HTTPError as e:
            log.debug("GET %s -> %s", url, e.code)
            return e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, ""
        except (URLError, socket.timeout, ssl.SSLError, ConnectionError, http.client.HTTPException) as e:
            transient = not isinstance(getattr(e, "reason", e), ssl.SSLCertVerificationError)
            if transient and attempt < retries:
                log.info("GET %s failed (%s); retrying", url, e)
                continue
            log.warning("GET %s failed: %s", url, e)
            return None, {"_error": str(e)}, ""


# ---------- collector: robots.txt (be polite) ----------

def check_robots(host: str) -> dict:
    status, _, body = _get(f"https://{host}/robots.txt")
    disallows = [l.split(":", 1)[1].strip()
                 for l in body.splitlines()
                 if l.lower().startswith("disallow")]
    return {"found": status == 200, "disallow_rules": disallows[:20]}


# ---------- collector: TLS / SSL ----------

CERT_PROBLEMS = {
    10: "expired",
    18: "self_signed",
    19: "self_signed_in_chain",
    20: "untrusted_issuer",
    21: "untrusted_issuer",
    62: "hostname_mismatch",
}


def check_tls(host: str, retries: int = 1) -> dict:
    """TLS handshake check; one retry on timeouts and dropped connections."""
    for attempt in range(retries + 1):
        out = _tls_once(host)
        if "cert_problem" in out or out["reachable"] or attempt == retries:
            return out
        log.info("%s: TLS check failed (%s); retrying", host, out.get("error"))
    return out


def _tls_once(host: str) -> dict:
    out = {"reachable": False}
    ctx = _ssl_context()
    try:
        with socket.create_connection((host, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                out["reachable"] = True
                out["tls_version"] = ssock.version()
                not_after = cert.get("notAfter")
                out["cert_expires"] = not_after
                if not_after:
                    exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    out["days_until_expiry"] = (exp - datetime.now(timezone.utc)).days
                out["issuer"] = dict(x[0] for x in cert.get("issuer", []))
    except (ssl.SSLCertVerificationError,) as e:
        out["cert_valid"] = False
        out["cert_problem"] = CERT_PROBLEMS.get(e.verify_code, "invalid")
        out["error"] = str(e)
        log.info("%s: certificate rejected (%s)", host, out["cert_problem"])
    except (socket.timeout, ConnectionError, socket.gaierror, OSError) as e:
        out["error"] = str(e)
    return out


# ---------- collector: security headers ----------

SECURITY_HEADERS = {
    "strict-transport-security": "HSTS — forces HTTPS",
    "content-security-policy": "CSP — mitigates XSS/injection",
    "x-frame-options": "Clickjacking protection",
    "x-content-type-options": "MIME-sniffing protection",
    "referrer-policy": "Controls referrer leakage",
    "permissions-policy": "Restricts browser features",
}


def _fetch_home(host: str):
    return _get(f"https://{host}/")


def check_headers(host: str, home=None) -> dict:
    status, headers, _ = home or _fetch_home(host)
    if status is None:
        return {"_unavailable": f"Could not fetch https://{host}/ "
                                f"({headers.get('_error', 'unknown error')})."}
    present, missing = {}, {}
    for h, why in SECURITY_HEADERS.items():
        if h in headers:
            present[h] = headers[h]
        else:
            missing[h] = why
    return {
        "http_status": status,
        "redirects_to_https": None,  # see check_http_redirect
        "present": present,
        "missing": missing,
        "server": headers.get("server"),
        "powered_by": headers.get("x-powered-by"),
    }


def check_http_redirect(host: str) -> dict:
    """Does plain http:// redirect to https://?"""
    status, headers, _ = _get(f"http://{host}/", follow_redirects=False)
    if status is None:
        return {"_unavailable": f"Could not fetch http://{host}/ "
                                f"({headers.get('_error', 'unknown error')})."}
    loc = headers.get("location", "")
    return {"http_status": status, "redirects_to_https": loc.startswith("https://"),
            "location": loc or None}


# ---------- collector: DNS email auth (SPF/DKIM/DMARC) ----------

def _txt_records(name: str, must_exist: bool = False):
    """Get TXT records. Tries dnspython, falls back to `dig`, then `nslookup`."""
    try:
        import dns.resolver  # type: ignore
        import dns.exception  # type: ignore
        try:
            return [b"".join(r.strings).decode() if hasattr(r, "strings") else str(r)
                    for r in dns.resolver.resolve(name, "TXT", lifetime=TIMEOUT)]
        except dns.resolver.NXDOMAIN:
            # A real domain's own name is never NXDOMAIN, so for must_exist
            # lookups this means a broken/filtering resolver: result unknown.
            return None if must_exist else []
        except dns.resolver.NoAnswer:
            return []          # name exists, no TXT record
        except dns.exception.DNSException:
            return None        # timeout / no nameservers: result unknown
    except ImportError:
        pass
    for cmd in (["dig", "+short", "TXT", name], ["nslookup", "-type=TXT", name]):
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT)
            if res.returncode == 0 and res.stdout.strip():
                return [l.strip().strip('"') for l in res.stdout.splitlines() if l.strip()]
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return None  # could not resolve — tool missing


def check_email_auth(host: str) -> dict:
    out = {}
    spf = _txt_records(host, must_exist=True)
    if spf is None:
        return {"_unavailable": "DNS lookup failed or no resolver available "
                                "(install dnspython or dig); SPF/DMARC status unknown."}
    out["spf"] = next((r for r in spf if r.lower().startswith("v=spf1")), None)
    dmarc = _txt_records(f"_dmarc.{host}")
    if dmarc is None:
        out["dmarc"] = None
        out["dmarc_unavailable"] = "DNS lookup failed; DMARC status unknown."
    else:
        out["dmarc"] = next((r for r in dmarc if r.lower().startswith("v=dmarc1")), None)
    # DKIM selectors are unknown without the mail config; note it.
    out["dkim_note"] = "DKIM uses org-specific selectors; verify with their mail admin."
    return out


# ---------- collector: privacy / policy pages ----------

POLICY_PATHS = ["/privacy", "/privacy-policy", "/privacy.html",
                "/terms", "/accessibility", "/cookie-policy"]


def check_privacy(host: str, home=None) -> dict:
    status, _, home = home or _fetch_home(host)
    if status is None:
        return {"_unavailable": "Could not fetch homepage; privacy signals unknown."}
    found = {}
    for p in POLICY_PATHS:
        status, _, _ = _get(f"https://{host}{p}")
        if status == 200:
            found[p] = True
    low = home.lower()
    return {
        "policy_pages_found": list(found.keys()),
        "mentions_cookies": "cookie" in low,
        "has_analytics": any(s in low for s in
                             ("google-analytics", "googletagmanager", "gtag(")),
        "cookie_banner_hint": any(s in low for s in
                                  ("cookie consent", "accept cookies", "cookiebanner")),
    }


# ---------- collector: lightweight accessibility signals ----------

NO_LABEL_INPUT_TYPES = {"hidden", "submit", "button", "reset", "image"}


def _text(tag) -> str:
    return " ".join(tag.get_text(" ", strip=True).split())


def _has_name(tag, soup) -> bool:
    """Does a form control / link / button have an accessible name?"""
    if any(tag.get(a, "").strip() for a in ("aria-label", "aria-labelledby", "title")):
        return True
    if _text(tag) or tag.find("img", alt=lambda v: v and v.strip()):
        return True
    if tag.name in ("input", "select", "textarea"):
        if tag.get("id") and soup.find("label", attrs={"for": tag["id"]}):
            return True
        if tag.find_parent("label"):
            return True
    if tag.name == "input" and tag.get("type") in ("submit", "button", "reset") \
            and tag.get("value", "").strip():
        return True
    return False


def analyze_html(soup) -> dict:
    """Cheap, high-confidence WCAG 2.1 checks from static HTML (no rendering)."""
    issues = []

    def add(rule, wcag, items):
        if items:
            issues.append({"rule": rule, "wcag": wcag, "count": len(items),
                           "examples": [str(i)[:100] for i in items[:3]]})

    html_tag = soup.find("html")
    lang = (html_tag.get("lang", "") if html_tag else "").strip()
    imgs = soup.find_all("img")
    imgs_no_alt = [i for i in imgs if i.get("alt") is None]  # alt="" is valid (decorative)

    add("Images missing alt attribute", "1.1.1", imgs_no_alt)
    controls = [c for c in soup.find_all(["input", "select", "textarea"])
                if c.get("type", "text").lower() not in NO_LABEL_INPUT_TYPES]
    add("Form fields without a label", "1.3.1 / 4.1.2",
        [c for c in controls if not _has_name(c, soup)])
    add("Links without an accessible name", "2.4.4",
        [a for a in soup.find_all("a", href=True) if not _has_name(a, soup)])
    add("Buttons without an accessible name", "4.1.2",
        [b for b in soup.find_all(["button", "input"])
         if (b.name == "button" or b.get("type") in ("submit", "button", "reset"))
         and not _has_name(b, soup)])
    add("Iframes without a title", "4.1.2",
        [f for f in soup.find_all("iframe") if not f.get("title", "").strip()])
    add("Empty headings", "1.3.1 / 2.4.6",
        [h for h in soup.find_all(["h1", "h2", "h3", "h4", "h5", "h6"]) if not _text(h)])

    ids = [t["id"] for t in soup.find_all(id=True)]
    add("Duplicate id values", "4.1.1", sorted({i for i in ids if ids.count(i) > 1}))

    levels = [int(h.name[1]) for h in soup.find_all(["h1", "h2", "h3", "h4", "h5", "h6"])]
    h1_count = levels.count(1)
    if h1_count != 1:
        add("Page should have exactly one h1", "1.3.1 / 2.4.6", [f"{h1_count} h1 elements"])
    skips = [f"h{a} -> h{b}" for a, b in zip(levels, levels[1:]) if b > a + 1]
    add("Heading levels skipped", "1.3.1", skips)

    viewport = soup.find("meta", attrs={"name": "viewport"})
    vp = (viewport.get("content", "") if viewport else "").replace(" ", "").lower()
    if "user-scalable=no" in vp or re.search(r"maximum-scale=1(\.0+)?(,|$)", vp):
        add("Viewport blocks zoom", "1.4.4", [vp])
    if not lang:
        add("Page language not set", "3.1.1", ["<html> has no lang attribute"])
    if not (soup.title and soup.title.string and soup.title.string.strip()):
        add("Page has no title", "2.4.2", ["<title> missing or empty"])
    add("Media that autoplays", "1.4.2",
        [m for m in soup.find_all(["video", "audio"]) if m.has_attr("autoplay")])
    add("Data tables without header cells", "1.3.1",
        [t for t in soup.find_all("table") if len(t.find_all("tr")) > 1 and not t.find("th")])
    if not any("skip" in _text(a).lower() and a["href"].startswith("#")
               for a in soup.find_all("a", href=True)[:10]):
        add("No skip-to-content link near top of page", "2.4.1", ["no skip link found"])

    return {
        "engine": "beautifulsoup",
        "has_lang_attribute": bool(lang),
        "page_has_title": bool(soup.title and soup.title.string and soup.title.string.strip()),
        "images_total": len(imgs),
        "images_missing_alt": len(imgs_no_alt),
        "issue_count": sum(i["count"] for i in issues),
        "issues": issues,
        "note": "Static HTML checks only (no colour contrast or keyboard testing). "
                "Run axe-core/Pa11y for a full WCAG 2.1 AA audit.",
    }


def check_accessibility(host: str, home=None) -> dict:
    """
    Signal-level only. A real WCAG audit needs axe-core/Pa11y (Node).
    This flags a few cheap, high-confidence issues from the homepage HTML.
    """
    _, _, html = home or _fetch_home(host)
    if not html:
        return {"_unavailable": "Could not fetch homepage HTML."}
    try:
        from bs4 import BeautifulSoup  # type: ignore
        return analyze_html(BeautifulSoup(html, "html.parser"))
    except ImportError:
        return {
            "_unavailable": "Install beautifulsoup4 for HTML parsing.",
            "crude_missing_alt_guess": html.count("<img") - html.lower().count("alt="),
        }


# ---------- authorization ----------

DEFAULT_ALLOWLIST = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 "authorized_targets.txt")


class TargetNotAuthorized(Exception):
    pass


def load_allowlist(path: str = None) -> list:
    """Domains we may scan. Path: argument, else WEBAUDIT_ALLOWLIST, else the default file."""
    path = path or os.environ.get("WEBAUDIT_ALLOWLIST") or DEFAULT_ALLOWLIST
    try:
        with open(path, encoding="utf-8") as f:
            lines = [l.split("#", 1)[0].strip().lower() for l in f]
    except FileNotFoundError:
        log.warning("allowlist %s not found; no targets are authorized", path)
        return []
    return [l for l in lines if l]


def is_authorized(host: str, allowlist: list) -> bool:
    """True if host is a listed domain or a subdomain of one (never a look-alike)."""
    host = host.lower().rstrip(".")
    return any(host == d or host.endswith("." + d) for d in allowlist)


def require_authorized(host: str, allowlist_path: str = None) -> None:
    if not is_authorized(host, load_allowlist(allowlist_path)):
        raise TargetNotAuthorized(
            f"{host} is not in the authorized targets list. Add it to "
            f"authorized_targets.txt once the owner has authorized the scan.")


# ---------- orchestrator ----------

AUDIT_STEPS = ["robots", "homepage", "tls", "headers", "http_redirect",
               "email_auth", "privacy", "accessibility", "browser_a11y"]


def check_browser_accessibility(host: str) -> dict:
    """axe-core + keyboard test in a real browser (see browser_audit.py)."""
    import browser_audit
    return browser_audit.run_browser_audit(f"https://{host}/")


def run_audit(domain: str, allowlist_path: str = None, on_step=None,
              browser: bool = True) -> dict:
    """Run every passive check. on_step(name, "running" | "done" | "skipped") reports progress."""
    host = _norm(domain)
    require_authorized(host, allowlist_path)
    log.info("Auditing %s (passive)", host)

    def step(name, fn, *args):
        if on_step:
            on_step(name, "running")
        out = fn(*args)
        if on_step:
            on_step(name, "done")
        return out

    robots = step("robots", check_robots, host)
    home = step("homepage", _fetch_home, host)
    result = {
        "target": host,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "scan_type": "passive",
        "robots": robots,
        "tls": step("tls", check_tls, host),
        "headers": step("headers", check_headers, host, home),
        "http_redirect": step("http_redirect", check_http_redirect, host),
        "email_auth": step("email_auth", check_email_auth, host),
        "privacy": step("privacy", check_privacy, host, home),
        "accessibility": step("accessibility", check_accessibility, host, home),
    }
    if browser:
        result["accessibility_browser"] = step("browser_a11y", check_browser_accessibility, host)
    elif on_step:
        on_step("browser_a11y", "skipped")
    return result


def main():
    ap = argparse.ArgumentParser(description="Passive website compliance/security audit.")
    ap.add_argument("domain", help="e.g. example.edu")
    ap.add_argument("--json", metavar="FILE", help="write raw findings to a JSON file")
    ap.add_argument("-v", "--verbose", action="store_true", help="log every request")
    ap.add_argument("--no-browser", action="store_true",
                    help="skip the real-browser accessibility audit (faster)")
    ap.add_argument("--allowlist", metavar="FILE",
                    help="authorized targets file (default: authorized_targets.txt)")
    args = ap.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(levelname)s %(message)s", stream=sys.stderr)

    try:
        data = run_audit(args.domain, args.allowlist, browser=not args.no_browser)
    except TargetNotAuthorized as e:
        log.error("%s", e)
        sys.exit(2)
    text = json.dumps(data, indent=2, default=str)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            f.write(text)
        log.info("Wrote %s", args.json)
    sys.stdout.reconfigure(encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
