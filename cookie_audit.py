"""Cookie and tracker audit: what a first-time visitor gets BEFORE agreeing to anything.

Loads the page in a fresh, empty browser profile, clicks nothing, waits for the
page to settle, then records cookies, third-party requests and any consent banner.
Passive: it behaves like a visitor who has not interacted with the page.
"""
import logging
import re
import time
from urllib.parse import urlparse

import browser_audit
import unknowns

log = logging.getLogger("webaudit.cookies")

SETTLE_MS = 6_000
LONG_LIVED_DAYS = 395  # about 13 months, the figure regulators such as the CNIL use

# Third-party domains grouped by what they do. Matched on the registrable domain.
TRACKER_DOMAINS = {
    "analytics": ["google-analytics.com", "googletagmanager.com", "analytics.google.com", "hotjar.com", "clarity.ms",
                  "segment.com", "segment.io", "mixpanel.com", "amplitude.com", "fullstory.com", "mouseflow.com",
                  "heapanalytics.com", "heap.io", "plausible.io", "matomo.cloud", "hubspot.com", "hs-analytics.net",
                  "hsforms.net", "crazyegg.com", "optimizely.com", "newrelic.com", "nr-data.net", "quantserve.com"],
    "advertising": ["doubleclick.net", "googlesyndication.com", "googleadservices.com", "adnxs.com", "criteo.com",
                    "taboola.com", "outbrain.com", "amazon-adsystem.com", "adsrvr.org", "rubiconproject.com",
                    "pubmatic.com", "openx.net", "bing.com", "ads-twitter.com", "scorecardresearch.com"],
    "social": ["facebook.net", "facebook.com", "twitter.com", "linkedin.com", "licdn.com", "tiktok.com",
               "pinterest.com", "snapchat.com", "instagram.com", "addthis.com", "sharethis.com"],
}
TRACKER_COOKIE_PATTERNS = [
    (re.compile(r"^(_ga|_gid|_gat|__utm[a-z]|_gcl_|_hj|_clck|_clsk|ajs_|mp_|_hstc|hubspotutk|__hs|amplitude_)"), "analytics"),
    (re.compile(r"^(_fbp|_fbc|IDE|_uetsid|_uetvid|__gads|_gads|_pin_unauth|_ttp|li_|MUID|test_cookie)"), "advertising"),
]
SESSION_LIKE = re.compile(r"(sess|auth|token|login|sid|jwt|csrf|xsrf)", re.I)
TWO_PART_SUFFIXES = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz", "co.jp",
                     "com.br", "co.za", "co.in", "com.mx"}

CONSENT_VENDORS = {
    "OneTrust": ["#onetrust-banner-sdk", "#onetrust-consent-sdk"],
    "Cookiebot": ["#CybotCookiebotDialog"],
    "Osano": [".osano-cm-dialog", ".osano-cm-window"],
    "Termly": ["#termly-code-snippet-support", ".t-consentPrompt"],
    "CookieYes": [".cky-consent-container", "#cookie-law-info-bar"],
    "TrustArc": ["#truste-consent-track", "#consent_blackbar"],
    "Usercentrics": ["#usercentrics-root", "#uc-banner-modal"],
    "Complianz": ["#cmplz-cookiebanner-container", ".cmplz-cookiebanner"],
    "Cookie Consent": [".cc-window", ".cc-banner"],
    "Didomi": ["#didomi-host", "#didomi-notice"],
    "Quantcast": [".qc-cmp2-container", "#qc-cmp2-container"],
}
BANNER_JS = """vendors => {
  for (const [name, sels] of Object.entries(vendors))
    for (const s of sels) if (document.querySelector(s)) return {found: true, vendor: name, text: ''};
  const words = /cookie|consent|privacy preferences/i;
  const buttons = /accept|agree|allow|got it|ok\\b/i;
  for (const el of document.querySelectorAll('div, section, aside, form, dialog')) {
    const st = getComputedStyle(el);
    if (!['fixed', 'sticky'].includes(st.position) || el.offsetHeight < 30) continue;
    const text = (el.innerText || '').trim();
    if (text.length < 400 && words.test(text) &&
        [...el.querySelectorAll('button, a, [role=button]')].some(b => buttons.test(b.innerText || ''))) {
      return {found: true, vendor: null, text: text.slice(0, 120)};
    }
  }
  return {found: false, vendor: null, text: ''};
}"""
REJECT_JS = """() => {
  const re = /reject|decline|deny|refuse|only necessary|essential only|manage|settings|preferences/i;
  return [...document.querySelectorAll('button, a, [role=button]')]
    .some(b => b.offsetParent !== null && re.test(b.innerText || ''));
}"""


def registrable_domain(host: str) -> str:
    host = (host or "").lower().split(":")[0].strip(".")
    labels = host.split(".")
    if len(labels) <= 2 or re.fullmatch(r"[\d.]+", host):
        return host
    return ".".join(labels[-3:] if ".".join(labels[-2:]) in TWO_PART_SUFFIXES else labels[-2:])


def tracker_category(domain: str):
    """What kind of tracker is this registrable domain, if any."""
    for category, domains in TRACKER_DOMAINS.items():
        if domain in domains:
            return category
    return None


def classify_cookie(name: str, cookie_domain: str, site: str) -> dict:
    """Party (first/third) and purpose of one cookie."""
    domain = registrable_domain(cookie_domain.lstrip("."))
    party = "first" if domain == site else "third"
    category = tracker_category(domain)
    for pattern, cat in TRACKER_COOKIE_PATTERNS:
        if category is None and pattern.match(name):
            category = cat
    return {"party": party, "category": category or ("functional" if party == "first" else "unknown")}


def analyze(site_host: str, cookies: list, request_hosts: list, banner: dict, offers_reject: bool, https: bool = True) -> dict:
    """Pure function: raw browser observations in, findings out."""
    site = registrable_domain(site_host)
    now = time.time()
    summarized = []
    for c in cookies:
        info = classify_cookie(c["name"], c["domain"], site)
        expires = c.get("expires", -1)
        summarized.append({
            "name": c["name"], "domain": c["domain"], **info,
            "secure": bool(c.get("secure")), "http_only": bool(c.get("httpOnly")),
            "same_site": c.get("sameSite", "None"),
            "lifetime_days": round((expires - now) / 86400) if expires and expires > 0 else None,
        })

    third_domains = sorted({registrable_domain(h) for h in request_hosts} - {site, ""})
    trackers = [{"domain": d, "category": tracker_category(d)} for d in third_domains if tracker_category(d)]
    tracking_cookies = [c for c in summarized if c["category"] in ("analytics", "advertising", "social")]

    issues = []

    def issue(rule, severity, detail, standards):
        issues.append({"rule": rule, "severity": severity, "detail": detail, "standards": standards})

    before_consent = bool(trackers or tracking_cookies)
    if before_consent:
        names = [c["name"] for c in tracking_cookies][:6] + [t["domain"] for t in trackers][:6]
        if not banner["found"]:
            issue("Tracking starts with no cookie consent banner", "High",
                  "Analytics, advertising or social trackers load for a first-time visitor and no consent banner "
                  "was found: " + ", ".join(names), "GDPR / ePrivacy, CCPA/CPRA")
        else:
            issue("Tracking starts before the visitor agrees", "Medium",
                  "A consent banner exists, but trackers already ran before any click: " + ", ".join(names),
                  "GDPR / ePrivacy")
    if banner["found"] and not offers_reject:
        issue("Consent banner offers no clear way to refuse", "Medium",
              "No reject, decline or settings option was found next to the accept button.", "GDPR / ePrivacy")
    if https:
        insecure = [c["name"] for c in summarized if c["party"] == "first" and not c["secure"]]
        if insecure:
            session_like = any(SESSION_LIKE.search(n) for n in insecure)
            issue("Cookies set without the Secure flag", "Medium" if session_like else "Low",
                  "These cookies can be sent over an unencrypted connection: " + ", ".join(insecure[:8]),
                  "PCI-DSS / data-breach laws (reasonable safeguards)")
    exposed = [c["name"] for c in summarized if c["party"] == "first" and SESSION_LIKE.search(c["name"]) and not c["http_only"]]
    if exposed:
        issue("Session-style cookies readable by scripts (no HttpOnly)", "Medium",
              "Page scripts can read these cookies, so a script flaw could expose them: " + ", ".join(exposed[:8]),
              "Data-breach laws (reasonable safeguards)")
    long_lived = [c["name"] for c in tracking_cookies if (c["lifetime_days"] or 0) > LONG_LIVED_DAYS]
    if long_lived:
        issue("Tracking cookies that last more than 13 months", "Low",
              "Regulators generally expect tracking cookies to expire sooner: " + ", ".join(long_lived[:6]), "GDPR / ePrivacy")
    if third_domains:
        issue("Outside companies receive visitor data on load", "Low",
              f"{len(third_domains)} third-party domain(s) were contacted, which a privacy policy should disclose: "
              + ", ".join(third_domains[:10]), "CCPA/GDPR (disclosure)")

    return {
        "cookies_total": len(summarized),
        "first_party": sum(1 for c in summarized if c["party"] == "first"),
        "third_party": sum(1 for c in summarized if c["party"] == "third"),
        "cookies": summarized[:40],
        "third_party_domains": third_domains[:40],
        "trackers": trackers,
        "tracking_before_consent": before_consent,
        "consent_banner": {**banner, "offers_reject_or_settings": offers_reject},
        "issues": issues,
        "note": "Observed on a first visit with nothing clicked. Behaviour after the visitor accepts or rejects "
                "was not tested.",
    }


def run_cookie_audit(url: str) -> dict:
    """Visit url with an empty profile and report cookies, trackers and consent banner."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return unknowns.unavailable("Install playwright for the cookie audit.", "missing_tool")
    try:
        with sync_playwright() as p:
            browser = browser_audit._launch(p)
            try:
                context = browser.new_context(viewport={"width": 1280, "height": 800})  # fresh, empty profile
                page = context.new_page()
                hosts = []
                page.on("request", lambda r: hosts.append(urlparse(r.url).hostname or ""))
                log.info("cookie audit: loading %s with an empty browser profile", url)
                page.goto(url, wait_until="load", timeout=browser_audit.PAGE_TIMEOUT_MS)
                page.wait_for_timeout(SETTLE_MS)  # let late-loading trackers fire; nothing is clicked
                banner = page.evaluate(BANNER_JS, CONSENT_VENDORS)
                offers_reject = page.evaluate(REJECT_JS) if banner["found"] else False
                cookies = context.cookies()
                result = analyze(urlparse(page.url).hostname or "", cookies, hosts, banner, offers_reject,
                                 https=page.url.startswith("https://"))
                result["url"] = page.url
                log.info("cookie audit: %d cookies, %d trackers, banner %s", result["cookies_total"],
                         len(result["trackers"]), "found" if banner["found"] else "not found")
                return result
            finally:
                browser.close()
    except Exception as e:
        log.warning("cookie audit failed: %s", e)
        return unknowns.unavailable(f"Cookie audit could not run: {str(e).splitlines()[0][:200]}", unknowns.classify(str(e)))
