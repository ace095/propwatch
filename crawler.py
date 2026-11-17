"""Find and check a few important pages beyond the homepage.

Safe by construction: same site only, robots.txt respected, a hard page limit,
and every request goes through audit._get (rate limited, passive GETs only).
"""
import logging
import re
from urllib.parse import urljoin, urldefrag, urlparse
from xml.etree import ElementTree

import audit

log = logging.getLogger("webaudit.crawl")

DEFAULT_PAGE_LIMIT = 5
MAX_BROWSER_PAGES = 3  # axe runs are slow, so only the first few pages get one
SKIP_EXTENSIONS = (".pdf", ".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".zip", ".mp4",
                   ".mp3", ".css", ".js", ".ico", ".xml", ".json", ".doc", ".docx", ".xls", ".xlsx")
# Pages that matter most to a compliance audit come first.
PRIORITY_WORDS = ("privacy", "cookie", "terms", "accessib", "contact", "login", "signin",
                  "sign-in", "account", "cart", "checkout", "donate", "apply", "register", "about")
POLICY_WORDS = ("privacy", "cookie", "terms", "accessib")


def parse_robots(body: str, agent: str = "*") -> list:
    """Disallow rules that apply to `agent` (falls back to the * group)."""
    groups, current, listing = {}, [], False
    for raw in body.splitlines():
        line = raw.split("#", 1)[0].strip()
        if ":" not in line:
            continue
        key, value = (p.strip() for p in line.split(":", 1))
        key = key.lower()
        if key == "user-agent":
            if listing:
                current, listing = [], False
            current.append(value.lower())
        elif key in ("disallow", "allow"):
            listing = True
            for name in current:
                groups.setdefault(name, []).append((key, value))
    rules = groups.get(agent.lower()) or groups.get("*", [])
    return [v for k, v in rules if k == "disallow" and v]


def allowed_by_robots(path: str, disallows: list) -> bool:
    for rule in disallows:
        pattern = re.escape(rule).replace(r"\*", ".*").replace(r"\$", "$")
        if re.match(pattern, path):
            return False
    return True


def _same_site(url: str, host: str) -> bool:
    netloc = urlparse(url).netloc.lower().removeprefix("www.")
    return netloc == host.lower().removeprefix("www.")


def _clean(base: str, href: str):
    url, _ = urldefrag(urljoin(base, href.strip()))
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or parsed.path.lower().endswith(SKIP_EXTENSIONS):
        return None
    return parsed._replace(scheme="https", query="").geturl()


def _sitemap_urls(host: str) -> list:
    status, _, body = audit._get(f"https://{host}/sitemap.xml")
    if status != 200:
        return []
    try:
        root = ElementTree.fromstring(body)
    except ElementTree.ParseError:
        return []
    return [e.text.strip() for e in root.iter() if e.tag.endswith("loc") and e.text]


def _priority(url: str) -> int:
    path = urlparse(url).path.lower()
    for i, word in enumerate(PRIORITY_WORDS):
        if word in path:
            return i
    return len(PRIORITY_WORDS)


def discover_pages(host: str, home_html: str, limit: int = DEFAULT_PAGE_LIMIT) -> dict:
    """Pick up to `limit` same-site pages from homepage links and the sitemap."""
    if limit <= 0:
        return {"urls": [], "discovered": 0, "blocked_by_robots": 0}
    from bs4 import BeautifulSoup
    base = f"https://{host}/"
    status, _, robots_body = audit._get(f"https://{host}/robots.txt")
    disallows = parse_robots(robots_body) if status == 200 else []

    candidates = []
    soup = BeautifulSoup(home_html or "", "html.parser")
    for a in soup.find_all("a", href=True):
        candidates.append(_clean(base, a["href"]))
    for loc in _sitemap_urls(host)[:200]:
        candidates.append(_clean(base, loc))

    seen, usable, blocked = {base.rstrip("/"), base}, [], 0
    for url in candidates:
        if not url or url in seen or url.rstrip("/") in seen or not _same_site(url, host):
            continue
        seen.add(url)
        if not allowed_by_robots(urlparse(url).path or "/", disallows):
            blocked += 1
            continue
        usable.append(url)
    usable.sort(key=_priority)  # stable: keeps page order within a priority
    log.info("crawl: %d candidate pages, %d blocked by robots.txt, scanning %d",
             len(usable), blocked, min(limit, len(usable)))
    return {"urls": usable[:limit], "discovered": len(usable), "blocked_by_robots": blocked}


def policy_links(home_html: str, host: str) -> list:
    """Privacy / cookie / terms / accessibility pages the homepage actually links to."""
    from bs4 import BeautifulSoup
    found = []
    for a in BeautifulSoup(home_html or "", "html.parser").find_all("a", href=True):
        url = _clean(f"https://{host}/", a["href"])
        label = (a.get_text(" ", strip=True) + " " + a["href"]).lower()
        if url and _same_site(url, host) and any(w in label for w in POLICY_WORDS) and url not in found:
            found.append(url)
    return found[:8]


def analyze_page(url: str, html: str, status: int) -> dict:
    """Static findings for one page."""
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(html or "", "html.parser")
    a11y = audit.analyze_html(soup) if html else {"issues": [], "issue_count": 0}
    mixed = [t.get("src") or t.get("href") for t in soup.find_all(["script", "img", "iframe", "link", "audio", "video", "source"])
             if str(t.get("src") or t.get("href") or "").startswith("http://")]
    return {
        "url": url,
        "status": status,
        "title": (soup.title.string or "").strip()[:100] if soup.title and soup.title.string else None,
        "a11y_issue_count": a11y["issue_count"],
        "a11y_issues": [{"rule": i["rule"], "wcag": i["wcag"], "count": i["count"]} for i in a11y["issues"]],
        "forms": len(soup.find_all("form")),
        "password_fields": len(soup.find_all("input", type="password")),
        "mixed_content": mixed[:5],
        "mixed_content_count": len(mixed),
    }


def scan_pages(host: str, home_html: str, limit: int = DEFAULT_PAGE_LIMIT, browser: bool = True) -> dict:
    """Discover and check extra pages. Returns {"crawl": {...}, "pages": [...]}."""
    plan = discover_pages(host, home_html, limit)  # host was authorized by run_audit
    pages = []
    for n, url in enumerate(plan["urls"]):
        status, _, html = audit._get(url)
        if status is None:
            pages.append({"url": url, "status": None, "error": "could not fetch"})
            continue
        page = analyze_page(url, html, status)
        if browser and n < MAX_BROWSER_PAGES and status == 200:
            import browser_audit
            axe = browser_audit.run_browser_audit(url)
            page["axe"] = ({"unavailable": axe["_unavailable"]} if "_unavailable" in axe else
                           {"violation_rules": axe["violation_rules"], "by_impact": axe["by_impact"],
                            "violations": [{"id": v["id"], "impact": v["impact"], "help": v["help"],
                                            "wcag": v["wcag"], "count": v["count"]} for v in axe["violations"]],
                            "keyboard_trap": axe["keyboard"]["possible_keyboard_trap"]})
        pages.append(page)
    return {"crawl": {"discovered": plan["discovered"], "scanned": len(pages),
                      "blocked_by_robots": plan["blocked_by_robots"], "limit": limit},
            "pages": pages}
