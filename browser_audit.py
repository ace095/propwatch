"""Real-browser accessibility audit: axe-core (WCAG 2.1 A/AA) plus a keyboard test.

Uses the Edge or Chrome already installed on the machine, driven by Playwright,
so no browser download is needed. Passive: it loads the page like a visitor and
presses Tab; it never submits forms or clicks anything.
"""
import logging
import os
import re

import unknowns

log = logging.getLogger("webaudit.browser")

BROWSER_CHANNELS = ("msedge", "chrome")
AXE_TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]
PAGE_TIMEOUT_MS = 25_000
MAX_TABS = 60

FOCUS_STYLE_JS = """el => {
  const s = getComputedStyle(el);
  return [s.outlineStyle, s.outlineWidth, s.outlineColor, s.boxShadow, s.borderColor,
          s.backgroundColor, s.color, s.textDecorationLine].join('|');
}"""

DESCRIBE_JS = """el => {
  const id = el.id ? '#' + el.id : '';
  const cls = el.classList.length ? '.' + [...el.classList].slice(0, 2).join('.') : '';
  const text = (el.innerText || el.getAttribute('aria-label') || '').trim().slice(0, 30);
  const path = [];
  for (let n = el; n && n.nodeType === 1; n = n.parentElement) {
    const same = n.parentElement ? [...n.parentElement.children].filter(c => c.tagName === n.tagName) : [n];
    path.push(n.tagName.toLowerCase() + ':' + (same.indexOf(n) + 1));
  }
  return {path: path.join('>'), label: el.tagName.toLowerCase() + id + cls + (text ? ' "' + text + '"' : '')};
}"""

FOCUSABLE_JS = """() => [...document.querySelectorAll(
  'a[href], button, input:not([type=hidden]), select, textarea, [tabindex]:not([tabindex="-1"])')]
  .filter(e => !e.disabled && e.offsetParent !== null).length"""


def _axe_source() -> str:
    import axe_playwright_python
    path = os.path.join(os.path.dirname(axe_playwright_python.__file__), "axe.min.js")
    with open(path, encoding="utf-8") as f:
        return f.read()


def _wcag_criteria(tags) -> list:
    """['wcag143', 'wcag2aa'] -> ['1.4.3']"""
    out = []
    for t in tags:
        m = re.fullmatch(r"wcag(\d)(\d)(\d+)", t)
        if m:
            out.append(".".join(m.groups()))
    return out


def summarize_axe(results: dict, max_examples: int = 3) -> dict:
    """Condense axe-core output into what a client report needs."""
    violations = []
    for v in results.get("violations", []):
        violations.append({
            "id": v["id"],
            "impact": v.get("impact") or "minor",
            "help": v["help"],
            "wcag": _wcag_criteria(v.get("tags", [])),
            "count": len(v["nodes"]),
            "examples": [{"target": " ".join(map(str, n["target"])), "html": n["html"][:160]}
                         for n in v["nodes"][:max_examples]],
            "more_info": v.get("helpUrl"),
        })
    order = {"critical": 0, "serious": 1, "moderate": 2, "minor": 3}
    violations.sort(key=lambda v: (order.get(v["impact"], 4), -v["count"]))
    by_impact = {k: 0 for k in order}
    for v in violations:
        by_impact[v["impact"]] = by_impact.get(v["impact"], 0) + v["count"]
    return {
        "violations": violations,
        "violation_rules": len(violations),
        "violation_elements": sum(v["count"] for v in violations),
        "by_impact": by_impact,
        "rules_passed": len(results.get("passes", [])),
        "needs_manual_review": len(results.get("incomplete", [])),
    }


def _keyboard_test(page) -> dict:
    """Tab through the page: can everything be reached, and is focus visible?"""
    focusable = page.evaluate(FOCUSABLE_JS)
    reached, hidden_focus, last, same_count, trap = [], [], None, 0, None
    for _ in range(min(focusable + 5, MAX_TABS)):
        page.keyboard.press("Tab")
        handle = page.evaluate_handle("document.activeElement")
        el = handle.as_element()
        if el is None:
            break
        info = el.evaluate(DESCRIBE_JS)
        if info["path"].startswith(("body:", "html:")):
            break
        same_count = same_count + 1 if info["path"] == last else 0
        if same_count >= 3:
            trap = info["label"]
            break
        last = info["path"]
        if info["path"] not in reached:
            reached.append(info["path"])
            focused = el.evaluate(FOCUS_STYLE_JS)
            el.evaluate("e => e.blur()")
            if el.evaluate(FOCUS_STYLE_JS) == focused:
                hidden_focus.append(info["label"])
            el.evaluate("e => e.focus()")
    return {
        "focusable_elements": focusable,
        "reached_by_tab": len(reached),
        "tab_presses_checked": min(focusable + 5, MAX_TABS),
        "no_visible_focus_style": hidden_focus[:8],
        "possible_keyboard_trap": trap,
    }


def _launch(playwright):
    last_error = None
    for channel in BROWSER_CHANNELS:
        try:
            log.debug("launching %s", channel)
            return playwright.chromium.launch(channel=channel, headless=True)
        except Exception as e:  # channel not installed
            last_error = e
    raise RuntimeError(f"no usable Edge or Chrome found ({last_error})")


def looks_js_rendered(html: str) -> bool:
    """True for a near-empty page whose content is probably built by scripts."""
    if not html or "<script" not in html.lower():
        return False
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    return len(soup.get_text(" ", strip=True)) < 150


def render_page(url: str):
    """Load url in a real browser. Returns (status, lower-case headers, html), or None on failure."""
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = _launch(p)
            try:
                page = browser.new_page(viewport={"width": 1280, "height": 800})
                response = page.goto(url, wait_until="load", timeout=PAGE_TIMEOUT_MS)
                try:
                    page.wait_for_load_state("networkidle", timeout=5_000)
                except Exception:
                    pass  # some sites never go idle; what loaded so far is enough
                headers = {k.lower(): v for k, v in response.all_headers().items()}
                log.info("rendered %s in a real browser (%d characters)", url, len(page.content()))
                return response.status, headers, page.content()
            finally:
                browser.close()
    except Exception as e:
        log.warning("browser render of %s failed: %s", url, e)
        return None


def run_browser_audit(url: str) -> dict:
    """Load url in a real browser; return axe-core and keyboard findings."""
    try:
        from playwright.sync_api import sync_playwright
        axe_js = _axe_source()
    except ImportError:
        return unknowns.unavailable("Install playwright and axe-playwright-python for the browser audit.",
                                    "missing_tool")
    try:
        with sync_playwright() as p:
            browser = _launch(p)
            try:
                page = browser.new_page(viewport={"width": 1280, "height": 800})
                log.info("browser audit: loading %s", url)
                page.goto(url, wait_until="load", timeout=PAGE_TIMEOUT_MS)
                page.evaluate(axe_js)
                results = page.evaluate(
                    "tags => axe.run(document, {runOnly: {type: 'tag', values: tags}})", AXE_TAGS)
                out = summarize_axe(results)
                out["keyboard"] = _keyboard_test(page)
                out["engine"] = f"axe-core {results.get('testEngine', {}).get('version', '?')} in a real browser"
                out["url"] = page.url
                log.info("browser audit: %d rules failed on %d elements",
                         out["violation_rules"], out["violation_elements"])
                return out
            finally:
                browser.close()
    except Exception as e:
        log.warning("browser audit failed: %s", e)
        message = str(e).splitlines()[0][:200]
        return unknowns.unavailable(f"Browser audit could not run: {message}", unknowns.classify(str(e)))
