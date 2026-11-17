"""Crawler tests: all offline, with audit._get mocked."""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import audit
import crawler

HOME = """<html><body>
<a href="/about">About</a> <a href="/privacy-policy">Privacy</a> <a href="/blog/post-1">Post</a>
<a href="https://x.test/contact?ref=nav#top">Contact</a> <a href="/files/report.pdf">PDF</a>
<a href="https://other.example/page">External</a> <a href="mailto:a@x.test">Mail</a>
<a href="/admin/panel">Admin</a> <a href="https://www.x.test/terms">Terms</a> <a href="/about">About again</a>
</body></html>"""

ROBOTS = "User-agent: *\nDisallow: /admin\nDisallow: /*.json$\n\nUser-agent: Googlebot\nDisallow: /nothing-for-us\n"
SITEMAP = ('<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
           '<url><loc>https://x.test/careers</loc></url><url><loc>https://x.test/about</loc></url>'
           '<url><loc>https://elsewhere.test/hidden</loc></url></urlset>')


def fake_get(url, follow_redirects=True, retries=1):
    table = {"https://x.test/robots.txt": (200, {}, ROBOTS),
             "https://x.test/sitemap.xml": (200, {}, SITEMAP)}
    return table.get(url, (404, {}, ""))


class Robots(unittest.TestCase):
    def test_only_the_matching_group_applies(self):
        self.assertEqual(crawler.parse_robots(ROBOTS), ["/admin", "/*.json$"])
        self.assertEqual(crawler.parse_robots(ROBOTS, "Googlebot"), ["/nothing-for-us"])

    def test_comments_and_blank_disallow_are_ignored(self):
        self.assertEqual(crawler.parse_robots("User-agent: *\nDisallow:  # allow all\nDisallow: /x # no\n"), ["/x"])

    def test_wildcards_and_end_anchor(self):
        rules = ["/admin", "/*.json$"]
        self.assertFalse(crawler.allowed_by_robots("/admin/panel", rules))
        self.assertFalse(crawler.allowed_by_robots("/data/a.json", rules))
        self.assertTrue(crawler.allowed_by_robots("/data/a.json.txt", rules))
        self.assertTrue(crawler.allowed_by_robots("/about", rules))


class Discovery(unittest.TestCase):
    def discover(self, limit=10):
        with mock.patch.object(audit, "_get", side_effect=fake_get):
            return crawler.discover_pages("x.test", HOME, limit)

    def test_same_site_only_and_cleaned(self):
        urls = self.discover()["urls"]
        self.assertIn("https://x.test/contact", urls)          # query and fragment dropped
        self.assertIn("https://www.x.test/terms", urls)        # www counts as the same site
        self.assertIn("https://x.test/careers", urls)          # from the sitemap
        for bad in ("other.example", "elsewhere.test", "mailto", ".pdf"):
            self.assertFalse(any(bad in u for u in urls), bad)

    def test_robots_disallowed_pages_are_skipped_and_counted(self):
        result = self.discover()
        self.assertNotIn("https://x.test/admin/panel", result["urls"])
        self.assertEqual(result["blocked_by_robots"], 1)

    def test_no_duplicates_and_homepage_excluded(self):
        urls = self.discover()["urls"]
        self.assertEqual(len(urls), len(set(urls)))
        self.assertNotIn("https://x.test/", urls)

    def test_important_pages_come_first_and_limit_applies(self):
        urls = self.discover(limit=3)["urls"]
        self.assertEqual(len(urls), 3)
        self.assertEqual(urls[0], "https://x.test/privacy-policy")
        self.assertNotIn("https://x.test/blog/post-1", urls)

    def test_limit_zero_makes_no_requests(self):
        with mock.patch.object(audit, "_get") as get:
            self.assertEqual(crawler.discover_pages("x.test", HOME, 0)["urls"], [])
        get.assert_not_called()


SITE = {  # a small fake site: page -> links on it
    "/": ["/a", "/private/x"],
    "/a": ["/b", "/c", "/private/y", "https://other.test/z"],
    "/b": ["/d", "/a"],
    "/c": ["/e"],
    "/d": [], "/e": [],
}


def fake_site_get(url, follow_redirects=True, retries=1):
    if url.endswith("/robots.txt"):
        return 200, {}, "User-agent: *\nDisallow: /private\n"
    if url.endswith("/sitemap.xml"):
        return 404, {}, ""
    path = "/" + url.split("//", 1)[1].split("/", 1)[1]
    path = path if path == "/" else path.rstrip("/")
    if path not in SITE:
        return 404, {}, ""
    links = "".join(f'<a href="{h}">l</a>' for h in SITE[path])
    return 200, {}, f"<html lang='en'><title>{path}</title><h1>x</h1>{links}</html>"


class FullSiteCrawl(unittest.TestCase):
    def crawl(self, limit):
        with mock.patch.object(audit, "_get", side_effect=fake_site_get):
            home = fake_site_get("https://x.test/")[2]
            return crawler.scan_pages("x.test", home, limit=limit, browser=False)

    def paths(self, result):
        return [p["url"].replace("https://x.test", "") for p in result["pages"]]

    def test_follows_links_beyond_the_homepage_up_to_the_limit(self):
        result = self.crawl(10)
        self.assertEqual(sorted(self.paths(result)), ["/a", "/b", "/c", "/d", "/e"])

    def test_stops_at_the_limit(self):
        result = self.crawl(3)
        self.assertEqual(len(result["pages"]), 3)
        self.assertEqual(result["crawl"]["limit"], 3)

    def test_never_follows_robots_disallowed_or_external_links(self):
        paths = self.paths(self.crawl(50))
        self.assertFalse(any(p.startswith("/private") for p in paths))
        self.assertFalse(any("other.test" in p for p in paths))

    def test_no_page_is_fetched_twice(self):
        with mock.patch.object(audit, "_get", side_effect=fake_site_get) as get:
            crawler.scan_pages("x.test", fake_site_get("https://x.test/")[2], limit=50, browser=False)
        pages = [c.args[0] for c in get.call_args_list if not c.args[0].endswith(("robots.txt", "sitemap.xml"))]
        self.assertEqual(len(pages), len(set(pages)))

    def test_limit_is_capped_however_large(self):
        result = self.crawl(10**6)
        self.assertEqual(result["crawl"]["limit"], crawler.MAX_PAGE_LIMIT)

    def test_axe_runs_only_on_the_first_few_pages_even_for_big_crawls(self):
        import browser_audit
        axe = {"violation_rules": 0, "by_impact": {}, "violations": [], "keyboard": {"possible_keyboard_trap": None}}
        with mock.patch.object(audit, "_get", side_effect=fake_site_get), \
             mock.patch.object(browser_audit, "run_browser_audit", return_value=axe) as run_axe:
            crawler.scan_pages("x.test", fake_site_get("https://x.test/")[2], limit=50, browser=True)
        self.assertEqual(run_axe.call_count, crawler.MAX_BROWSER_PAGES)


class PageAnalysis(unittest.TestCase):
    def test_flags_mixed_content_forms_and_accessibility(self):
        html = ('<html lang="en"><title>Pay</title><body><h1>Pay</h1>'
                '<script src="http://cdn.test/a.js"></script><img src="http://i.test/a.png" alt="">'
                '<form><input type="password" name="p"><input type="text" name="u"></form></body></html>')
        page = crawler.analyze_page("https://x.test/pay", html, 200)
        self.assertEqual((page["title"], page["forms"], page["password_fields"]), ("Pay", 1, 1))
        self.assertEqual(page["mixed_content_count"], 2)
        rules = {i["rule"] for i in page["a11y_issues"]}
        self.assertIn("Form fields without a label", rules)

    def test_clean_https_page_has_no_mixed_content(self):
        page = crawler.analyze_page("u", '<html lang="en"><title>t</title><img src="/a.png" alt="x">', 200)
        self.assertEqual(page["mixed_content_count"], 0)

    def test_policy_links_use_the_link_text_too(self):
        html = '<a href="/legal/p">Privacy Policy</a><a href="/x">Cookie settings</a><a href="/about">About</a>'
        self.assertEqual(crawler.policy_links(html, "x.test"),
                         ["https://x.test/legal/p", "https://x.test/x"])


class ScanPages(unittest.TestCase):
    def test_scans_each_page_and_runs_axe_on_the_first_few_only(self):
        urls = [f"https://x.test/p{i}" for i in range(5)]
        axe = {"violation_rules": 1, "by_impact": {"serious": 1}, "keyboard": {"possible_keyboard_trap": None},
               "violations": [{"id": "color-contrast", "impact": "serious", "help": "h", "wcag": ["1.4.3"], "count": 2}]}
        import browser_audit
        with mock.patch.object(crawler, "discover_pages",
                               return_value={"urls": urls, "discovered": 9, "blocked_by_robots": 2}), \
             mock.patch.object(audit, "_get", return_value=(200, {}, "<html lang='en'><title>t</title></html>")), \
             mock.patch.object(browser_audit, "run_browser_audit", return_value=axe) as run_axe:
            result = crawler.scan_pages("x.test", "", limit=5, browser=True)
        self.assertEqual(run_axe.call_count, crawler.MAX_BROWSER_PAGES)
        self.assertEqual(result["crawl"], {"discovered": 9, "scanned": 5, "blocked_by_robots": 2, "limit": 5})
        self.assertEqual(result["pages"][0]["axe"]["violations"][0]["id"], "color-contrast")
        self.assertNotIn("axe", result["pages"][4])

    def test_unreachable_page_is_recorded_not_dropped(self):
        with mock.patch.object(crawler, "discover_pages",
                               return_value={"urls": ["https://x.test/a"], "discovered": 1, "blocked_by_robots": 0}), \
             mock.patch.object(audit, "_get", return_value=(None, {"_error": "x"}, "")):
            result = crawler.scan_pages("x.test", "", browser=False)
        self.assertEqual(result["pages"], [{"url": "https://x.test/a", "status": None,
                                            "error": "could not fetch", "reason": "unknown_error"}])

    def test_run_audit_can_skip_the_crawl(self):
        steps = []
        with mock.patch.object(audit, "load_allowlist", return_value=["x.test"]), \
             mock.patch.object(audit, "_get", return_value=(200, {}, "<html></html>")), \
             mock.patch.object(audit, "check_tls", return_value={}), \
             mock.patch.object(audit, "check_email_auth", return_value={}), \
             mock.patch.object(crawler, "scan_pages") as scan:
            result = audit.run_audit("x.test", browser=False, pages=0, on_step=lambda n, s: steps.append((n, s)))
        scan.assert_not_called()
        self.assertNotIn("pages", result)
        self.assertIn(("pages", "skipped"), steps)


if __name__ == "__main__":
    unittest.main()
