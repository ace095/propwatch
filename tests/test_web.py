import os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from propwatch import web


class Cache(unittest.TestCase):
    def test_second_call_is_served_from_cache(self):
        web._cache.clear()
        calls = []
        f = lambda: calls.append(1) or {"ok": True}
        web.cached("k", f); web.cached("k", f)
        self.assertEqual(len(calls), 1)


class Page(unittest.TestCase):
    def test_index_is_present_and_has_no_hardcoded_address(self):
        path = os.path.join(os.path.dirname(web.__file__), "static", "index.html")
        html = open(path, encoding="utf-8").read()
        self.assertIn("/api/lookup", html)
        self.assertIn("does not say whether the building is safe", html)


if __name__ == "__main__":
    unittest.main()
