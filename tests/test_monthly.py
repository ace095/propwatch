import os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from propwatch import monthly


def z(a, b, c, bld):
    return {"A": a, "B": b, "C": c, "buildings": bld}


class Report(unittest.TestCase):
    cur = {"month": "2026-12", "taken": "2026-12-02",
           "zips": {"10001": z(0, 100, 50, 60), "10002": z(0, 10, 5, 60),
                    "10003": z(0, 999, 999, 5)}}   # too few buildings -> excluded
    prev = {"month": "2026-11", "zips": {"10001": z(0, 90, 40, 60), "10002": z(0, 20, 5, 60)}}

    def test_ranks_by_per_building_and_skips_tiny_zips(self):
        out = monthly.report(self.cur, None)
        self.assertLess(out.index("10001"), out.index("10002"))
        self.assertNotIn("10003", out)
        self.assertIn("No earlier snapshot", out)

    def test_shows_change_vs_previous(self):
        out = monthly.report(self.cur, self.prev)
        self.assertIn("+20", out)          # 10001: 150 vs 130
        self.assertIn("Most improved: 10002", out)

    def test_hazardous_is_b_plus_c(self):
        self.assertEqual(monthly.hazardous(z(7, 3, 2, 1)), 5)


if __name__ == "__main__":
    unittest.main()
