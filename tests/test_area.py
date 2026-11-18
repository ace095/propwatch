import os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from propwatch import area


class Area(unittest.TestCase):
    def test_zip_validation(self):
        self.assertEqual(area._zip("10452"), "10452")
        for bad in ("1045", "abcde", "10452' OR 1=1", ""):
            with self.assertRaises(ValueError):
                area._zip(bad)

    def test_render_explains_raw_counts(self):
        row = {"zip": "10001", "open_total": 10, "open_by_class": {"C": 2, "B": 3},
               "open_hazardous": 5, "hazardous_over_1yr": 4, "buildings_with_open": 2,
               "avg_open_per_building": 5.0, "oldest_open_class_c": "2001-01-01",
               "worst_buildings": [{"address": "1 MAIN ST", "n": 3}]}
        out = area.render([row])
        self.assertIn("ZIP 10001", out)
        self.assertIn("not per resident", out)


if __name__ == "__main__":
    unittest.main()
