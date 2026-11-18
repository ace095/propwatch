import os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import nyc_violations as n


class StreetNormalization(unittest.TestCase):
    def test_dob_and_hpd_spellings_match(self):
        self.assertEqual(n.norm_street("West   43rd Street"), n.norm_street("WEST 43 STREET"))
        self.assertEqual(n.norm_street("Stagg Street"), "STAGG ST")

    def test_different_streets_differ(self):
        self.assertNotEqual(n.norm_street("W 43 ST"), n.norm_street("W 44 ST"))


class InputIsSanitized(unittest.TestCase):
    def test_rejects_query_injection(self):
        with self.assertRaises(ValueError):
            n.lookup("1' OR '1'='1", "Main St", "brooklyn")


if __name__ == "__main__":
    unittest.main()
