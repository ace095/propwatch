import os, sys, unittest
from unittest import mock
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from propwatch import nyc


class Helpers(unittest.TestCase):
    def test_bbl_parts_unpadded_like_hpd(self):
        self.assertEqual(nyc.bbl_parts("3030310015"), ("3", "3031", "15"))
        self.assertEqual(nyc.bbl_parts("1008350041"), ("1", "835", "41"))

    def test_ids_must_be_digits(self):
        with self.assertRaises(ValueError):
            nyc._digits("1' OR '1'='1", "bin")

    def test_quote_escaping(self):
        self.assertEqual(nyc._esc("O'Brien"), "O''Brien")


class Resolve(unittest.TestCase):
    def test_not_found(self):
        with mock.patch.object(nyc, "_get", return_value={"features": []}):
            with self.assertRaises(LookupError):
                nyc.resolve("nowhere")

    def test_no_tax_lot(self):
        feat = {"features": [{"properties": {"label": "X", "addendum": {}}}]}
        with mock.patch.object(nyc, "_get", return_value=feat):
            with self.assertRaises(LookupError):
                nyc.resolve("somewhere")


class Render(unittest.TestCase):
    base = {"address": "A", "bbl": "1", "bin": "2",
            "hpd": {"open": 0, "open_by_class": {}, "oldest_open_issued": None},
            "dob": {"active_older_system": 0, "active_dob_now": 0},
            "ecb_penalties": {"active": 0, "balance_due": 0.0},
            "dob_complaints_active": 0,
            "complaints_311_last_year": {"total": 0, "still_open": 0, "top_types": []}}

    def test_never_claims_safety(self):
        out = nyc.render(self.base)
        self.assertIn("does not say whether the building is safe", out)

    def test_private_house_hint_when_nothing_on_record(self):
        self.assertIn("1-2 family", nyc.render(self.base))


if __name__ == "__main__":
    unittest.main()
