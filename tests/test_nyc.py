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


class Guidance(unittest.TestCase):
    from propwatch import guidance as g
    base = {"hpd": {"open_by_class": {}}, "dob": {"active_older_system": 0, "active_dob_now": 0},
            "ecb_penalties": {"active": 0}}

    def test_nothing_open_gives_no_steps(self):
        self.assertEqual(self.g.next_steps(self.base), [])

    def test_class_c_comes_first_and_mentions_24_hours(self):
        r = dict(self.base, hpd={"open_by_class": {"C": 2, "A": 5}})
        steps = self.g.next_steps(r)
        self.assertIn("Class C", steps[0]["title"])
        self.assertIn("24 hours", steps[0]["body"])
        self.assertIn("not legal advice", steps[-1]["body"])

    def test_no_dollar_penalties_stated(self):
        r = dict(self.base, hpd={"open_by_class": {"A": 1, "B": 1, "C": 1}},
                 dob={"active_older_system": 1, "active_dob_now": 0}, ecb_penalties={"active": 1})
        self.assertNotIn("$", " ".join(s["body"] for s in self.g.next_steps(r)))


class FailureHandling(unittest.TestCase):
    """A dead data source must read as 'unavailable', never as a clean zero."""
    prop = {"label": "1 TEST ST, Bronx, NY, USA", "bbl": "2024660050", "bin": "2002867",
            "housenumber": "1", "street": "Test St", "borough": "Bronx", "zip": "10452"}

    def run_lookup(self, failing):
        def fake_soda(rid, where, select=None, limit=5000):
            if rid == failing:
                raise OSError("boom")
            return []
        with mock.patch.object(nyc, "resolve", return_value=self.prop), \
             mock.patch.object(nyc, "_soda", side_effect=fake_soda):
            return nyc.lookup("1 Test St, Bronx")

    def test_failed_source_is_unavailable_not_zero(self):
        r = self.run_lookup("wvxf-dwi5")
        self.assertIn("HPD housing violations", r["unavailable"])
        self.assertIsNone(r["hpd"]["open"])
        self.assertIn("WARNING", nyc.render(r))

    def test_other_sources_still_reported(self):
        r = self.run_lookup("erm2-nwe9")
        self.assertEqual(r["hpd"]["open"], 0)
        self.assertEqual(r["unavailable"], ["311 requests"])

    def test_all_good_has_nothing_unavailable(self):
        self.assertEqual(self.run_lookup("none")["unavailable"], [])


class StaleRecords(unittest.TestCase):
    def test_age_years(self):
        self.assertGreater(nyc._age_years("2010-01-01"), 15)
        self.assertEqual(nyc._age_years(None), 0.0)


class CertifiedCount(unittest.TestCase):
    def test_certified_late_is_counted_separately(self):
        rows = [{"violationstatus": "Open", "currentstatus": "NOV CERTIFIED LATE", "class": "A"},
                {"violationstatus": "Open", "currentstatus": "NOV SENT OUT", "class": "B"}]
        def fake(rid, where, select=None, limit=5000):
            return rows if rid == "wvxf-dwi5" else []
        with mock.patch.object(nyc, "resolve", return_value=FailureHandling.prop), \
             mock.patch.object(nyc, "_soda", side_effect=fake):
            r = nyc.lookup("x")
        self.assertEqual(r["hpd"]["open"], 2)
        self.assertEqual(r["hpd"]["certified_awaiting"], 1)
