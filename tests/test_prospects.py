import os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from propwatch import prospects as p


class Prospects(unittest.TestCase):
    def test_company_name_variants_merge(self):
        self.assertEqual(p.norm_company("DARDANI INVESTMENT GROUP, LLC"),
                         p.norm_company("Dardani Investment Group LLC"))

    def test_different_companies_stay_apart(self):
        self.assertNotEqual(p.norm_company("A Realty LLC"), p.norm_company("B Realty LLC"))

    def test_government_owners_are_excluded(self):
        for name in ("CITY OF NEW YORK", "New York City Housing Authority", "NYC HPD", "STATE OF NEW YORK"):
            self.assertTrue(p.is_government(name), name)
        for name in ("Concord Management of NY LLC", "Cityview Realty Corp", "Hudson Valley Holdings"):
            self.assertFalse(p.is_government(name), name)

    def test_no_personal_name_fields_requested(self):
        src = open(p.__file__, encoding="utf-8").read()
        self.assertNotIn("firstname", src.split('"""')[2])   # code, not the docstring
        self.assertNotIn("lastname", src.split('"""')[2])


if __name__ == "__main__":
    unittest.main()
