"""
Prototype: open violations for one NYC address, from NYC Open Data (public).

    python -m propwatch 22 "Stagg Street" brooklyn
    python -m propwatch 22 "Stagg Street" brooklyn --json out.json

Sources (data.cityofnewyork.us, Socrata):
    wvxf-dwi5  HPD housing maintenance code violations
    3h2n-5cm9  DOB violations (older, BIS)
    855j-jady  DOB safety violations (newer, DOB NOW)

Limits: matches by house number + street name text (no geocoding), so odd
spellings can miss. Reports what is *on record*; it says nothing about whether
a building is structurally safe.
"""
import re
import sys
import json
import argparse
import urllib.parse
import urllib.request

BASE = "https://data.cityofnewyork.us/resource/{}.json"
BOROS = {"manhattan": "1", "bronx": "2", "brooklyn": "3", "queens": "4",
         "staten island": "5"}
SUFFIX = {"STREET": "ST", "AVENUE": "AVE", "ROAD": "RD", "BOULEVARD": "BLVD",
          "PLACE": "PL", "DRIVE": "DR", "COURT": "CT", "LANE": "LN"}


def norm_street(s: str) -> str:
    """'West   43rd Street' and 'WEST 43 STREET' -> 'W 43 ST'."""
    s = re.sub(r"(\d+)(ST|ND|RD|TH)\b", r"\1", s.upper())
    words = [{"WEST": "W", "EAST": "E", "NORTH": "N", "SOUTH": "S"}.get(w, SUFFIX.get(w, w))
             for w in s.split()]
    return " ".join(words)


def _query(rid: str, **params):
    url = BASE.format(rid) + "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"User-Agent": "nyc-violations-prototype"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def lookup(house: str, street: str, borough: str) -> dict:
    boro = BOROS[borough.lower()]
    if not re.fullmatch(r"[0-9A-Za-z-]{1,12}", house):
        raise ValueError("house number must be letters, digits or hyphens")
    want = norm_street(street)

    hpd = [r for r in _query("wvxf-dwi5", **{
        "$where": f"boroid='{boro}' AND (housenumber='{house}' OR housenumber like '{house} %') "
                  "AND violationstatus='Open'",
        "$limit": "5000"}) if norm_street(r.get("streetname", "")) == want]

    dob_old = [r for r in _query("3h2n-5cm9", **{
        "$where": f"boro='{boro}' AND house_number='{house}'", "$limit": "5000"})
        if norm_street(r.get("street", "")) == want
        and "ACTIVE" in r.get("violation_category", "").upper()]

    dob_new = [r for r in _query("855j-jady", **{
        "$where": f"borough='{borough.upper()}' AND house_number='{house}' "
                  "AND violation_status='Active'", "$limit": "5000"})
        if norm_street(r.get("street", "")) == want]

    by_class = {}
    for r in hpd:
        by_class[r.get("class", "?")] = by_class.get(r.get("class", "?"), 0) + 1
    return {
        "address": f"{house} {street}, {borough.title()}",
        "hpd_open": len(hpd),
        "hpd_by_class": by_class,   # A non-hazardous, B hazardous, C immediately hazardous
        "hpd_oldest_issued": min((r["novissueddate"][:10] for r in hpd
                                  if r.get("novissueddate")), default=None),
        "hpd_examples": [{"class": r.get("class"),
                          "issued": (r.get("novissueddate") or "")[:10],
                          "status": r.get("currentstatus"),
                          "description": (r.get("novdescription") or "")[:160]}
                         for r in sorted(hpd, key=lambda r: r.get("class", "Z"))[:5]],
        "dob_active_bis": len(dob_old),
        "dob_active_dob_now": len(dob_new),
        "dob_examples": [(r.get("violation_type") or "").strip()[:100] for r in dob_old[:5]]
                        + [r.get("violation_type", "") for r in dob_new[:5]],
    }


def main(argv=None):
    ap = argparse.ArgumentParser(prog="propwatch",
                                 description="Open NYC violations for one address.")
    ap.add_argument("house")
    ap.add_argument("street")
    ap.add_argument("borough", choices=sorted(BOROS))
    ap.add_argument("--json", metavar="FILE")
    a = ap.parse_args(argv)
    res = lookup(a.house, a.street, a.borough)
    print(json.dumps(res, indent=2))
    if a.json:
        with open(a.json, "w") as f:
            json.dump(res, f, indent=2)
