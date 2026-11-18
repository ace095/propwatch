"""
Neighborhood view: which zip codes have the most unresolved hazardous
housing violations, and how long have they sat?

    python -m propwatch area 10452
    python -m propwatch area 10452 10021 11206      # side-by-side

Source: HPD housing violations (wvxf-dwi5), open violations only.
Housing (HPD) data mostly covers multi-unit rental buildings, so this shows
those, not 1-2 family homes.
"""
import re
import sys
import argparse
from datetime import date, timedelta

from .nyc import _soda, _get, SODA  # same tiny HTTP helpers


def _zip(z: str) -> str:
    if not re.fullmatch(r"\d{5}", z or ""):
        raise ValueError(f"zip must be 5 digits, got {z!r}")
    return z


def area_summary(zipcode: str) -> dict:
    z = _zip(zipcode)
    base = f"zip='{z}' AND violationstatus='Open'"
    cutoff = (date.today() - timedelta(days=365)).isoformat()

    by_class = _grouped(z)
    total = sum(by_class.values())
    hazardous = by_class.get("B", 0) + by_class.get("C", 0)

    old_haz = _count(f"{base} AND class in ('B','C') AND novissueddate < '{cutoff}'")
    buildings = int((_soda("wvxf-dwi5", base, select="count(distinct buildingid) as n")
                     or [{"n": 0}])[0].get("n", 0))
    oldest_c = (_soda("wvxf-dwi5", f"{base} AND class='C'",
                      select="min(novissueddate) as d") or [{}])[0].get("d")
    worst = _get(SODA.format("wvxf-dwi5") + "?" + _qs({
        "$select": "housenumber, streetname, count(*) as n",
        "$group": "housenumber, streetname", "$order": "n DESC", "$limit": "5",
        "$where": f"{base} AND class in ('B','C')"}))
    worst = [{"address": f"{r.get('housenumber','')} {r.get('streetname','')}".strip(),
              "n": int(r["n"])} for r in worst]
    return {"zip": z, "open_total": total, "open_by_class": by_class,
            "open_hazardous": hazardous, "hazardous_over_1yr": old_haz,
            "buildings_with_open": buildings,
            "avg_open_per_building": round(total / buildings, 1) if buildings else 0,
            "oldest_open_class_c": (oldest_c or "")[:10] or None,
            "worst_buildings": worst}


def _grouped(z):
    rows = _get(SODA.format("wvxf-dwi5") + "?" + _qs(
        {"$select": "class, count(*) as n", "$group": "class",
         "$where": f"zip='{z}' AND violationstatus='Open'"}))
    return {r["class"]: int(r["n"]) for r in rows if "class" in r}


def _count(where):
    return int((_soda("wvxf-dwi5", where, select="count(*) as n") or [{"n": 0}])[0]["n"])


def _qs(p):
    import urllib.parse
    return urllib.parse.urlencode(p)


def render(rows):
    out = []
    for r in rows:
        c = r["open_by_class"]
        out.append(f"ZIP {r['zip']}: {r['open_total']:,} open housing violations in "
                   f"{r['buildings_with_open']:,} buildings (avg {r['avg_open_per_building']} each)")
        out.append(f"  Hazardous (B+C): {r['open_hazardous']:,}   "
                   f"Class C (immediate): {c.get('C', 0):,}   "
                   f"Hazardous and open > 1 year: {r['hazardous_over_1yr']:,}")
        if r["oldest_open_class_c"]:
            out.append(f"  Oldest open Class C issued: {r['oldest_open_class_c']}")
        if r["worst_buildings"]:
            out.append("  Most open B/C violations: " + "; ".join(
                f"{w['address']} ({w['n']})" for w in r["worst_buildings"][:3]))
        out.append("")
    out.append("Counts are raw, not per resident; bigger zips have more buildings. "
               "Open = reported and not yet closed in city records.")
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="propwatch area")
    ap.add_argument("zips", nargs="+", help="one or more 5-digit NYC zip codes")
    a = ap.parse_args(argv)
    try:
        print(render([area_summary(z) for z in a.zips]))
    except ValueError as ex:
        sys.exit(str(ex))
