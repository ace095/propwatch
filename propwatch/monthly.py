"""
Monthly citywide snapshot + report.

    python -m propwatch monthly            # take a snapshot, compare to last month
    python -m propwatch monthly --no-save  # just print

Saves snapshots/YYYY-MM.json (open HPD housing violations per zip, all five
boroughs). The report ranks zips and shows change since the previous snapshot.
"""
import os
import re
import sys
import json
import glob
import argparse
import urllib.parse
from datetime import date

from .nyc import _get, SODA

MIN_BUILDINGS = 50          # ignore tiny zips so rankings aren't noise
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SNAP_DIR = os.path.join(ROOT, "snapshots")


def _grp(params):
    return _get(SODA.format("wvxf-dwi5") + "?" + urllib.parse.urlencode(params))


def take_snapshot() -> dict:
    where = "violationstatus='Open'"
    by_class = _grp({"$select": "zip, class, count(*) as n", "$group": "zip, class",
                     "$where": where, "$limit": "50000"})
    blds = _grp({"$select": "zip, count(distinct buildingid) as b", "$group": "zip",
                 "$where": where, "$limit": "50000"})
    zips = {}
    for r in by_class:
        z = r.get("zip", "")
        if not re.fullmatch(r"\d{5}", z) or r.get("class") not in ("A", "B", "C"):
            continue                      # drops junk zips and class I (informational)
        zips.setdefault(z, {"A": 0, "B": 0, "C": 0, "buildings": 0})[r["class"]] = int(r["n"])
    for r in blds:
        if r.get("zip") in zips:
            zips[r["zip"]]["buildings"] = int(r["b"])
    return {"month": date.today().strftime("%Y-%m"), "taken": date.today().isoformat(),
            "source": "HPD housing violations wvxf-dwi5 (open)", "zips": zips}


def hazardous(z):  # Class B + C
    return z["B"] + z["C"]


def load_previous(current_month: str):
    files = sorted(f for f in glob.glob(os.path.join(SNAP_DIR, "*.json"))
                   if os.path.basename(f)[:-5] < current_month)
    return json.load(open(files[-1])) if files else None


def report(cur: dict, prev: dict | None, top: int = 10) -> str:
    rows = [(z, d) for z, d in cur["zips"].items() if d["buildings"] >= MIN_BUILDINGS]
    rows.sort(key=lambda kv: -(hazardous(kv[1]) / kv[1]["buildings"]))
    total_h = sum(hazardous(d) for d in cur["zips"].values())
    total_c = sum(d["C"] for d in cur["zips"].values())
    out = [f"Propwatch monthly report - {cur['month']}  (data pulled {cur['taken']})",
           f"Citywide open hazardous (B+C) housing violations: {total_h:,}  "
           f"(Class C: {total_c:,})", "",
           f"Zips with the most open hazardous violations per building "
           f"(min {MIN_BUILDINGS} buildings):"]
    for z, d in rows[:top]:
        line = (f"  {z}: {hazardous(d)/d['buildings']:.1f} per building "
                f"({hazardous(d):,} in {d['buildings']:,} buildings, {d['C']:,} Class C)")
        if prev and z in prev["zips"]:
            delta = hazardous(d) - hazardous(prev["zips"][z])
            line += f"  [{delta:+,} vs {prev['month']}]"
        out.append(line)
    if prev:
        moves = sorted(((hazardous(d) - hazardous(prev["zips"][z]), z)
                        for z, d in cur["zips"].items() if z in prev["zips"]))
        out += ["", f"Biggest change since {prev['month']}:",
                "  Most improved: " + ", ".join(f"{z} ({dv:+,})" for dv, z in moves[:3]),
                "  Most worsened: " + ", ".join(f"{z} ({dv:+,})" for dv, z in moves[::-1][:3])]
    else:
        out += ["", "No earlier snapshot yet; next month's report will show changes."]
    out += ["", "Raw counts of what is open in city records; not per resident. "
                "Covers HPD housing data (mostly multi-unit rentals)."]
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="propwatch monthly")
    ap.add_argument("--no-save", action="store_true")
    a = ap.parse_args(argv)
    cur = take_snapshot()
    prev = load_previous(cur["month"])
    print(report(cur, prev))
    if not a.no_save:
        os.makedirs(SNAP_DIR, exist_ok=True)
        path = os.path.join(SNAP_DIR, f"{cur['month']}.json")
        with open(path, "w") as f:
            json.dump(cur, f, indent=1, sort_keys=True)
        print(f"\nSaved {os.path.relpath(path, ROOT)}", file=sys.stderr)
