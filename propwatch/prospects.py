"""
Prospect list: businesses registered as owners or managing agents of NYC
buildings with open hazardous housing violations.

    python -m propwatch prospects --borough bronx --min 10 --max 400 --out prospects.csv

Uses only business names and business addresses from HPD's public property
registrations. Individual people's names are never read into the output.
Registration "0" (unregistered buildings) is excluded: there is no one to contact.
No phone numbers or emails exist in this data; look up a business's public
listing yourself. Check do-not-call and cold-outreach rules before calling.
"""
import re
import csv
import sys
import argparse
import urllib.parse

from .nyc import _get, SODA
from .log import log, setup as setup_logging, timed

BOROIDS = {"manhattan": "1", "bronx": "2", "brooklyn": "3", "queens": "4", "staten island": "5"}
BATCH = 80


def _q(rid, **p):
    return _get(SODA.format(rid) + "?" + urllib.parse.urlencode(p))


def norm_company(name: str) -> str:
    """'DARDANI INVESTMENT GROUP, LLC' and '... GROUP LLC' -> the same key."""
    s = re.sub(r"[^\w\s&]", "", name.upper())
    return re.sub(r"\s+", " ", s).strip()


def top_registrations(boroid, lo, hi, limit):
    where = "violationstatus='Open' AND class in ('B','C') AND registrationid != '0'"
    if boroid:
        where += f" AND boroid='{boroid}'"
    rows = _q("wvxf-dwi5", **{
        "$select": "registrationid, count(*) as n, sum(case(class='C',1,true,0)) as c",
        "$group": "registrationid", "$where": where,
        "$order": "n DESC", "$limit": str(limit)})
    return [r for r in rows if lo <= int(r["n"]) <= hi]


def build(boroid=None, lo=10, hi=400, limit=1500):
    regs = {r["registrationid"]: (int(r["n"]), int(r["c"])) for r in
            top_registrations(boroid, lo, hi, limit)}
    ids = list(regs)
    companies = {}
    for i in range(0, len(ids), BATCH):
        chunk = ",".join(f"'{x}'" for x in ids[i:i + BATCH] if x.isdigit())
        if not chunk:
            continue
        contacts = _q("feu5-w2e2", **{
            "$select": "registrationid,type,corporationname,businesshousenumber,"
                       "businessstreetname,businesscity,businessstate,businesszip",
            "$where": f"registrationid in ({chunk}) AND type in ('Agent','CorporateOwner')"
                      " AND corporationname IS NOT NULL", "$limit": "5000"})
        addrs = {a["registrationid"]: a for a in _q("tesw-yqqr", **{
            "$select": "registrationid,housenumber,streetname,zip",
            "$where": f"registrationid in ({chunk})", "$limit": "5000"})}
        for c in contacts:
            key = norm_company(c["corporationname"])
            if not key:
                continue
            e = companies.setdefault(key, {
                "company": c["corporationname"].strip(), "roles": set(), "regs": set(),
                "hazardous": 0, "class_c": 0, "samples": [],
                "address": " ".join(filter(None, [c.get("businesshousenumber"),
                                                  c.get("businessstreetname")])),
                "city": f"{c.get('businesscity', '')}, {c.get('businessstate', '')} "
                        f"{c.get('businesszip', '')}".strip()})
            rid = c["registrationid"]
            e["roles"].add("Managing agent" if c["type"] == "Agent" else "Owner")
            if rid not in e["regs"]:
                e["regs"].add(rid)
                e["hazardous"] += regs[rid][0]
                e["class_c"] += regs[rid][1]
                a = addrs.get(rid)
                if a and len(e["samples"]) < 3:
                    e["samples"].append(f"{a.get('housenumber', '')} {a.get('streetname', '')}".strip())
    out = []
    for e in companies.values():
        role = "/".join(sorted(e["roles"]))
        noun = "buildings you manage" if role == "Managing agent" else "of your registered buildings"
        out.append({
            "company": e["company"], "role": role, "business_address": e["address"],
            "city_state_zip": e["city"], "buildings": len(e["regs"]),
            "open_hazardous": e["hazardous"], "class_c": e["class_c"],
            "sample_buildings": "; ".join(e["samples"]),
            "talking_point": f"City records show {e['hazardous']:,} open hazardous housing "
                             f"violations across {len(e['regs'])} {noun}."})
    out.sort(key=lambda r: -r["open_hazardous"])
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(prog="propwatch prospects")
    ap.add_argument("--borough", choices=sorted(BOROIDS), help="limit to one borough")
    ap.add_argument("--min", type=int, default=10, help="min open hazardous per registration")
    ap.add_argument("--max", type=int, default=400, help="max (skips the biggest owners)")
    ap.add_argument("--out", default="prospects.csv")
    a = ap.parse_args(argv)
    setup_logging()
    with timed("prospect list", warn_after=120):
        rows = build(BOROIDS.get(a.borough), a.min, a.max)
    if not rows:
        sys.exit("No matches. Try a lower --min or higher --max.")
    with open(a.out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    print(f"Wrote {len(rows)} businesses to {a.out}\n")
    for r in rows[:10]:
        print(f"{r['company']} ({r['role']}) - {r['open_hazardous']:,} open hazardous in "
              f"{r['buildings']} buildings; {r['business_address']}, {r['city_state_zip']}")
