"""
Propwatch: type an NYC address, see what the city has on record for it.

    python -m propwatch "22 Stagg Street, Brooklyn"
    python -m propwatch "22 Stagg Street, Brooklyn" --json out.json

Flow:  address -> property ID (BIN/BBL) -> six public datasets -> one summary.

Sources (all public, data.cityofnewyork.us unless noted):
    HPD housing violations      wvxf-dwi5   (multi-unit buildings mostly)
    DOB violations (older)      3h2n-5cm9
    DOB safety violations       855j-jady
    ECB / OATH penalties        6bgk-3dad
    DOB complaints              eabe-havv
    311 service requests        erm2-nwe9   (matched by address text)
Address lookup: geosearch.planninglabs.nyc (NYC Planning, free).

Reports what is *on record*. It says nothing about whether a building is safe.
"""
import re
import sys
import json
import argparse
import urllib.parse
import urllib.request
from datetime import date, timedelta

SODA = "https://data.cityofnewyork.us/resource/{}.json"
GEO = "https://geosearch.planninglabs.nyc/v2/search"
BORO_NAMES = {"1": "MANHATTAN", "2": "BRONX", "3": "BROOKLYN", "4": "QUEENS",
              "5": "STATEN ISLAND"}


def _get(url: str):
    req = Request_(url)
    with urllib.request.urlopen(req, timeout=40) as r:
        return json.load(r)


def Request_(url):
    return urllib.request.Request(url, headers={"User-Agent": "propwatch-prototype"})


def _soda(rid: str, where: str, select: str | None = None, limit: int = 5000):
    p = {"$where": where, "$limit": str(limit)}
    if select:
        p["$select"] = select
    return _get(SODA.format(rid) + "?" + urllib.parse.urlencode(p))


# ---------- step 1: address -> property ID ----------

def resolve(address: str) -> dict:
    """Free-text address -> label, BBL, BIN, borough, zip. Raises if not found."""
    data = _get(GEO + "?" + urllib.parse.urlencode({"text": address, "size": 1}))
    feats = data.get("features") or []
    if not feats:
        raise LookupError(f"No NYC address found for: {address!r}")
    p = feats[0]["properties"]
    pad = (p.get("addendum") or {}).get("pad") or {}
    bbl = pad.get("bbl")
    if not bbl:
        raise LookupError(f"Found {p.get('label')!r} but it has no tax-lot ID "
                          "(try a street address, not an intersection).")
    return {"label": p.get("label"), "bbl": bbl, "bin": pad.get("bin"),
            "borough": p.get("borough"), "zip": p.get("postalcode"),
            "housenumber": p.get("housenumber"), "street": p.get("street")}


def bbl_parts(bbl: str):
    """'3030310015' -> ('3', '3031', '15') as HPD stores them (no padding)."""
    return bbl[0], str(int(bbl[1:6])), str(int(bbl[6:]))


def _digits(v: str, what: str) -> str:
    if not re.fullmatch(r"\d+", v or ""):
        raise ValueError(f"bad {what}: {v!r}")
    return v


# ---------- step 2: ask each dataset about that property ----------

def lookup(address: str) -> dict:
    prop = resolve(address)
    boro, block, lot = bbl_parts(_digits(prop["bbl"], "bbl"))
    bin_ = _digits(prop["bin"] or "0", "bin")
    since = (date.today() - timedelta(days=365)).isoformat()

    hpd = _soda("wvxf-dwi5", f"boroid='{boro}' AND block='{block}' AND lot='{lot}'")
    hpd_open = [r for r in hpd if r.get("violationstatus") == "Open"]
    by_class = {}
    for r in hpd_open:
        by_class[r.get("class", "?")] = by_class.get(r.get("class", "?"), 0) + 1

    dob_old = [r for r in _soda("3h2n-5cm9", f"bin='{bin_}'")
               if "ACTIVE" in (r.get("violation_category") or "").upper()]
    dob_new = _soda("855j-jady", f"bin='{bin_}' AND violation_status='Active'")
    ecb = [r for r in _soda("6bgk-3dad", f"bin='{bin_}'")
           if (r.get("ecb_violation_status") or "").upper() == "ACTIVE"]
    dob_complaints = [r for r in _soda("eabe-havv", f"bin='{bin_}'")
                      if (r.get("status") or "").upper() == "ACTIVE"]

    addr311 = f"{prop['housenumber']} {(prop['street'] or '').upper()}"
    req311 = _soda("erm2-nwe9",
                   f"borough='{BORO_NAMES.get(boro, '')}' AND "
                   f"upper(incident_address) like '{_esc(addr311)}%' AND "
                   f"created_date > '{since}'",
                   select="complaint_type,status,created_date")
    types311 = {}
    for r in req311:
        t = r.get("complaint_type", "?")
        types311[t] = types311.get(t, 0) + 1

    balance = sum(_num(r.get("balance_due")) for r in ecb)
    return {
        "address": prop["label"], "bbl": prop["bbl"], "bin": prop["bin"],
        "hpd": {"open": len(hpd_open), "total_on_record": len(hpd),
                "open_by_class": by_class,      # A minor, B hazardous, C immediately hazardous
                "oldest_open_issued": min((r["novissueddate"][:10] for r in hpd_open
                                           if r.get("novissueddate")), default=None),
                "examples": [{"class": r.get("class"), "issued": (r.get("novissueddate") or "")[:10],
                              "text": (r.get("novdescription") or "")[:150]}
                             for r in sorted(hpd_open, key=lambda r: r.get("class", "Z"))[:4]]},
        "dob": {"active_older_system": len(dob_old), "active_dob_now": len(dob_new),
                "types": sorted({(r.get("violation_type") or "").strip()[:60]
                                 for r in dob_old} |
                                {(r.get("violation_type") or "").strip()[:60]
                                 for r in dob_new})[:6]},
        "ecb_penalties": {"active": len(ecb), "balance_due": round(balance, 2)},
        "dob_complaints_active": len(dob_complaints),
        "complaints_311_last_year": {"total": len(req311),
                                     "still_open": sum(1 for r in req311
                                                       if (r.get("status") or "").lower() == "open"),
                                     "top_types": sorted(types311.items(),
                                                         key=lambda kv: -kv[1])[:5]},
    }


def _esc(s: str) -> str:
    return s.replace("'", "''")


def _num(v) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


# ---------- step 3: say it in plain words ----------

def render(r: dict) -> str:
    h, d, e = r["hpd"], r["dob"], r["ecb_penalties"]
    c = r["complaints_311_last_year"]
    cls = ", ".join(f"{n} Class {k}" for k, n in sorted(h["open_by_class"].items())) or "none"
    lines = [
        f"{r['address']}   (BBL {r['bbl']}, BIN {r['bin']})", "",
        f"Housing (HPD):      {h['open']} open violations ({cls})"
        + (f"; oldest issued {h['oldest_open_issued']}" if h["oldest_open_issued"] else ""),
        f"Buildings (DOB):    {d['active_older_system'] + d['active_dob_now']} active violations",
        f"Penalties (ECB):    {e['active']} active, ${e['balance_due']:,.2f} balance due",
        f"DOB complaints:     {r['dob_complaints_active']} active",
        f"311 (last year):    {c['total']} requests, {c['still_open']} still open"
        + (f"; most common: {c['top_types'][0][0]}" if c["top_types"] else ""),
        "", "Class C = immediately hazardous, B = hazardous, A = non-hazardous.",
        "This shows what is on record. It does not say whether the building is safe.",
    ]
    if h["open"] == 0 and d["active_older_system"] + d["active_dob_now"] == 0:
        lines.append("Note: no HPD records is normal for many 1-2 family homes; "
                     "check DOB, ECB and 311 above.")
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="propwatch",
                                 description="What the city has on record for an NYC address.")
    ap.add_argument("address", help='e.g. "22 Stagg Street, Brooklyn"')
    ap.add_argument("--json", metavar="FILE", help="also save the raw summary")
    a = ap.parse_args(argv)
    try:
        res = lookup(a.address)
    except (LookupError, ValueError) as ex:
        sys.exit(str(ex))
    print(render(res))
    if a.json:
        with open(a.json, "w") as f:
            json.dump(res, f, indent=2)
