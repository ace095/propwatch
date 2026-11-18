"""
Propwatch: type an NYC address, see what the city has on record for it.

    python -m propwatch "22 Stagg Street, Brooklyn"
    python -m propwatch "22 Stagg Street, Brooklyn" --json out.json

Flow:  address -> property ID (BIN/BBL) -> six public datasets (in parallel)
       -> one summary, with freshness and "possibly stale" flags.

Sources (all public, data.cityofnewyork.us unless noted):
    HPD housing violations      wvxf-dwi5   (multi-unit buildings mostly)
    DOB violations (older)      3h2n-5cm9
    DOB safety violations       855j-jady
    ECB / OATH penalties        6bgk-3dad
    DOB complaints              eabe-havv
    311 service requests        erm2-nwe9   (matched by address text)
Address lookup: geosearch.planninglabs.nyc (NYC Planning, free).

Reports what is *on record*. It says nothing about whether a building is safe.
If a source cannot be reached, that section is marked unavailable instead of
showing zero, so a failure is never mistaken for a clean record.
"""
import re
import sys
import json
import time
import argparse
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timedelta, timezone

from .log import log, setup as setup_logging, timed

SODA = "https://data.cityofnewyork.us/resource/{}.json"
VIEWS = "https://data.cityofnewyork.us/api/views/{}.json"
GEO = "https://geosearch.planninglabs.nyc/v2/search"
BORO_NAMES = {"1": "MANHATTAN", "2": "BRONX", "3": "BROOKLYN", "4": "QUEENS",
              "5": "STATEN ISLAND"}
DATASETS = {"hpd": ("HPD housing violations", "wvxf-dwi5"),
            "dob_old": ("DOB violations (older system)", "3h2n-5cm9"),
            "dob_new": ("DOB safety violations", "855j-jady"),
            "ecb": ("ECB / OATH penalties", "6bgk-3dad"),
            "dob_complaints": ("DOB complaints", "eabe-havv"),
            "311": ("311 requests", "erm2-nwe9")}
STALE_SOURCE_DAYS = 7      # a dataset not refreshed this long is flagged
STALE_RECORD_YEARS = 5     # an open violation this old may be a records problem


def _get(url: str, tries: int = 4):
    """GET JSON, retrying transient network errors (city API and proxies drop connections)."""
    for attempt in range(tries):
        try:
            with urllib.request.urlopen(Request_(url), timeout=120) as r:
                return json.load(r)
        except (urllib.error.URLError, ConnectionError, TimeoutError) as e:
            if attempt == tries - 1:
                log.error("GET failed after %d tries: %s (%s)", tries, url[:120], e)
                raise
            log.warning("GET retry %d for %s (%s)", attempt + 1, url[:100], e)
            time.sleep(2 ** attempt)


def Request_(url):
    return urllib.request.Request(url, headers={"User-Agent": "propwatch-prototype"})


def _soda(rid: str, where: str, select: str | None = None, limit: int = 5000):
    p = {"$where": where, "$limit": str(limit)}
    if select:
        p["$select"] = select
    return _get(SODA.format(rid) + "?" + urllib.parse.urlencode(p))


# ---------- freshness: how old is the city's data? ----------

_fresh_cache: dict = {"at": 0, "val": None}


def freshness(max_age: int = 3600) -> dict:
    """When each dataset was last updated by the city. Cached for an hour."""
    if _fresh_cache["val"] and time.time() - _fresh_cache["at"] < max_age:
        return _fresh_cache["val"]

    def one(item):
        key, (label, rid) = item
        try:
            ts = _get(VIEWS.format(rid), tries=2)["rowsUpdatedAt"]
            when = datetime.fromtimestamp(ts, timezone.utc)
            age = (datetime.now(timezone.utc) - when).days
            return key, {"label": label, "updated": when.isoformat(timespec="minutes"),
                         "age_days": age, "stale": age > STALE_SOURCE_DAYS}
        except Exception as e:  # metadata is a nice-to-have; never break a lookup
            log.warning("freshness check failed for %s: %s", rid, e)
            return key, {"label": label, "updated": None, "age_days": None, "stale": None}

    with ThreadPoolExecutor(max_workers=6) as ex:
        val = dict(ex.map(one, DATASETS.items()))
    _fresh_cache.update(at=time.time(), val=val)
    return val


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


def _esc(s: str) -> str:
    return s.replace("'", "''")


def _num(v) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0


def _age_years(iso: str | None) -> float:
    try:
        return (date.today() - date.fromisoformat(iso[:10])).days / 365.25
    except (TypeError, ValueError):
        return 0.0


# ---------- step 2: ask each dataset about that property (in parallel) ----------

def lookup(address: str) -> dict:
    t0 = time.time()
    prop = resolve(address)
    boro, block, lot = bbl_parts(_digits(prop["bbl"], "bbl"))
    bin_ = _digits(prop["bin"] or "0", "bin")
    since = (date.today() - timedelta(days=365)).isoformat()
    addr311 = f"{prop['housenumber']} {(prop['street'] or '').upper()}"

    queries = {
        "hpd": lambda: _soda("wvxf-dwi5", f"boroid='{boro}' AND block='{block}' AND lot='{lot}'"),
        "dob_old": lambda: _soda("3h2n-5cm9", f"bin='{bin_}'"),
        "dob_new": lambda: _soda("855j-jady", f"bin='{bin_}' AND violation_status='Active'"),
        "ecb": lambda: _soda("6bgk-3dad", f"bin='{bin_}'"),
        "dob_complaints": lambda: _soda("eabe-havv", f"bin='{bin_}'"),
        "311": lambda: _soda(
            "erm2-nwe9",
            f"borough='{BORO_NAMES.get(boro, '')}' AND "
            f"upper(incident_address) like '{_esc(addr311)}%' AND created_date > '{since}'",
            select="complaint_type,status,created_date"),
    }

    def run(item):
        key, fn = item
        try:
            with timed(f"{key} query for {prop['label']}", warn_after=20):
                return key, fn(), None
        except Exception as e:
            log.error("source %s failed for %r: %s", key, address, e)
            return key, None, str(e)[:120]

    with ThreadPoolExecutor(max_workers=6) as ex:
        out = {k: (v, err) for k, v, err in ex.map(run, queries.items())}
    unavailable = [DATASETS[k][0] for k, (v, err) in out.items() if v is None]
    d = {k: v for k, (v, err) in out.items()}

    hpd = d["hpd"]
    hpd_open = [r for r in hpd if r.get("violationstatus") == "Open"] if hpd is not None else None
    by_class, over5 = {}, 0
    for r in hpd_open or []:
        by_class[r.get("class", "?")] = by_class.get(r.get("class", "?"), 0) + 1
        if _age_years(r.get("novissueddate")) > STALE_RECORD_YEARS:
            over5 += 1

    dob_old = None if d["dob_old"] is None else [
        r for r in d["dob_old"] if "ACTIVE" in (r.get("violation_category") or "").upper()]
    ecb = None if d["ecb"] is None else [
        r for r in d["ecb"] if (r.get("ecb_violation_status") or "").upper() == "ACTIVE"]
    dob_c = None if d["dob_complaints"] is None else [
        r for r in d["dob_complaints"] if (r.get("status") or "").upper() == "ACTIVE"]
    req311 = d["311"]
    types311 = {}
    for r in req311 or []:
        t = r.get("complaint_type", "?")
        types311[t] = types311.get(t, 0) + 1

    result = {
        "address": prop["label"], "bbl": prop["bbl"], "bin": prop["bin"],
        "unavailable": unavailable,
        "hpd": {"open": None if hpd_open is None else len(hpd_open),
                "total_on_record": None if hpd is None else len(hpd),
                "open_by_class": by_class,       # A minor, B hazardous, C immediately hazardous
                "open_over_5_years": over5,       # possibly stale records
                "oldest_open_issued": min((r["novissueddate"][:10] for r in hpd_open or []
                                           if r.get("novissueddate")), default=None),
                "examples": [{"class": r.get("class"), "issued": (r.get("novissueddate") or "")[:10],
                              "text": (r.get("novdescription") or "")[:150]}
                             for r in sorted(hpd_open or [], key=lambda r: r.get("class", "Z"))[:4]]},
        "dob": {"active_older_system": None if dob_old is None else len(dob_old),
                "active_dob_now": None if d["dob_new"] is None else len(d["dob_new"]),
                "types": sorted({(r.get("violation_type") or "").strip()[:60]
                                 for r in (dob_old or []) + (d["dob_new"] or [])})[:6]},
        "ecb_penalties": {"active": None if ecb is None else len(ecb),
                          "balance_due": round(sum(_num(r.get("balance_due")) for r in ecb or []), 2)},
        "dob_complaints_active": None if dob_c is None else len(dob_c),
        "complaints_311_last_year": {
            "total": None if req311 is None else len(req311),
            "still_open": sum(1 for r in req311 or [] if (r.get("status") or "").lower() == "open"),
            "top_types": sorted(types311.items(), key=lambda kv: -kv[1])[:5]},
    }
    log.info("lookup %r done in %.1fs, unavailable=%s", address, time.time() - t0, unavailable)
    return with_steps(result)


def with_steps(result: dict) -> dict:
    from .guidance import next_steps
    result["next_steps"] = next_steps(result)
    return result


# ---------- step 3: say it in plain words ----------

def _n(v) -> str:
    return "unavailable" if v is None else f"{v:,}"


def render(r: dict) -> str:
    h, d, e = r["hpd"], r["dob"], r["ecb_penalties"]
    c = r["complaints_311_last_year"]
    cls = ", ".join(f"{n} Class {k}" for k, n in sorted(h["open_by_class"].items())) or "none"
    dob_n = None if d["active_older_system"] is None or d["active_dob_now"] is None \
        else d["active_older_system"] + d["active_dob_now"]
    lines = [f"{r['address']}   (BBL {r['bbl']}, BIN {r['bin']})", ""]
    if r.get("unavailable"):
        lines += ["WARNING: could not reach: " + "; ".join(r["unavailable"]) +
                  ". Those lines below are NOT zero, they are unknown.", ""]
    lines += [
        f"Housing (HPD):      {_n(h['open'])} open violations"
        + (f" ({cls})" if h["open"] else "")
        + (f"; oldest issued {h['oldest_open_issued']}" if h["oldest_open_issued"] else ""),
        f"Buildings (DOB):    {_n(dob_n)} active violations",
        f"Penalties (ECB):    {_n(e['active'])} active, ${e['balance_due']:,.2f} balance due",
        f"DOB complaints:     {_n(r['dob_complaints_active'])} active",
        f"311 (last year):    {_n(c['total'])} requests, {c['still_open']} still open"
        + (f"; most common: {c['top_types'][0][0]}" if c["top_types"] else ""),
    ]
    if h.get("open_over_5_years"):
        lines.append(f"Possibly stale:     {h['open_over_5_years']} housing violations have been open "
                     f"over {STALE_RECORD_YEARS} years; verify these on HPD Online.")
    lines += ["", "Class C = immediately hazardous, B = hazardous, A = non-hazardous.",
              "This shows what is on record. It does not say whether the building is safe."]
    if (h["open"] or 0) == 0 and (dob_n or 0) == 0 and not r.get("unavailable"):
        lines.append("Note: no HPD records is normal for many 1-2 family homes; "
                     "check DOB, ECB and 311 above.")
    if r.get("next_steps"):
        lines += ["", "What this usually means:"]
        for st in r["next_steps"]:
            lines.append(f"  - {st['title']}: {st['body']}")
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="propwatch",
                                 description="What the city has on record for an NYC address.")
    ap.add_argument("address", help='e.g. "22 Stagg Street, Brooklyn"')
    ap.add_argument("--json", metavar="FILE", help="also save the raw summary")
    a = ap.parse_args(argv)
    setup_logging()
    try:
        res = lookup(a.address)
    except (LookupError, ValueError) as ex:
        sys.exit(str(ex))
    print(render(res))
    stale = [v["label"] for v in freshness().values() if v["stale"]]
    if stale:
        print("\nWARNING: the city has not refreshed these in over "
              f"{STALE_SOURCE_DAYS} days: {', '.join(stale)}")
    if a.json:
        with open(a.json, "w") as f:
            json.dump(res, f, indent=2)
