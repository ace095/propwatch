"""
Tiny local web app (standard library only).

    python -m propwatch serve            # http://127.0.0.1:8000
    python -m propwatch serve --port 9000

Routes:
    /                      the page
    /api/lookup?address=   one address across six city datasets
    /api/area?zip=         one zip's open housing violations
    /api/snapshot          latest monthly citywide snapshot (top / bottom zips)

Results are cached for 10 minutes to be gentle on the city's servers.
Binds to 127.0.0.1 by default (your machine only).
"""
import os
import re
import json
import glob
import time
import argparse
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import nyc, area, monthly

HERE = os.path.dirname(os.path.abspath(__file__))
TTL = 600
_cache: dict = {}


def cached(key, fn):
    hit = _cache.get(key)
    if hit and time.time() - hit[0] < TTL:
        return hit[1]
    val = fn()
    _cache[key] = (time.time(), val)
    return val


def latest_snapshot():
    files = sorted(glob.glob(os.path.join(monthly.SNAP_DIR, "*.json")))
    if not files:
        raise FileNotFoundError("no snapshot")
    snap = json.load(open(files[-1]))
    rows = [(z, d) for z, d in snap["zips"].items() if d["buildings"] >= monthly.MIN_BUILDINGS]
    rows.sort(key=lambda kv: -(monthly.hazardous(kv[1]) / kv[1]["buildings"]))
    return {"month": snap["month"], "taken": snap["taken"], "n": len(rows),
            "top": [{"zip": z, **d} for z, d in rows[:12]],
            "low": [{"zip": z, **d} for z, d in rows[-5:]],
            "tot_h": sum(monthly.hazardous(d) for d in snap["zips"].values()),
            "tot_c": sum(d["C"] for d in snap["zips"].values())}


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body: bytes, ctype="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code, obj):
        self._send(code, json.dumps(obj).encode())

    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(url.query)
        try:
            if url.path == "/":
                with open(os.path.join(HERE, "static", "index.html"), "rb") as f:
                    return self._send(200, f.read(), "text/html; charset=utf-8")
            if url.path == "/api/lookup":
                a = (q.get("address", [""])[0]).strip()
                if not 3 <= len(a) <= 200:
                    return self._json(400, {"error": "Enter a street address, like 22 Stagg Street, Brooklyn."})
                return self._json(200, cached(("a", a.lower()), lambda: nyc.lookup(a)))
            if url.path == "/api/area":
                z = (q.get("zip", [""])[0]).strip()
                if not re.fullmatch(r"\d{5}", z):
                    return self._json(400, {"error": "Enter a 5-digit zip code."})
                return self._json(200, cached(("z", z), lambda: area.area_summary(z)))
            if url.path == "/api/snapshot":
                return self._json(200, latest_snapshot())
            return self._json(404, {"error": "Not found"})
        except (LookupError, ValueError) as e:
            return self._json(404, {"error": str(e)})
        except FileNotFoundError:
            return self._json(404, {"error": "No monthly snapshot yet. Run: python -m propwatch monthly"})
        except Exception:
            return self._json(502, {"error": "The city's data service didn't answer. Try again in a moment."})

    def log_message(self, fmt, *args):
        pass


def main(argv=None):
    ap = argparse.ArgumentParser(prog="propwatch serve")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--host", default="127.0.0.1")
    a = ap.parse_args(argv)
    print(f"Propwatch running at http://{a.host}:{a.port}  (Ctrl+C to stop)")
    ThreadingHTTPServer((a.host, a.port), Handler).serve_forever()
