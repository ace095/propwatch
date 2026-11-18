"""Logging for Propwatch: stderr plus a rolling file at logs/propwatch.log."""
import os
import time
import logging
from logging.handlers import RotatingFileHandler
from contextlib import contextmanager

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(ROOT, "logs")
log = logging.getLogger("propwatch")


def setup(level=logging.INFO):
    if log.handlers:
        return log
    log.setLevel(level)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    sh = logging.StreamHandler()
    sh.setLevel(logging.WARNING)
    sh.setFormatter(fmt)
    log.addHandler(sh)
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        fh = RotatingFileHandler(os.path.join(LOG_DIR, "propwatch.log"),
                                 maxBytes=1_000_000, backupCount=3, encoding="utf-8")
        fh.setFormatter(fmt)
        log.addHandler(fh)
    except OSError:
        pass  # read-only disk: stderr logging is enough
    return log


@contextmanager
def timed(label: str, warn_after: float = 15.0):
    """Log how long a step took; warn when it is slow (a bottleneck signal)."""
    t = time.time()
    try:
        yield
    finally:
        dt = time.time() - t
        (log.warning if dt > warn_after else log.info)("%s took %.1fs", label, dt)
