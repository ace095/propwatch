"""Shared helpers: load .env and build the Anthropic client."""
import os
import sys


def load_dotenv():
    """Load KEY=value lines from a .env in the repo root (stdlib only).
    Real environment variables win over the file."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(root, ".env")
    if not os.path.isfile(path):
        return
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            key = key.strip().removeprefix("export ").strip()
            val = val.strip().strip('"').strip("'")
            if key and val:
                os.environ.setdefault(key, val)


def anthropic_client():
    try:
        import anthropic
    except ImportError:
        sys.exit("Install the SDK first: pip install anthropic")
    load_dotenv()
    if not os.environ.get("ANTHROPIC_API_KEY"):
        sys.exit("ANTHROPIC_API_KEY is not set. Copy .env.example to .env and "
                 "paste your key from https://platform.claude.com/settings/keys")
    return anthropic.Anthropic()
