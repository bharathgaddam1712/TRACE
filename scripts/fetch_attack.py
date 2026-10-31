"""Download the pinned MITRE ATT&CK Enterprise STIX bundle and check its hash.

    python scripts/fetch_attack.py --version 20.0
"""
import argparse
import hashlib
import sys
import urllib.request
from pathlib import Path

URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-{v}.json"
KNOWN_SHA256 = {"20.0": "81113ba98afa2928f3dcff62022539f7ce30c315c32e14422f11ff95ce534352"}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", default="20.0")
    ap.add_argument("--out", default=str(Path(__file__).resolve().parents[1] / "attack"))
    a = ap.parse_args()
    out = Path(a.out) / f"enterprise-attack-{a.version}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    print(f"downloading {URL.format(v=a.version)}")
    with urllib.request.urlopen(URL.format(v=a.version), timeout=120) as resp:
        data = resp.read()
    digest = hashlib.sha256(data).hexdigest()
    want = KNOWN_SHA256.get(a.version)
    if want and digest != want:
        print(f"sha256 mismatch: got {digest}, expected {want}", file=sys.stderr)
        return 1
    out.write_bytes(data)
    print(f"saved {out} ({len(data) / 1e6:.1f} MB) sha256={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
