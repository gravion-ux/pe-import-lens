"""Command line interface: pe-import-lens scan <file> [--json]."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .parser import flag_imports, parse_imports


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="pe-import-lens")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="Scan one PE file")
    scan.add_argument("file")
    scan.add_argument("--json", action="store_true", help="Emit JSON")
    args = parser.parse_args(argv)
    try:
        entries = parse_imports(Path(args.file).read_bytes())
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    flagged = flag_imports(entries)
    if args.json:
        print(json.dumps({"imports": [e.to_dict() for e in entries], "flagged": flagged}, indent=2))
    else:
        for f in flagged:
            print(f"[{f['severity'].upper()}] {f['dll']}!{f['name']} — {f['note']}")
        if not flagged:
            print(f"{args.file}: {len(entries)} imports, none flagged")
    return 1 if any(f["severity"] == "high" for f in flagged) else 0


if __name__ == "__main__":
    sys.exit(main())
