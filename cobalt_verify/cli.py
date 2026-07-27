"""cobalt-verify — verify a Cobalt audit bundle offline.

Usage:
    cobalt-verify BUNDLE.json

Exit code 0 = VALID, 1 = INVALID or unreadable.
"""

from __future__ import annotations

import argparse
import sys

from cobalt_verify.verify import verify_bundle_file


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cobalt-verify",
        description="Verify a Cobalt audit bundle offline — no account, no "
                    "server, no database. Integrity is proven with the public "
                    "keys embedded in the bundle itself.",
    )
    parser.add_argument("bundle", help="Path to the bundle JSON file.")
    args = parser.parse_args(argv)

    try:
        result = verify_bundle_file(args.bundle)
    except FileNotFoundError:
        print(f"error: no such file: {args.bundle}", file=sys.stderr)
        return 1
    except ValueError as e:
        print(f"error: not valid JSON: {e}", file=sys.stderr)
        return 1

    if result["valid"]:
        c = result["counts"]
        line = f"VALID  {c['receipts']} receipts, {c['usage_records']} usage rows"
        if "ledger_rows" in c:
            line += f", {c['ledger_rows']} ledger rows"
        print(line)
        s = result.get("summary")
        if s:
            d = s.get("decisions", {})
            print(
                f"  decisions: allow={d.get('allow', 0)} "
                f"confirm={d.get('confirm', 0)} deny={d.get('deny', 0)}"
            )
            print(
                f"  denials={len(s.get('denials', []))}  "
                f"trips={len(s.get('trips', []))}  "
                f"movements={len(s.get('movements', []))}"
            )
            for denial in s.get("denials", [])[:10]:
                zone = f" zone={denial['zone']}" if denial.get("zone") else ""
                print(f"    DENY {denial['at']}  {denial['capability']}{zone}: "
                      f"{denial.get('reason')}")
        return 0

    print("INVALID", file=sys.stderr)
    for err in result["errors"]:
        print(f"  - {err}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
