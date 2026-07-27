"""cobalt-verify — verify a Cobalt audit bundle offline.

Usage:
    cobalt-verify BUNDLE.json

Exit code 0 = VALID, 1 = INVALID or unreadable.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from cobalt_verify.verify import verify_bundle_file


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cobalt-verify",
        description="Verify a Cobalt audit bundle offline — no account, no "
                    "server, no database. Integrity is proven with the public "
                    "keys embedded in the bundle itself.",
    )
    parser.add_argument("bundle", help="Path to the bundle JSON file.")
    parser.add_argument(
        "--signer-key", metavar="PEM",
        help="File containing the expected signer's PEM public key, obtained "
             "OUT OF BAND (published key, contract exhibit, handed to you). "
             "Without it a valid result proves internal consistency only — NOT "
             "that the named party produced the bundle.",
    )
    parser.add_argument(
        "--allow-insecure-legacy", action="store_true",
        help="Inspect v1/v2 bundles, which have known forgery weaknesses. "
             "Never attest to a bundle read this way.",
    )
    args = parser.parse_args(argv)

    trusted = None
    if args.signer_key:
        try:
            trusted = Path(args.signer_key).read_text()
        except OSError as e:
            print(f"error: cannot read signer key: {e}", file=sys.stderr)
            return 1

    try:
        result = verify_bundle_file(
            args.bundle, trusted_signer_key=trusted,
            allow_insecure_legacy=args.allow_insecure_legacy,
        )
    except FileNotFoundError:
        print(f"error: no such file: {args.bundle}", file=sys.stderr)
        return 1
    except ValueError as e:
        print(f"error: not valid JSON: {e}", file=sys.stderr)
        return 1

    if result["valid"]:
        c = result["counts"]
        verdict = "VERIFIED" if result["signer_trusted"] else "SELF-CONSISTENT"
        line = f"{verdict}  {c['receipts']} receipts, {c['usage_records']} usage rows"
        if c.get("ledger_rows"):
            line += f", {c['ledger_rows']} ledger rows"
        print(line)
        if not result["signer_trusted"]:
            print("  WARNING: signer NOT verified. This bundle is internally")
            print("  consistent, but anyone can generate a key and produce a")
            print("  consistent bundle. Re-run with --signer-key to prove who")
            print("  signed it.")
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
