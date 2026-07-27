# cobalt-verify

Offline verifier for **Cobalt audit bundles** — prove an agent-authority audit
trail's integrity with nothing but the file.

A Cobalt bundle is a single JSON document produced by an agent-safety
substrate: every authority decision (allow / confirm / **deny**), safety-monitor
trip, demotion, and earn-back, individually ed25519-signed, merkle-rooted, and
bundle-signed by the site supervisor's key.

This tool answers one question for an auditor, insurer, or notified body:
**is this file exactly what the supervisor's key signed — untampered, complete,
provable — without trusting the party that handed it to you?**

- No account. No server. No network. No source database.
- Any modified byte in any covered section → `INVALID`, with the failing
  check named.

## Install

```
pip install cobalt-verify
```

## Use

```
cobalt-verify bundle.json
```

```
VALID  14 receipts, 3 usage rows, 4 ledger rows
  decisions: allow=5 confirm=2 deny=3
  denials=3  trips=1  movements=4
    DENY 2026-07-27T15:35:13Z  Arm.move zone=loading-dock: authority rung Read does not permit execution
```

Exit code `0` = valid, `1` = invalid. Or from Python:

```python
from cobalt_verify import verify_bundle_file
result = verify_bundle_file("bundle.json")   # {"valid": bool, "errors": [...], ...}
```

## What gets checked

| # | Check | Covers |
|---|---|---|
| 1 | Each receipt's ed25519 signature (embedded public key) | every recorded action, decision, denial, trip |
| 2 | Recomputed merkle root == signed metadata | receipt-set completeness (nothing removed or injected) |
| 3 | Bundle signature (supervisor's key) | metadata, counts, merkle root |
| 4 | Recomputed sections hash (format v2) | authority ledger, policy snapshot, summary |

## Bundle formats

- **v1 `merkle_bundle`** — receipts + usage records.
- **v2 `safety-case`** — v1 plus the authority ledger (trips / demotions /
  earn-backs), an authority snapshot, and a computed summary, all covered by a
  `sections_hash` inside the signed metadata.

The format is open. Verification logic is intentionally small — read
`cobalt_verify/verify.py`.

## License

Apache-2.0.
