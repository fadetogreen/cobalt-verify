# cobalt-verify

Offline verifier for **Cobalt audit bundles** — prove an agent-authority audit
trail's integrity with nothing but the file.

A Cobalt bundle is a single JSON document produced by an agent-safety
substrate: every authority decision (allow / confirm / **deny**), safety-monitor
trip, demotion, and earn-back, individually ed25519-signed, merkle-rooted, and
bundle-signed by the site supervisor's key.

This tool answers one question for an auditor, insurer, or notified body:
**is this file exactly what the expected signer's key signed — untampered,
complete, provable — without trusting the party that handed it to you?**

- No account. No server. No network. No source database.
- Any modified byte in any covered section → `INVALID`, with the failing
  check named.

## ⚠️ Pin the signer, or you have proven nothing

A bundle can be *self-consistent* without being *authentic*. Anyone can
generate a keypair and fabricate a bundle whose every signature, hash, and
count agrees — claiming any identity they like. Consistency is not authorship.

So supply the key you expect, obtained **out of band** (a published key, a
contract exhibit, one handed to you in person) — never taken from the bundle
you are checking:

```
cobalt-verify bundle.json --signer-key supervisor.pub.pem
→ VERIFIED  14 receipts, 3 usage rows, 4 ledger rows
```

Without it you get the honest, weaker answer:

```
cobalt-verify bundle.json
→ SELF-CONSISTENT  14 receipts, 3 usage rows, 4 ledger rows
    WARNING: signer NOT verified. ...
```

(v0.1.0 reported plain `VALID` for forged bundles. See CHANGELOG.)

## Install

```
pip install cobalt-verify
```

## Use

```
cobalt-verify bundle.json --signer-key supervisor.pub.pem
```

```
VERIFIED  14 receipts, 3 usage rows, 4 ledger rows
  decisions: allow=5 confirm=2 deny=3
  denials=3  trips=1  movements=4
    DENY 2026-07-27T15:35:13Z  Arm.move zone=loading-dock: authority rung Read does not permit execution
```

Exit code `0` = valid (check the verdict word for attribution), `1` = invalid.
From Python:

```python
from cobalt_verify import verify_bundle_file

result = verify_bundle_file("bundle.json", trusted_signer_key=pem)
assert result["valid"] and result["signer_trusted"]
```

## What gets checked

| # | Check | Covers |
|---|---|---|
| 1 | Each receipt's ed25519 signature | every recorded action, decision, denial, trip |
| 2 | No duplicate `receipt_id` | receipt injection |
| 3 | Domain-separated merkle root == signed root | receipt-set completeness |
| 4 | `receipts_hash` / `usage_hash` / `sections_hash` | every section's contents |
| 5 | Signed counts == actual counts | silent additions or removals |
| 6 | Top-level `signing_did` / `profile` == signed copies | envelope tampering |
| 7 | Bundle signature | all of the above, as one signed unit |
| 8 | Signer identity, when `--signer-key` is given | **authorship** |

## Bundle format

**v3** — one envelope, two profiles: `standard` (receipts + usage) and
`safety-case` (adds the authority ledger of trips/demotions/earn-backs, an
authority snapshot, and a computed summary). The signed metadata commits to
every section.

**v1 / v2 are rejected.** Their merkle construction duplicated odd trailing
leaves (append forgery), counts were unenforced, and `usage_records`,
`signing_did` and `profile` were unsigned. Use `--allow-insecure-legacy` to
inspect such a file — never to attest to one.

The format is open. Verification logic is intentionally small — read
`cobalt_verify/verify.py`.

## License

Apache-2.0.
