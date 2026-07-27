# Changelog

## 0.2.0 — 2026-07-28

**Security release. 0.1.0 accepted forged bundles as valid — do not use it.**

Found by an adversarial review of the format and this verifier, and reproduced
before fixing.

### Fixed

- **CRITICAL — forged bundles verified as valid.** The verifier trusted the
  public keys embedded in the bundle it was checking. Anyone could generate
  their own Ed25519 keypair, fabricate receipts claiming any DID, sign the
  bundle with that key, and get `{"valid": true, "errors": []}`. "Signed by
  DID X" was never checked; only internal consistency was.

  Verification now reports `signer_trusted`, and you can pin the expected key:

      verify_bundle(bundle, trusted_signer_key=PEM)
      cobalt-verify bundle.json --signer-key supervisor.pub.pem

  Without a pinned key the CLI prints **SELF-CONSISTENT** and a warning instead
  of VALID. Get the key out of band — never from the bundle under test.

- **CRITICAL — receipt injection via odd-leaf merkle duplication.** The tree
  duplicated an odd trailing leaf, so `[A,B,C]` and `[A,B,C,C]` produced the
  same root (CVE-2012-2459 class): a receipt could be appended to a signed
  bundle and still verify. The tree is now domain-separated —
  `leaf = H(0x00‖data)`, `node = H(0x01‖l‖r)` — and odd nodes are promoted,
  never duplicated. Duplicate `receipt_id`s are also rejected outright.

- **HIGH — signed counts were never enforced.** `receipt_count`, `usage_count`
  and `ledger_count` were signed but ignored, so receipts could be added or
  dropped silently. All three are now checked against the actual contents.

- **HIGH — whole sections were covered by no hash.** `usage_records`,
  top-level `signing_did`, and `profile` could be edited freely while the
  bundle still verified. Format v3 commits to every section
  (`receipts_hash`, `usage_hash`, `sections_hash`) plus `signing_did` and
  `profile` inside the signed metadata.

### Changed

- **Bundle format v3 is now the only accepted format.** v1 and v2 are rejected
  with an explanatory error — they carry the weaknesses above and cannot be
  made safe after the fact. Pass `allow_insecure_legacy=True` (or
  `--allow-insecure-legacy`) to inspect an old file; never to attest to one.
- `verify_bundle` returns `signer_trusted` and always populates
  `counts.ledger_rows`.
- CLI exits 0 for both VERIFIED and SELF-CONSISTENT; check the verdict word or
  use `--signer-key` to require attribution.

## 0.1.0 — 2026-07-27

Initial release. **Withdrawn — see 0.2.0.** Never published to PyPI.
