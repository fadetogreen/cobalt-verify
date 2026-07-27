"""Offline verifier for Cobalt audit bundles.

Standalone by design: no dependency on the Cobalt substrate, no network, no
database. A third party receives a single JSON bundle file and checks its
integrity using cryptography alone.

## What "valid" means — read this before trusting a result

A bundle is *self-consistent* when every receipt signature, the merkle root,
the section hashes, the counts, and the bundle signature all agree.
Self-consistency alone proves **nothing about who produced the bundle** — an
attacker can generate their own keypair and fabricate an entirely consistent
bundle claiming any DID. (This verifier accepted exactly such a forgery before
v0.2.0; see CHANGELOG.)

To get a trustworthy answer you MUST pin the expected signer:

    verify_bundle(bundle, trusted_signer_key=EXPECTED_PUBLIC_KEY_PEM)
    cobalt-verify bundle.json --signer-key supervisor.pub.pem

Obtain that key out of band — the site's published key, a contract exhibit, a
key you were handed in person. Never take it from the bundle you are checking.
Without it, results carry `signer_trusted: False` and the CLI says
SELF-CONSISTENT rather than VERIFIED.

## Formats

    format_version 3 — current. Signed metadata covers every section
        (receipts_hash, usage_hash, sections_hash, counts, merkle_root,
        signing_did, profile), and the merkle tree is domain-separated.
    format_version 1, 2 — REJECTED. Known forgery weaknesses: the merkle
        construction duplicated odd trailing leaves, so appending a duplicate
        receipt preserved the root; counts were unenforced; usage_records,
        signing_did and profile were covered by no hash at all. Re-export as
        v3. Pass allow_insecure_legacy=True only to inspect historical files,
        never to attest to them.

## Checks (v3)

    1. every receipt's ed25519 signature over its canonical payload
    2. no duplicate receipt_id
    3. merkle root over receipt hashes (domain-separated) == signed root
    4. receipts_hash / usage_hash / sections_hash == signed hashes
    5. counts == signed counts
    6. top-level signing_did / profile == their signed copies
    7. bundle signature over canonical metadata
    8. signer identity, when a trusted key is pinned
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.serialization import load_pem_public_key

__all__ = ["verify_bundle", "verify_bundle_file"]

SUPPORTED_FORMAT = 3
LEGACY_FORMATS = (1, 2)


# ---------------------------------------------------------------------------
# Canonical forms — must match the Cobalt substrate byte-for-byte.
# ---------------------------------------------------------------------------

def _canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode()


def _canonical_receipt_payload(receipt: dict) -> bytes:
    """The signed byte sequence of a receipt (signature/public_key excluded)."""
    payload = {
        "receipt_id": receipt["receipt_id"],
        "parent_receipt_id": receipt.get("parent_receipt_id"),
        "actor_did": receipt["actor_did"],
        "actor_model": receipt.get("actor_model"),
        "actor_model_provider": receipt.get("actor_model_provider"),
        "capability": receipt["capability"],
        "authority_level": receipt["authority_level"],
        "inputs_hash": receipt["inputs_hash"],
        "outputs_hash": receipt["outputs_hash"],
        "counterparties": receipt.get("counterparties", []),
        "started_at": receipt["started_at"],
        "completed_at": receipt["completed_at"],
        "metadata": receipt.get("metadata", {}),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _merkle_root(leaf_hashes: list[str]) -> str:
    """Domain-separated merkle root (RFC 6962 style).

    leaf  = SHA256(0x00 || leaf_bytes)
    node  = SHA256(0x01 || left || right)
    An odd trailing node is PROMOTED unchanged, never duplicated — duplicating
    it is what let [A,B,C] and [A,B,C,C] share a root (CVE-2012-2459 class).
    """
    if not leaf_hashes:
        return hashlib.sha256(b"\x02cobalt-empty").hexdigest()
    nodes = [hashlib.sha256(b"\x00" + bytes.fromhex(h)).digest() for h in leaf_hashes]
    while len(nodes) > 1:
        nxt = []
        for i in range(0, len(nodes), 2):
            if i + 1 < len(nodes):
                nxt.append(hashlib.sha256(b"\x01" + nodes[i] + nodes[i + 1]).digest())
            else:
                nxt.append(nodes[i])
        nodes = nxt
    return nodes[0].hex()


def _canonical_sections(ledger: list, snapshot: dict, summary: dict) -> bytes:
    return _canon({"ledger": ledger, "authority_snapshot": snapshot, "summary": summary})


def _canonical_bundle_metadata(meta: dict) -> bytes:
    """Every field the bundle signature commits to. Adding a field here is a
    format change — the substrate and this verifier must agree exactly."""
    payload = {
        "tenant_did": meta["tenant_did"],
        "generated_at": meta["generated_at"],
        "period_start": meta["period_start"],
        "period_end": meta["period_end"],
        "receipt_count": meta["receipt_count"],
        "usage_count": meta["usage_count"],
        "ledger_count": meta["ledger_count"],
        "merkle_root": meta["merkle_root"],
        "receipts_hash": meta["receipts_hash"],
        "usage_hash": meta["usage_hash"],
        "sections_hash": meta["sections_hash"],
        "signing_did": meta["signing_did"],
        "profile": meta["profile"],
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------

def verify_bundle(
    bundle: dict,
    *,
    trusted_signer_key: str | None = None,
    allow_insecure_legacy: bool = False,
) -> dict:
    """Verify a Cobalt bundle.

    trusted_signer_key: PEM public key obtained OUT OF BAND. When given, the
        bundle must be signed by exactly that key. When omitted, the result is
        `signer_trusted: False` and proves only internal consistency.

    Returns {"valid", "signer_trusted", "errors", "counts", ...}.
    """
    errors: list[str] = []
    version = bundle.get("format_version")

    if version in LEGACY_FORMATS and not allow_insecure_legacy:
        return {
            "valid": False, "signer_trusted": False, "counts": {},
            "errors": [
                (
                    f"format_version {version} is REJECTED: known forgery weaknesses "
                    f"(odd-leaf merkle duplication, unenforced counts, unsigned "
                    f"sections). Re-export as v{SUPPORTED_FORMAT}."
                )
            ],
        }
    if version != SUPPORTED_FORMAT and not (version in LEGACY_FORMATS and allow_insecure_legacy):
        return {
            "valid": False, "signer_trusted": False, "counts": {},
            "errors": [f"Unknown format_version: {version}"],
        }

    receipts = bundle.get("receipts", [])
    usage = bundle.get("usage_records", [])
    ledger = bundle.get("ledger", [])
    metadata = bundle.get("metadata", {})

    # 1. per-receipt signatures
    failures = 0
    for r in receipts:
        try:
            pub = load_pem_public_key(r["public_key"].encode())
            pub.verify(bytes.fromhex(r["signature"]), _canonical_receipt_payload(r))
        except Exception:
            failures += 1
    if failures:
        errors.append(f"{failures} receipt signature(s) failed verification")

    # 2. duplicate receipt ids
    ids = [r.get("receipt_id") for r in receipts]
    if len(set(ids)) != len(ids):
        dupes = len(ids) - len(set(ids))
        errors.append(f"{dupes} duplicate receipt_id(s) — receipts were injected")

    if version == SUPPORTED_FORMAT:
        # 3. merkle root
        expected_root = _merkle_root(
            [hashlib.sha256(_canonical_receipt_payload(r)).hexdigest() for r in receipts]
        )
        if expected_root != metadata.get("merkle_root"):
            errors.append("Merkle root mismatch: the receipt set was modified")

        # 4. section hashes
        if hashlib.sha256(_canon(receipts)).hexdigest() != metadata.get("receipts_hash"):
            errors.append("Receipts hash mismatch: receipt contents were modified")
        if hashlib.sha256(_canon(usage)).hexdigest() != metadata.get("usage_hash"):
            errors.append("Usage hash mismatch: usage records were modified")
        sections = hashlib.sha256(
            _canonical_sections(ledger, bundle.get("authority_snapshot", {}),
                                bundle.get("summary", {}))).hexdigest()
        if sections != metadata.get("sections_hash"):
            errors.append("Sections hash mismatch: ledger/snapshot/summary were modified")

        # 5. counts
        for field, actual, what in (
            ("receipt_count", len(receipts), "receipts"),
            ("usage_count", len(usage), "usage records"),
            ("ledger_count", len(ledger), "ledger rows"),
        ):
            if metadata.get(field) != actual:
                errors.append(
                    f"Count mismatch: signed {field}={metadata.get(field)} but "
                    f"bundle carries {actual} {what}"
                )

        # 6. top-level copies must match their signed originals
        for field in ("signing_did", "profile"):
            if bundle.get(field) != metadata.get(field):
                errors.append(f"Top-level {field} does not match the signed metadata")

    # 7. bundle signature
    signer_trusted = False
    try:
        embedded_pem = bundle["signing_public_key"]
        if trusted_signer_key is not None:
            trusted = load_pem_public_key(trusted_signer_key.encode())
            embedded = load_pem_public_key(embedded_pem.encode())
            if trusted.public_bytes_raw() != embedded.public_bytes_raw():
                errors.append(
                    "Signer mismatch: bundle is signed by a key other than the "
                    "trusted key you supplied"
                )
            else:
                signer_trusted = True
            verifying_key = trusted
        else:
            verifying_key = load_pem_public_key(embedded_pem.encode())
        sig = bytes.fromhex(bundle["bundle_signature"])
        verifying_key.verify(sig, _canonical_bundle_metadata(metadata))
    except KeyError as e:
        errors.append(f"Missing bundle field: {e}")
    except Exception as e:
        errors.append(f"Bundle signature failed: {type(e).__name__}")
        signer_trusted = False

    if errors:
        signer_trusted = False

    result = {
        "valid": len(errors) == 0,
        "signer_trusted": signer_trusted,
        "errors": errors,
        "counts": {
            "receipts": len(receipts),
            "usage_records": len(usage),
            "ledger_rows": len(ledger),
        },
        "authorship": _authorship_tally(
            receipts, (bundle.get("authority_snapshot") or {}).get("identities")
        ),
    }
    if bundle.get("summary") is not None:
        result["summary"] = bundle["summary"]
    return result


def _authorship_tally(receipts: list, identities: list | None) -> dict:
    """How many receipts are bound to the actor DID they name.

    A receipt signature proves the bytes match the attached key. Binding proves
    that key belongs to the named actor, checked against the identity snapshot
    the bundle carries. Reported separately from `valid`: an unbound receipt
    means a weaker signing era, not tampering.
    """
    tally = {"bound": 0, "unbound": 0, "unknown_did": 0, "not_a_did": 0}
    by_did = {i["did"]: i for i in (identities or [])}
    for r in receipts:
        actor = r.get("actor_did", "")
        if not actor.startswith("did:cobalt:"):
            tally["not_a_did"] += 1
            continue
        if identities is None:
            tally["unknown_did"] += 1
            continue
        ident = by_did.get(actor)
        if ident is None:
            tally["unknown_did"] += 1
            continue
        a = (ident.get("public_key") or "").strip()
        b = (r.get("public_key") or "").strip()
        tally["bound" if a and a == b else "unbound"] += 1
    return tally


def verify_bundle_file(
    path: str | Path,
    *,
    trusted_signer_key: str | None = None,
    allow_insecure_legacy: bool = False,
) -> dict:
    """Load a bundle JSON file and verify it."""
    bundle = json.loads(Path(path).read_text())
    return verify_bundle(bundle, trusted_signer_key=trusted_signer_key,
                         allow_insecure_legacy=allow_insecure_legacy)
