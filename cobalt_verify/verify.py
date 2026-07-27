"""Offline verifier for Cobalt audit bundles.

Standalone by design: no dependency on the Cobalt substrate, no network, no
database. A third party receives a single JSON bundle file and proves its
integrity using only the public keys embedded in the bundle itself.

Supported formats:
    format_version 1 — merkle_bundle: receipts + usage records, receipt-level
        ed25519 signatures, a merkle root over receipt canonical hashes, and
        a bundle-level signature over the canonical metadata.
    format_version 2 — safety-case: everything in v1, plus the authority
        ledger (trips / demotions / earn-backs), an authority snapshot, and a
        computed summary — covered by a sections_hash that is part of the
        signed metadata.

Checks performed:
    1. Every receipt's own signature against its embedded public_key
    2. Recomputed merkle root over receipts == metadata.merkle_root
    3. bundle_signature against signing_public_key
    4. (v2) recomputed sections_hash over ledger + snapshot + summary

Any tampered byte in any covered section makes the bundle INVALID, with the
failing check named.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.serialization import load_pem_public_key

__all__ = ["verify_bundle", "verify_bundle_file"]


# ---------------------------------------------------------------------------
# Canonical forms — must match the Cobalt substrate byte-for-byte.
# ---------------------------------------------------------------------------

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


def _compute_merkle_root(hashes: list[str]) -> str:
    if not hashes:
        return hashlib.sha256(b"empty").hexdigest()
    if len(hashes) == 1:
        return hashes[0]
    nodes = [bytes.fromhex(h) for h in hashes]
    while len(nodes) > 1:
        next_level = []
        for i in range(0, len(nodes), 2):
            left = nodes[i]
            right = nodes[i + 1] if i + 1 < len(nodes) else nodes[i]
            next_level.append(hashlib.sha256(left + right).digest())
        nodes = next_level
    return nodes[0].hex()


def _canonical_bundle_metadata_v1(meta: dict) -> bytes:
    payload = {
        "tenant_did": meta["tenant_did"],
        "generated_at": meta["generated_at"],
        "period_start": meta["period_start"],
        "period_end": meta["period_end"],
        "receipt_count": meta["receipt_count"],
        "usage_count": meta["usage_count"],
        "merkle_root": meta["merkle_root"],
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _canonical_bundle_metadata_v2(meta: dict) -> bytes:
    payload = {
        "tenant_did": meta["tenant_did"],
        "generated_at": meta["generated_at"],
        "period_start": meta["period_start"],
        "period_end": meta["period_end"],
        "receipt_count": meta["receipt_count"],
        "usage_count": meta["usage_count"],
        "ledger_count": meta["ledger_count"],
        "merkle_root": meta["merkle_root"],
        "sections_hash": meta["sections_hash"],
        "profile": meta["profile"],
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _canonical_sections(ledger: list, snapshot: dict, summary: dict) -> bytes:
    payload = {
        "ledger": ledger,
        "authority_snapshot": snapshot,
        "summary": summary,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()


# ---------------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------------

def verify_bundle(bundle: dict) -> dict:
    """Verify a Cobalt bundle dict.

    Returns {"valid": bool, "errors": [str], "counts": {...}} — plus
    "summary" (the bundle's own summary section) for safety-case bundles.
    """
    errors: list[str] = []

    version = bundle.get("format_version")
    if version not in (1, 2):
        errors.append(f"Unknown format_version: {version}")
        return {"valid": False, "errors": errors, "counts": {}}

    receipts = bundle.get("receipts", [])
    metadata = bundle.get("metadata", {})

    # 1. Per-receipt signatures
    receipt_failures = 0
    for r in receipts:
        try:
            pub = load_pem_public_key(r["public_key"].encode())
            sig = bytes.fromhex(r["signature"])
            pub.verify(sig, _canonical_receipt_payload(r))
        except Exception:
            receipt_failures += 1
    if receipt_failures:
        errors.append(f"{receipt_failures} receipt signature(s) failed verification")

    # 2. Merkle root
    expected_root = _compute_merkle_root([
        hashlib.sha256(_canonical_receipt_payload(r)).hexdigest() for r in receipts
    ])
    if expected_root != metadata.get("merkle_root"):
        bundle_root = metadata.get("merkle_root")
        errors.append(
            f"Merkle root mismatch: bundle={bundle_root[:16] if bundle_root else None}... "
            f"recomputed={expected_root[:16]}..."
        )

    # 3. Bundle signature
    try:
        signing_pub = load_pem_public_key(bundle["signing_public_key"].encode())
        bundle_sig = bytes.fromhex(bundle["bundle_signature"])
        if version == 2:
            signing_pub.verify(bundle_sig, _canonical_bundle_metadata_v2(metadata))
        else:
            signing_pub.verify(bundle_sig, _canonical_bundle_metadata_v1(metadata))
    except KeyError as e:
        errors.append(f"Missing bundle field: {e}")
    except Exception as e:
        errors.append(f"Bundle signature failed: {type(e).__name__}")

    counts = {
        "receipts": len(receipts),
        "usage_records": len(bundle.get("usage_records", [])),
    }
    result: dict = {"valid": None, "errors": errors, "counts": counts}

    # 4. (v2) sections hash
    if version == 2:
        expected_sections = hashlib.sha256(_canonical_sections(
            bundle.get("ledger", []),
            bundle.get("authority_snapshot", {}),
            bundle.get("summary", {}),
        )).hexdigest()
        if expected_sections != metadata.get("sections_hash"):
            errors.append(
                "Sections hash mismatch: ledger/snapshot/summary were modified"
            )
        counts["ledger_rows"] = len(bundle.get("ledger", []))
        result["summary"] = bundle.get("summary")

    result["valid"] = len(errors) == 0
    return result


def verify_bundle_file(path: str | Path) -> dict:
    """Load a bundle JSON file and verify it."""
    bundle = json.loads(Path(path).read_text())
    return verify_bundle(bundle)
