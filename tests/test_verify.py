"""cobalt-verify test suite — runs against a committed fixture bundle.

The fixture is a real safety-case export (format v3) from the Cobalt substrate:
an allow decision + completed outcome, a denial in an unrecognized zone, a
light-curtain trip (demote), and a human-sign-off earn-back. `signer.pub.pem`
is the signer's public key — what an auditor would pin out of band.

The forgery tests below correspond to attacks that WORKED against v0.1.0.
"""

import copy
import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from cobalt_verify import verify_bundle, verify_bundle_file
from cobalt_verify.cli import main
from cobalt_verify.verify import (
    _canon,
    _canonical_bundle_metadata,
    _canonical_receipt_payload,
    _canonical_sections,
    _merkle_root,
)

FIXTURES = Path(__file__).parent / "fixtures"
FIXTURE = FIXTURES / "safety-case.json"
SIGNER_KEY = FIXTURES / "signer.pub.pem"


@pytest.fixture
def bundle() -> dict:
    return json.loads(FIXTURE.read_text())


@pytest.fixture
def signer() -> str:
    return SIGNER_KEY.read_text()


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

def test_fixture_is_valid_and_trusted(bundle, signer):
    result = verify_bundle(bundle, trusted_signer_key=signer)
    assert result["valid"] is True, result["errors"]
    assert result["signer_trusted"] is True
    assert result["counts"]["receipts"] > 0
    assert result["counts"]["ledger_rows"] == 2
    assert result["summary"]["decisions"]["deny"] == 1
    assert len(result["summary"]["trips"]) == 1


def test_valid_but_untrusted_without_a_pinned_key(bundle):
    result = verify_bundle(bundle)
    assert result["valid"] is True
    assert result["signer_trusted"] is False


def test_file_roundtrip(signer):
    assert verify_bundle_file(FIXTURE, trusted_signer_key=signer)["signer_trusted"]


# ---------------------------------------------------------------------------
# Forgery — the v0.1.0 critical
# ---------------------------------------------------------------------------

def _forge(claim_did="did:cobalt:site-bk/safety-plc#key-1") -> dict:
    """A wholly fabricated but internally consistent bundle, attacker-keyed."""
    priv = Ed25519PrivateKey.generate()
    pubpem = priv.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode()
    r = {
        "receipt_id": "9999999999999-forged", "parent_receipt_id": None,
        "actor_did": claim_did, "actor_model": None, "actor_model_provider": None,
        "capability": "Arm.move", "authority_level": "Autonomous",
        "inputs_hash": "00" * 32, "outputs_hash": "11" * 32,
        "counterparties": [], "started_at": "2020-01-01T00:00:00Z",
        "completed_at": "2020-01-01T00:00:00Z",
        "metadata": {"kernel": {"type": "decision", "verdict": "allow"}},
    }
    r["signature"] = priv.sign(_canonical_receipt_payload(r)).hex()
    r["public_key"] = pubpem
    summary = {"decisions": {"allow": 1, "confirm": 0, "deny": 0}, "denials": [],
               "confirmations": 0, "trips": [], "movements": [],
               "outcomes": {"completed": 0, "aborted": 0, "tripped": 0}}
    meta = {
        "tenant_did": claim_did, "generated_at": "2020-01-01T00:00:00Z",
        "period_start": "", "period_end": "",
        "receipt_count": 1, "usage_count": 0, "ledger_count": 0,
        "merkle_root": _merkle_root([hashlib.sha256(_canonical_receipt_payload(r)).hexdigest()]),
        "receipts_hash": hashlib.sha256(_canon([r])).hexdigest(),
        "usage_hash": hashlib.sha256(_canon([])).hexdigest(),
        "sections_hash": hashlib.sha256(_canonical_sections([], {}, summary)).hexdigest(),
        "signing_did": claim_did, "profile": "safety-case",
    }
    return {
        "format_version": 3, "profile": "safety-case", "metadata": meta,
        "receipts": [r], "usage_records": [], "ledger": [],
        "authority_snapshot": {}, "summary": summary,
        "signing_did": claim_did, "signing_public_key": pubpem,
        "bundle_signature": priv.sign(_canonical_bundle_metadata(meta)).hex(),
    }


def test_forged_bundle_is_never_trusted():
    result = verify_bundle(_forge())
    assert result["valid"] is True          # consistent by construction...
    assert result["signer_trusted"] is False  # ...but never trusted


def test_forged_bundle_fails_against_the_real_signer(signer):
    result = verify_bundle(_forge(), trusted_signer_key=signer)
    assert result["valid"] is False
    assert result["signer_trusted"] is False
    assert any("Signer mismatch" in e for e in result["errors"])


# ---------------------------------------------------------------------------
# Merkle / injection
# ---------------------------------------------------------------------------

def test_odd_leaf_duplication_changes_root():
    leaves = [hashlib.sha256(bytes([i])).hexdigest() for i in range(3)]
    assert _merkle_root(leaves) != _merkle_root(leaves + [leaves[-1]])


def test_injected_duplicate_receipt_rejected(bundle, signer):
    b = copy.deepcopy(bundle)
    b["receipts"].append(b["receipts"][-1])
    result = verify_bundle(b, trusted_signer_key=signer)
    assert result["valid"] is False
    assert any("duplicate receipt_id" in e for e in result["errors"])


def test_removed_receipt_detected(bundle, signer):
    b = copy.deepcopy(bundle)
    b["receipts"].pop()
    assert verify_bundle(b, trusted_signer_key=signer)["valid"] is False


def test_tampered_receipt_detected(bundle, signer):
    b = copy.deepcopy(bundle)
    b["receipts"][0]["capability"] = "Arm.harmless"
    result = verify_bundle(b, trusted_signer_key=signer)
    assert result["valid"] is False
    assert any("receipt signature" in e for e in result["errors"])


# ---------------------------------------------------------------------------
# Section coverage
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("mutate,expect", [
    (lambda b: b.update({"usage_records": [{"model": "forged"}]}), "Usage"),
    (lambda b: b.update({"signing_did": "did:cobalt:x/y#key-1"}), "signing_did"),
    (lambda b: b.update({"profile": "standard"}), "profile"),
    (lambda b: b["ledger"].__setitem__(0, {**b["ledger"][0], "kind": "earn_back"}), "Sections"),
    (lambda b: b["summary"].update({"denials": []}), "Sections"),
    (lambda b: b["metadata"].update({"receipt_count": 999}), "Bundle signature"),
])
def test_every_section_is_covered(bundle, signer, mutate, expect):
    b = copy.deepcopy(bundle)
    mutate(b)
    result = verify_bundle(b, trusted_signer_key=signer)
    assert result["valid"] is False
    assert any(expect in e for e in result["errors"]), result["errors"]


# ---------------------------------------------------------------------------
# Formats
# ---------------------------------------------------------------------------

def test_legacy_formats_rejected(bundle):
    for version in (1, 2):
        b = {**copy.deepcopy(bundle), "format_version": version}
        result = verify_bundle(b)
        assert result["valid"] is False
        assert any("REJECTED" in e for e in result["errors"])


def test_legacy_readable_only_with_explicit_opt_in(bundle):
    b = {**copy.deepcopy(bundle), "format_version": 2}
    result = verify_bundle(b, allow_insecure_legacy=True)
    assert not any("REJECTED" in e for e in result["errors"])


def test_unknown_format_version(bundle):
    b = {**copy.deepcopy(bundle), "format_version": 99}
    result = verify_bundle(b)
    assert result["valid"] is False
    assert any("format_version" in e for e in result["errors"])


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def test_cli_verified_with_signer_key(capsys):
    assert main([str(FIXTURE), "--signer-key", str(SIGNER_KEY)]) == 0
    out = capsys.readouterr().out
    assert "VERIFIED" in out and "deny=1" in out
    assert "WARNING" not in out


def test_cli_warns_without_signer_key(capsys):
    assert main([str(FIXTURE)]) == 0
    out = capsys.readouterr().out
    assert "SELF-CONSISTENT" in out
    assert "signer NOT verified" in out


def test_cli_rejects_forgery_against_pinned_key(tmp_path, capsys):
    forged = tmp_path / "forged.json"
    forged.write_text(json.dumps(_forge()))
    assert main([str(forged), "--signer-key", str(SIGNER_KEY)]) == 1
    assert "INVALID" in capsys.readouterr().err


def test_cli_missing_file(tmp_path, capsys):
    assert main([str(tmp_path / "nope.json")]) == 1
    assert "no such file" in capsys.readouterr().err
