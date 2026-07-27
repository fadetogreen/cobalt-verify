"""cobalt-verify test suite — runs against a committed fixture bundle.

The fixture is a real safety-case export from the Cobalt substrate: an allow
decision + completed outcome, a denial in an unrecognized zone, a
light-curtain trip (demote), and a human-sign-off earn-back.
"""

import copy
import json
from pathlib import Path

import pytest

from cobalt_verify import verify_bundle, verify_bundle_file
from cobalt_verify.cli import main

FIXTURE = Path(__file__).parent / "fixtures" / "safety-case.json"


@pytest.fixture
def bundle() -> dict:
    return json.loads(FIXTURE.read_text())


def test_fixture_is_valid(bundle):
    result = verify_bundle(bundle)
    assert result["valid"] is True, result["errors"]
    assert result["counts"]["receipts"] > 0
    assert result["counts"]["ledger_rows"] == 2
    assert result["summary"]["decisions"]["deny"] == 1
    assert len(result["summary"]["trips"]) == 1


def test_file_roundtrip():
    assert verify_bundle_file(FIXTURE)["valid"] is True


def test_tampered_receipt_detected(bundle):
    b = copy.deepcopy(bundle)
    b["receipts"][0]["capability"] = "Arm.harmless"
    result = verify_bundle(b)
    assert result["valid"] is False
    assert any("receipt signature" in e for e in result["errors"])
    assert any("Merkle root" in e for e in result["errors"])


def test_removed_receipt_detected(bundle):
    b = copy.deepcopy(bundle)
    b["receipts"].pop()
    assert verify_bundle(b)["valid"] is False


def test_tampered_ledger_detected(bundle):
    b = copy.deepcopy(bundle)
    b["ledger"][0]["new_default_authority"] = "Autonomous"
    result = verify_bundle(b)
    assert result["valid"] is False
    assert any("Sections hash" in e for e in result["errors"])


def test_tampered_summary_detected(bundle):
    b = copy.deepcopy(bundle)
    b["summary"]["denials"] = []
    assert verify_bundle(b)["valid"] is False


def test_tampered_metadata_detected(bundle):
    b = copy.deepcopy(bundle)
    b["metadata"]["receipt_count"] = 999
    result = verify_bundle(b)
    assert result["valid"] is False
    assert any("Bundle signature" in e for e in result["errors"])


def test_unknown_format_version(bundle):
    b = copy.deepcopy(bundle)
    b["format_version"] = 99
    result = verify_bundle(b)
    assert result["valid"] is False
    assert any("format_version" in e for e in result["errors"])


def test_cli_valid_and_invalid(tmp_path, capsys):
    assert main([str(FIXTURE)]) == 0
    out = capsys.readouterr().out
    assert "VALID" in out and "deny=1" in out

    b = json.loads(FIXTURE.read_text())
    b["summary"]["trips"] = []
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(b))
    assert main([str(bad)]) == 1
    err = capsys.readouterr().err
    assert "INVALID" in err

    assert main([str(tmp_path / "missing.json")]) == 1
