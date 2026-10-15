"""Real-tool integration checks; these intentionally do not mock Slither or solc."""

from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
from pathlib import Path

import pytest

from conftest import PROJECT
from scanner.detectors import collect_detector_hits


SLITHER_AVAILABLE = shutil.which("slither") is not None and shutil.which("solc") is not None
requires_slither = pytest.mark.skipif(
    not SLITHER_AVAILABLE,
    reason="real Slither CLI and solc are required; run this integration suite in the configured WSL environment",
)


@requires_slither
def test_broken_vault_is_a_controlled_compile_error_in_the_app_path(tmp_path, monkeypatch):
    import app

    source = PROJECT / "tests" / "fixtures" / "BrokenVault.sol"
    original_bytes = source.read_bytes()
    original_hash = hashlib.sha256(original_bytes).hexdigest()
    assert b"uint256 public balance\n" in original_bytes
    assert b"uint256 public balance;" not in original_bytes

    temp_root = Path(tempfile.gettempdir())
    before_temp_dirs = {path.resolve() for path in temp_root.glob("microscope-*") if path.is_dir()}
    monkeypatch.setattr(app, "RUNS_DIR", tmp_path / "runs")

    run_id, ui_error = app._run_scan(source, fixture=False)

    assert run_id is not None
    assert ui_error is not None
    assert "compilation" in ui_error.lower()
    run_dir = tmp_path / "runs" / run_id
    facts = json.loads((run_dir / "facts.json").read_text(encoding="utf-8"))
    findings = json.loads((run_dir / "findings.json").read_text(encoding="utf-8"))
    diagnostics = facts["analysis_diagnostics"]
    compile_errors = [item for item in diagnostics if item.get("classification") == "compilation_error"]

    assert compile_errors, diagnostics
    assert any("expected" in item.get("message", "").lower() for item in compile_errors)
    assert facts["contract_notes"][0]["code"] == "analysis_error"
    assert "compilation failed" in facts["contract_notes"][0]["message"].lower()
    assert len(findings) == 1
    finding = findings[0]
    assert finding["category"] == "analysis"
    assert finding["status"] == "inconclusive"
    assert finding["src"] is None
    assert finding["original_result"] == {
        "status": "inconclusive",
        "reason": "static analysis was inconclusive; no original attack was run",
        "steps": [],
    }
    assert finding.get("oracle") is None
    assert finding["patched_result"]["status"] is None
    assert finding["regression_result"]["status"] is None
    assert not (run_dir / "generated").exists()
    assert not (run_dir / "forge_original.json").exists()
    assert source.read_bytes() == original_bytes
    assert hashlib.sha256(source.read_bytes()).hexdigest() == original_hash
    assert not ({path.resolve() for path in temp_root.glob("microscope-*") if path.is_dir()} - before_temp_dirs)

    bundle = json.loads(app._report_bundle(run_dir))
    assert bundle["artifacts"]["facts.json"]["analysis_diagnostics"] == diagnostics

    # A failed upload must leave the app path usable for a following valid source.
    valid_run_id, valid_error = app._run_scan(
        PROJECT / "src" / "fixed" / "SafeVault.sol", fixture=True,
    )
    assert valid_run_id is not None
    assert valid_error is None


@requires_slither
@pytest.mark.parametrize(
    ("relative_source", "expected_checks"),
    [
        ("src/vulnerable/VulnerableVault.sol", {"reentrancy-eth", "low-level-calls"}),
        ("src/fixed/SafeVault.sol", {"low-level-calls"}),
        ("src/vulnerable/VulnerableTreasury.sol", {"missing-zero-check", "low-level-calls"}),
        ("src/fixed/SafeTreasury.sol", {"events-access", "missing-zero-check", "low-level-calls"}),
    ],
)
def test_reference_contracts_still_run_through_real_slither(tmp_path, relative_source, expected_checks):
    source = PROJECT / relative_source
    assert source.is_file(), source
    hits, errors = collect_detector_hits(source.resolve(), tmp_path)
    assert errors == []
    observed_checks = {hit["check"] for hit in hits}
    assert observed_checks == expected_checks
    assert source.is_file()

