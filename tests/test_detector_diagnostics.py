"""Unit edge cases for Slither process output; the separate integration test uses real tools."""

from __future__ import annotations

import json
import subprocess

from scanner import detectors


def test_success_false_json_is_not_accepted_as_detector_success(tmp_path, monkeypatch):
    source = tmp_path / "input.sol"
    source.write_text("pragma solidity ^0.8.24;", encoding="utf-8")
    monkeypatch.setattr(detectors.shutil, "which", lambda _name: "slither")

    def process(*_args, **_kwargs):
        (tmp_path / "slither.json").write_text(
            json.dumps({"success": False, "error": "Invalid compilation: parser error"}),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess([], 0, "", "")

    monkeypatch.setattr(detectors.subprocess, "run", process)
    diagnostics = []

    hits, errors = detectors.collect_detector_hits(source, tmp_path, diagnostics=diagnostics)

    assert hits == []
    assert errors and "compilation_error" in errors[0]
    assert diagnostics[0]["classification"] == "compilation_error"
    assert diagnostics[0]["returncode"] == 0


def test_stale_json_is_removed_and_raw_failure_output_is_preserved(tmp_path, monkeypatch):
    source = tmp_path / "input.sol"
    source.write_text("pragma solidity ^0.8.24;", encoding="utf-8")
    stale = tmp_path / "slither.json"
    stale.write_text(json.dumps({"success": True, "results": {"detectors": []}}), encoding="utf-8")
    monkeypatch.setattr(detectors.shutil, "which", lambda _name: "slither")

    def failed_process(*_args, **_kwargs):
        assert not stale.exists(), "stale analyzer JSON must not survive into a new invocation"
        return subprocess.CompletedProcess([], 2, "partial stdout", "compiler diagnostic")

    monkeypatch.setattr(detectors.subprocess, "run", failed_process)
    diagnostics = []

    hits, errors = detectors.collect_detector_hits(source, tmp_path, diagnostics=diagnostics)

    assert hits == []
    assert errors and "compiler diagnostic" in errors[0]
    assert diagnostics[0]["returncode"] == 2
    assert diagnostics[0]["stdout"] == "partial stdout"
    assert diagnostics[0]["stderr"] == "compiler diagnostic"
