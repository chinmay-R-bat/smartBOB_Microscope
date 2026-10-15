from __future__ import annotations

import json
import tempfile
from pathlib import Path
from types import SimpleNamespace

from scanner import run as run_module
from scanner.runner import ForgeExecution
from scanner.schema import SourceRef, Status, Suspect


def test_run_file_emits_truthful_start_and_completion_events(tmp_path, monkeypatch):
    source = tmp_path / "Example.sol"
    source.write_text("pragma solidity ^0.8.24; contract Example {}\n", encoding="utf-8")
    run_dir = tmp_path / "runs" / "sample-run"
    run_dir.mkdir(parents=True)
    facts = SimpleNamespace(
        functions=[], detector_hits=[], mode="api", source_sha256="abc123",
        tool_versions={"slither": "test"},
    )
    monkeypatch.setattr(run_module, "analyze_file", lambda *args, **kwargs: (facts, run_dir))
    monkeypatch.setattr(run_module, "build_hypotheses", lambda _facts: [])
    events: list[dict[str, str]] = []

    findings, result_dir = run_module.run_file(
        source, runs_dir=tmp_path / "runs", progress_callback=events.append,
    )

    assert findings == []
    assert result_dir == run_dir
    assert [(event["stage"], event["state"]) for event in events] == [
        ("static_analysis", "running"),
        ("static_analysis", "complete"),
        ("hypotheses", "complete"),
        ("complete", "complete"),
    ]
    assert "0 candidate(s)" in events[2]["message"]


def test_progress_callback_failure_does_not_change_scan_result(tmp_path, monkeypatch):
    source = tmp_path / "Example.sol"
    source.write_text("pragma solidity ^0.8.24; contract Example {}\n", encoding="utf-8")
    run_dir = tmp_path / "runs" / "sample-run"
    run_dir.mkdir(parents=True)
    facts = SimpleNamespace(
        functions=[], detector_hits=[], mode="api", source_sha256="abc123",
        tool_versions={"slither": "test"},
    )
    monkeypatch.setattr(run_module, "analyze_file", lambda *args, **kwargs: (facts, run_dir))
    monkeypatch.setattr(run_module, "build_hypotheses", lambda _facts: [])

    findings, result_dir = run_module.run_file(
        source, runs_dir=tmp_path / "runs",
        progress_callback=lambda _event: (_ for _ in ()).throw(RuntimeError("UI disconnected")),
    )

    assert findings == []
    assert result_dir == run_dir


def test_supported_candidate_reports_live_original_attack_start_and_result(tmp_path, monkeypatch):
    source = tmp_path / "Example.sol"
    source.write_text("pragma solidity ^0.8.24; contract Example {}\n", encoding="utf-8")
    run_dir = tmp_path / "runs" / "sample-run"
    run_dir.mkdir(parents=True)
    facts = SimpleNamespace(
        functions=[], detector_hits=[], mode="api", source_sha256="abc123",
        tool_versions={"slither": "test"},
    )
    suspect = Suspect(
        id="RE-1-Example.withdraw", category="reentrancy", status=Status.CANDIDATE,
        function_id="Example.withdraw", src=SourceRef("Example.sol", 1, 1), rule="RE-1",
    )
    template = SimpleNamespace(kind="reentrancy", source="contract AttackTest {}", assumptions=[])
    forge_json = json.dumps({"suite": {"test_results": {"test_microscope_attack": {
        "status": "Success",
        "decoded_logs": ['MICROSCOPE_RESULT {"class":"reentrancy","exploit_succeeded":false,"steps":[]}'],
    }}}})
    monkeypatch.setattr(run_module, "analyze_file", lambda *args, **kwargs: (facts, run_dir))
    monkeypatch.setattr(run_module, "build_hypotheses", lambda _facts: [suspect])
    monkeypatch.setattr(run_module, "render_attack", lambda *_args: (template, None))
    monkeypatch.setattr(run_module, "_write_foundry_project", lambda *_args: None)
    monkeypatch.setattr(run_module, "run_forge", lambda *_args, **_kwargs: ForgeExecution(forge_json, "", 0))
    original_temporary_directory = tempfile.TemporaryDirectory
    monkeypatch.setattr(
        tempfile, "TemporaryDirectory",
        lambda prefix="": original_temporary_directory(prefix=prefix, dir=tmp_path),
    )
    events: list[dict[str, str]] = []

    findings, _ = run_module.run_file(
        source, runs_dir=tmp_path / "runs", progress_callback=events.append,
    )

    attack_events = [event for event in events if event["stage"] == "original_attack"]
    assert [event["state"] for event in attack_events] == ["running", "complete"]
    assert "running now" in attack_events[0]["message"]
    assert "not_reproduced" in attack_events[1]["message"]
    assert findings[0]["original_result"]["status"] == "not_reproduced"
