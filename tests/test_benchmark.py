from __future__ import annotations

import importlib.util
import hashlib
import json
import re
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("microscope_benchmark", ROOT / "bench" / "run_benchmark.py")
assert SPEC and SPEC.loader
benchmark = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(benchmark)


def test_recorded_scanner_freeze_and_six_labeled_sources_are_valid():
    freeze_path = ROOT / "bench" / "scanner-freeze.sha256"
    freeze_text = freeze_path.read_text(encoding="utf-8-sig")
    expected = re.search(r"^Aggregate SHA-256: ([0-9a-f]{64})$", freeze_text, re.MULTILINE)
    recorded_lines = [
        line for line in freeze_text.splitlines()
        if re.match(r"^[0-9a-f]{64}  scanner[\\/]", line)
    ]
    assert expected is not None
    assert recorded_lines
    assert hashlib.sha256(("\n".join(recorded_lines) + "\n").encode("utf-8")).hexdigest() == expected.group(1)
    results = json.loads((ROOT / "bench" / "results.json").read_text(encoding="utf-8"))
    assert results["scanner_sha256"] == expected.group(1)
    labels = json.loads((ROOT / "bench" / "labels.json").read_text(encoding="utf-8"))
    assert len(labels["cases"]) == 6
    assert len({case["id"] for case in labels["cases"]}) == 6
    assert all((ROOT / "bench" / case["source"]).is_file() for case in labels["cases"])


def test_frozen_benchmark_guard_detects_scanner_changes(tmp_path, monkeypatch):
    root = tmp_path
    scanner_dir = root / "scanner"
    scanner_dir.mkdir()
    (scanner_dir / "__init__.py").write_text("", encoding="utf-8")
    source = scanner_dir / "detectors.py"
    source.write_text("BASELINE = True\n", encoding="utf-8")
    lines = []
    for path in sorted(scanner_dir.rglob("*")):
        if path.is_file() and path.suffix in {".py", ".j2"}:
            relative = path.relative_to(root).as_posix()
            lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {relative}")
    aggregate = hashlib.sha256(("\n".join(lines) + "\n").encode("utf-8")).hexdigest()
    freeze_path = root / "bench" / "scanner-freeze.sha256"
    freeze_path.parent.mkdir()
    freeze_path.write_text(
        "Test freeze\nAggregate SHA-256: " + aggregate + "\n" + "\n".join(lines) + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(benchmark, "ROOT", root)
    monkeypatch.setattr(benchmark, "FREEZE_PATH", freeze_path)

    assert benchmark.assert_frozen() == aggregate
    source.write_text("BASELINE = False\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="changed after the P5 freeze"):
        benchmark.assert_frozen()


def test_benchmark_outcome_marks_false_positive_and_missed_exploit():
    safe = {"id": "safe", "category": "reentrancy", "ground_truth": "safe_lookalike", "source": "contracts/safe.sol"}
    vulnerable = {"id": "bug", "category": "access_control", "ground_truth": "vulnerable", "source": "contracts/bug.sol"}
    run_dir = ROOT / "bench" / "raw_runs" / "sample"

    false_positive = benchmark._evaluate(
        safe,
        [{"id": "finding", "original_result": {"status": "reproduced"}, "oracle": {"exploit_succeeded": True}}],
        {"source_sha256": "abc", "detector_hits": [{"check": "reentrancy-eth"}]},
        run_dir,
    )
    assert false_positive["wrong_case"] is True
    assert false_positive["slither_false_alarm"] is True

    missed = benchmark._evaluate(vulnerable, [], {"source_sha256": "def", "detector_hits": []}, run_dir)
    assert missed["wrong_case"] is True
    assert missed["slither_direct_detection"] is None


def test_slither_alarm_is_listed_only_after_not_reproduced_execution():
    case = {"id": "safe", "category": "reentrancy", "ground_truth": "safe_lookalike", "source": "contracts/safe.sol"}
    record = benchmark._evaluate(
        case,
        [{"id": "RE-1-case", "detector_corroboration": "true", "original_result": {"status": "not_reproduced"}}],
        {"source_sha256": "abc", "detector_hits": [{"check": "reentrancy-eth"}]},
        ROOT / "bench" / "raw_runs" / "sample",
    )
    assert record["slither_alarm_downgraded_to_not_reproduced"] == ["RE-1-case"]
