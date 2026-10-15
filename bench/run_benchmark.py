"""Run the frozen Microscope scanner once against the P5 held-out mini-benchmark."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
BENCH = Path(__file__).resolve().parent
# Running ``python bench/run_benchmark.py`` puts bench/ rather than the
# repository root on sys.path. Add the project root so the frozen scanner
# package imports consistently from both the repo root and other directories.
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

LABELS_PATH = BENCH / "labels.json"
FREEZE_PATH = BENCH / "scanner-freeze.sha256"
RESULTS_PATH = BENCH / "results.csv"
RESULTS_JSON_PATH = BENCH / "results.json"
RUN_MARKER_PATH = BENCH / "run-started.json"
UNSEEN_SOURCE = BENCH / "unseen" / "human_demo.sol"
UNSEEN_RESULT_PATH = BENCH / "unseen_demo_result.json"
RAW_RUNS = BENCH / "raw_runs"
DIRECT_DETECTORS = {
    "reentrancy": {"reentrancy-eth"},
    # Slither has no generic detector for the benchmark's admin-setter AC-1 pattern.
    "access_control": None,
}


def scanner_fingerprint() -> tuple[str, list[str]]:
    files = sorted(
        path for path in (ROOT / "scanner").rglob("*")
        if path.is_file() and path.suffix in {".py", ".j2"} and "__pycache__" not in path.parts
    )
    lines: list[str] = []
    for path in files:
        relative = path.relative_to(ROOT).as_posix()
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {relative}")
    aggregate = hashlib.sha256(("\n".join(lines) + "\n").encode("utf-8")).hexdigest()
    return aggregate, lines


def assert_frozen() -> str:
    text = FREEZE_PATH.read_text(encoding="utf-8-sig")
    expected = re.search(r"^Aggregate SHA-256: ([0-9a-f]{64})$", text, re.MULTILINE)
    if not expected:
        raise RuntimeError("scanner freeze manifest is missing its aggregate SHA-256")
    actual, lines = scanner_fingerprint()
    recorded_lines = [line for line in text.splitlines() if re.match(r"^[0-9a-f]{64}  scanner[\\/]", line)]
    parsed = [re.match(r"^([0-9a-f]{64})  (scanner[\\/].+)$", line) for line in recorded_lines]
    if any(item is None for item in parsed):
        raise RuntimeError("scanner freeze manifest contains a malformed file entry")
    recorded_map = {item.group(2).replace("\\", "/"): item.group(1) for item in parsed if item}
    current_map = {line.split("  ", 1)[1]: line.split("  ", 1)[0] for line in lines}
    for relative, recorded_hash in recorded_map.items():
        source_path = ROOT.joinpath(*re.split(r"[\\/]", relative))
        if not source_path.is_file() or hashlib.sha256(source_path.read_bytes()).hexdigest() != recorded_hash:
            raise RuntimeError(f"scanner file changed after the P5 freeze: {relative}")
    aggregate = hashlib.sha256(("\n".join(recorded_lines) + "\n").encode("utf-8")).hexdigest()
    if expected.group(1) != aggregate or recorded_map != current_map:
        raise RuntimeError("scanner/ changed after the P5 freeze; refusing to run benchmark")
    return expected.group(1)


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _outcome(item: dict[str, Any], key: str) -> str:
    result = item.get(key)
    return str(result.get("status") or "unavailable") if isinstance(result, dict) else "unavailable"


def _evaluate(case: dict[str, Any], findings: list[Any], facts: dict[str, Any], run_dir: Path) -> dict[str, Any]:
    detectors = sorted({
        str(hit.get("check")) for hit in facts.get("detector_hits", [])
        if isinstance(hit, dict) and hit.get("check")
    })
    direct_checks = DIRECT_DETECTORS[case["category"]]
    direct_hit = any(detector in direct_checks for detector in detectors) if direct_checks is not None else None
    safe = case["ground_truth"] == "safe_lookalike"
    statuses = sorted({str(item.get("status") or "inconclusive") for item in findings if isinstance(item, dict)})
    original = sorted({_outcome(item, "original_result") for item in findings if isinstance(item, dict)})
    patched = sorted({_outcome(item, "patched_result") for item in findings if isinstance(item, dict)})
    regression = sorted({_outcome(item, "regression_result") for item in findings if isinstance(item, dict)})
    confirmed = any(
        isinstance(item, dict)
        and _outcome(item, "original_result") == "reproduced"
        and isinstance(item.get("oracle"), dict)
        and item["oracle"].get("exploit_succeeded") is True
        for item in findings
    )
    false_positive_findings = [
        str(item.get("id") or item.get("function_id") or "finding")
        for item in findings
        if safe and isinstance(item, dict) and _outcome(item, "original_result") == "reproduced"
    ]
    slither_downgrades = [
        str(item.get("id") or item.get("function_id") or "finding")
        for item in findings
        if isinstance(item, dict)
        and item.get("detector_corroboration") == "true"
        and _outcome(item, "original_result") == "not_reproduced"
    ]
    return {
        "id": case["id"],
        "category": case["category"],
        "ground_truth": case["ground_truth"],
        "source": case["source"],
        "source_sha256": str(facts.get("source_sha256") or ""),
        "slither_detectors": detectors,
        "slither_direct_detection": direct_hit,
        "slither_direct_detection_correct": (direct_hit is True if not safe else direct_hit is False) if direct_hit is not None else None,
        "slither_false_alarm": bool(safe and direct_hit is True) if direct_hit is not None else None,
        "microscope_finding_ids": [str(item.get("id")) for item in findings if isinstance(item, dict)],
        "microscope_final_statuses": statuses or ["no_finding_recorded"],
        "original_attack_outcomes": original or ["not_run_no_finding"],
        "exploit_confirmed": confirmed,
        "patched_attack_outcomes": patched or ["not_run"],
        "regression_outcomes": regression or ["not_run"],
        "microscope_false_positive_findings": false_positive_findings,
        "slither_alarm_downgraded_to_not_reproduced": slither_downgrades,
        "truth_concordant": (confirmed if not safe else not confirmed),
        "wrong_case": not (confirmed if not safe else not confirmed),
        "run_error": None,
        "run_dir": run_dir.relative_to(ROOT).as_posix(),
    }


def _failed_case(case: dict[str, Any], run_dir: Path | None, error: Exception) -> dict[str, Any]:
    return {
        "id": case["id"], "category": case["category"], "ground_truth": case["ground_truth"],
        "source": case["source"], "source_sha256": "", "slither_detectors": [],
        "slither_direct_detection": None, "slither_direct_detection_correct": None,
        "slither_false_alarm": None, "microscope_finding_ids": [],
        "microscope_final_statuses": ["unavailable_run_failed"],
        "original_attack_outcomes": ["unavailable_run_failed"], "exploit_confirmed": False,
        "patched_attack_outcomes": ["unavailable_run_failed"], "regression_outcomes": ["unavailable_run_failed"],
        "microscope_false_positive_findings": [], "slither_alarm_downgraded_to_not_reproduced": [],
        "truth_concordant": False,
        "wrong_case": True,
        "run_error": f"{type(error).__name__}: {str(error)[:400]}",
        "run_dir": run_dir.relative_to(ROOT).as_posix() if run_dir else "",
    }


def run() -> list[dict[str, Any]]:
    if RESULTS_PATH.exists() or RESULTS_JSON_PATH.exists() or RUN_MARKER_PATH.exists() or UNSEEN_RESULT_PATH.exists():
        raise RuntimeError("P5 benchmark was already started; this frozen benchmark is single-run and will not be repeated")
    freeze = assert_frozen()
    labels = _load_json(LABELS_PATH)
    cases = labels.get("cases") if isinstance(labels, dict) else None
    if not isinstance(cases, list) or len(cases) != 6:
        raise RuntimeError("P5 requires the planned six labeled cases; labels.json is malformed")
    if not UNSEEN_SOURCE.is_file() or UNSEEN_SOURCE.suffix.lower() != ".sol":
        raise RuntimeError("attach the human-supplied unseen contract at bench/unseen/human_demo.sol before the one-shot P5 run")
    if UNSEEN_SOURCE.stat().st_size > 200_000:
        raise RuntimeError("the unseen demo contract exceeds the 200 KB input limit")

    from scanner.run import run_file

    RUN_MARKER_PATH.write_text(json.dumps({
        "started_at": datetime.now(timezone.utc).isoformat(),
        "scanner_sha256": freeze,
        "case_count": len(cases),
    }, indent=2) + "\n", encoding="utf-8")
    RAW_RUNS.mkdir(parents=True, exist_ok=True)
    results: list[dict[str, Any]] = []
    for case in cases:
        source = (BENCH / case["source"]).resolve()
        if source.parent != (BENCH / "contracts").resolve() or not source.is_file():
            results.append(_failed_case(case, None, RuntimeError("invalid or missing benchmark source")))
            continue
        run_dir: Path | None = None
        try:
            findings, run_dir = run_file(source, fixture=False, runs_dir=RAW_RUNS)
            facts_path = run_dir / "facts.json"
            findings_path = run_dir / "findings.json"
            if not facts_path.is_file() or not findings_path.is_file():
                raise RuntimeError("run artifacts are incomplete")
            facts = _load_json(facts_path)
            persisted_findings = _load_json(findings_path)
            if findings != persisted_findings:
                raise RuntimeError("persisted findings differ from returned output")
            result = _evaluate(case, findings, facts, run_dir)
        except Exception as exc:
            result = _failed_case(case, run_dir, exc)
        results.append(result)
        print(f"{case['id']}: {result['microscope_final_statuses']} · exploit_confirmed={result['exploit_confirmed']}")

    unseen_record: dict[str, Any] = {
        "schema": "microscope-unseen-demo-result-v1",
        "fixture": False,
        "source": "unseen/human_demo.sol",
        "source_sha256": hashlib.sha256(UNSEEN_SOURCE.read_bytes()).hexdigest(),
    }
    unseen_run_dir: Path | None = None
    try:
        unseen_findings, unseen_run_dir = run_file(UNSEEN_SOURCE, fixture=False, runs_dir=RAW_RUNS)
        unseen_record["run_dir"] = unseen_run_dir.relative_to(ROOT).as_posix()
        unseen_record["findings"] = unseen_findings
        unseen_record["result"] = _load_json(unseen_run_dir / "findings.json")
    except Exception as exc:
        unseen_record["run_dir"] = unseen_run_dir.relative_to(ROOT).as_posix() if unseen_run_dir else None
        unseen_record["error"] = f"{type(exc).__name__}: {str(exc)[:400]}"
    UNSEEN_RESULT_PATH.write_text(json.dumps(unseen_record, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Unseen demo: fixture=false · result saved to {UNSEEN_RESULT_PATH.relative_to(ROOT)}")

    fields = [
        "id", "category", "ground_truth", "source", "source_sha256", "slither_detectors",
        "slither_direct_detection", "slither_direct_detection_correct", "slither_false_alarm",
        "microscope_finding_ids", "microscope_final_statuses", "original_attack_outcomes",
        "exploit_confirmed", "patched_attack_outcomes", "regression_outcomes",
        "microscope_false_positive_findings", "slither_alarm_downgraded_to_not_reproduced", "run_dir",
        "truth_concordant", "wrong_case", "run_error",
    ]
    with RESULTS_PATH.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for result in results:
            writer.writerow({key: json.dumps(result[key], ensure_ascii=False) if isinstance(result[key], (list, dict)) else result[key] for key in fields})
    wrong_cases = [item["id"] for item in results if not item["truth_concordant"]]
    RESULTS_JSON_PATH.write_text(json.dumps({
        "schema": "microscope-mini-benchmark-results-v1",
        "scanner_sha256": freeze,
        "labels": "labels.json",
        "wrong_cases": wrong_cases,
        "results": results,
    }, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Wrote {RESULTS_PATH.relative_to(ROOT)} and {RESULTS_JSON_PATH.relative_to(ROOT)}")
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    try:
        run()
    except Exception as exc:
        print(f"P5 benchmark failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
