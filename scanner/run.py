"""Run P1 static hypotheses through one supported original Foundry attack."""

from __future__ import annotations

import argparse
import copy
import json
import re
import shutil
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .facts import analyze_file
from .hypotheses import build_hypotheses
from .patcher import build_patch, render_regression_test
from .runner import parse_forge_json, run_forge, run_forge_build, write_execution
from .schema import Status, Tri, to_jsonable
from .template_engine import render_attack

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ProgressCallback = Callable[[dict[str, str]], None]


def _progress(callback: ProgressCallback | None, stage: str, state: str, message: str) -> None:
    """Publish real pipeline transitions; display code must not affect scan results."""
    if callback is None:
        return
    try:
        callback({"stage": stage, "state": state, "message": message})
    except Exception:
        pass


def _write_foundry_project(root: Path, source: Path, test_source: str) -> None:
    (root / "src").mkdir(parents=True, exist_ok=True)
    (root / "test").mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, root / "src" / "input.sol")
    (root / "test" / "Attack.t.sol").write_text(test_source, encoding="utf-8")
    libs = PROJECT_ROOT / "lib"
    lib_value = json.dumps(str(libs.resolve())) if libs.is_dir() else "[]"
    config = (
        "[profile.default]\n"
        'src = "src"\n'
        'test = "test"\n'
        'out = "out"\n'
        'cache_path = "cache"\n'
        f"libs = {lib_value if lib_value == '[]' else '[' + lib_value + ']'}\n"
        'solc_version = "0.8.24"\n'
    )
    (root / "foundry.toml").write_text(config, encoding="utf-8")


def _slug(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._-") or "finding"


def _finding_record(suspect: Any, *, template_kind: str | None, outcome: str,
                    reason: str | None = None, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    record = to_jsonable(suspect)
    record["template_kind"] = template_kind
    record["original_result"] = {"status": outcome, "reason": reason, "steps": (payload or {}).get("steps", [])}
    if payload is not None:
        record["oracle"] = payload
    return record


def _p3_record(record: dict[str, Any], *, patch_kind: str | None, patch_reason: str | None,
               patched_status: str | None = None, patched_reason: str | None = None,
               regression_status: str | None = None, regression_reason: str | None = None,
               lock_self_check: bool | None = None) -> dict[str, Any]:
    record.update({
        "patch_kind": patch_kind,
        "patch_reason": patch_reason,
        "patched_result": {"status": patched_status, "reason": patched_reason},
        "regression_result": {"status": regression_status, "reason": regression_reason},
    })
    if lock_self_check is not None:
        record["patcher_lock_self_check"] = lock_self_check
    return record


def _patch_and_verify(source_text: str, source_fixture: bool, facts: Any, suspect: Any,
                      template: Any, run_dir: Path, finding_dir: Path,
                      timeout: int, progress_callback: ProgressCallback | None = None) -> tuple[str, str | None, dict[str, Any]]:
    """Patch one reproduced finding, compile it, replay the attack, and test regression."""
    target = suspect.function_id
    _progress(progress_callback, "patch", "running", f"Building a supported patch for {target}.")
    patch = build_patch(source_text, facts, suspect)
    if patch.source is None:
        _progress(progress_callback, "patch", "skipped", f"Patch not applied: {patch.reason or 'unsupported source shape'}.")
        return Status.INCONCLUSIVE.value, patch.reason, {
            "patch_kind": None, "patch_reason": patch.reason,
            "patched_status": None, "patched_reason": None,
            "regression_status": None, "regression_reason": None,
            "lock_self_check": None,
        }

    regression_source, regression_error = render_regression_test(template)
    if regression_source is None:
        reason = regression_error or "regression template unavailable"
        _progress(progress_callback, "patch", "skipped", f"Patch verification not run: {reason}.")
        return Status.INCONCLUSIVE.value, reason, {
            "patch_kind": patch.kind, "patch_reason": reason,
            "patched_status": None, "patched_reason": None,
            "regression_status": None, "regression_reason": None,
            "lock_self_check": None,
        }

    finding_dir.mkdir(parents=True, exist_ok=True)
    (finding_dir / "patch.diff").write_text(patch.diff, encoding="utf-8")
    if not (run_dir / "patch.diff").exists():
        (run_dir / "patch.diff").write_text(patch.diff, encoding="utf-8")
    (finding_dir / "Regression.t.sol").write_text(regression_source, encoding="utf-8")
    with tempfile.TemporaryDirectory(prefix="microscope-patched-") as temp_name:
        temp_root = Path(temp_name)
        patched_input = temp_root / "patched-input.sol"
        patched_input.write_text(patch.source, encoding="utf-8")
        try:
            _write_foundry_project(temp_root, patched_input, template.source)
        except OSError as exc:
            reason = f"could not prepare patched Foundry project: {type(exc).__name__}"
            _progress(progress_callback, "patch", "error", f"Could not prepare the patched test project for {target}.")
            return Status.INCONCLUSIVE.value, reason, {
                "patch_kind": patch.kind, "patch_reason": None,
                "patched_status": None, "patched_reason": reason,
                "regression_status": None, "regression_reason": None,
                "lock_self_check": None,
            }
        (temp_root / "test" / "Regression.t.sol").write_text(regression_source, encoding="utf-8")

        lock_self_check: bool | None = None
        lock_reason: str | None = None
        if patch.kind == "reentrancy":
            try:
                from .facts import analyze_file
                patched_facts, _ = analyze_file(
                    patched_input, fixture=source_fixture,
                    runs_dir=temp_root / "lock_self_check_runs",
                )
                target_after_patch = next(
                    (item for item in patched_facts.functions if item.id == suspect.function_id), None
                )
                lock_self_check = bool(
                    target_after_patch
                    and target_after_patch.reentrancy_guard.get("kind") == "lock_like_modifier"
                )
                if not lock_self_check:
                    lock_reason = "the scanner did not recognize its generated reentrancy lock"
            except Exception as exc:
                lock_reason = f"reentrancy lock self-check failed: {type(exc).__name__}: {exc}"
            (finding_dir / "patcher_lock_self_check.json").write_text(json.dumps({
                "recognized": lock_self_check, "reason": lock_reason,
            }, indent=2) + "\n", encoding="utf-8")

        _progress(progress_callback, "patch_compile", "running", f"Compiling the patched {target} in an isolated Foundry project.")
        build = run_forge_build(temp_root, timeout=timeout)
        (finding_dir / "patched_compile.log").write_text(
            build.stdout + ("\n" if build.stdout and build.stderr else "") + build.stderr,
            encoding="utf-8",
        )
        if build.error or build.returncode != 0:
            reason = build.error or f"patched source did not compile (forge build exited {build.returncode})"
            _progress(progress_callback, "patch_compile", "error", f"Patched compilation failed for {target}: {reason}.")
            failure = {"error": reason, "returncode": build.returncode,
                       "stdout_tail": build.stdout[-2000:], "stderr_tail": build.stderr[-2000:]}
            (finding_dir / "forge_patched.json").write_text(json.dumps(failure, indent=2) + "\n", encoding="utf-8")
            return Status.COMPILE_FAILED.value, reason, {
                "patch_kind": patch.kind, "patch_reason": lock_reason,
                "patched_status": "compile_failed", "patched_reason": reason,
                "regression_status": None, "regression_reason": None,
                "lock_self_check": lock_self_check,
            }
        _progress(progress_callback, "patch_compile", "complete", f"Patched source compiled for {target}.")

        _progress(progress_callback, "patched_attack", "running", f"Running the same Foundry attack against patched {target}.")
        attack = run_forge(temp_root, timeout=timeout, test_name="test_microscope_attack", verbosity=4)
        write_execution(finding_dir / "forge_patched.json", attack)
        (finding_dir / "trace.txt").write_text(attack.stdout or attack.stderr, encoding="utf-8")
        if not (run_dir / "trace.txt").exists():
            (run_dir / "trace.txt").write_text(attack.stdout or attack.stderr, encoding="utf-8")
        if not (run_dir / "forge_patched.json").exists():
            write_execution(run_dir / "forge_patched.json", attack)
        if attack.error:
            attack_result = None
            attack_reason = attack.error
        elif attack.returncode != 0:
            attack_result = None
            attack_reason = f"patched attack harness exited with status {attack.returncode}"
        else:
            attack_result = parse_forge_json(attack.stdout, expected_class=template.kind)
            attack_reason = attack_result.reason
        _progress(
            progress_callback, "patched_attack",
            "complete" if attack_result is not None else "error",
            f"Patched attack result for {target}: {attack_result.outcome if attack_result else 'inconclusive'}"
            + (f" — {attack_reason}" if attack_reason else ""),
        )

        _progress(progress_callback, "regression", "running", f"Running behavior-preservation regression for {target}.")
        regression = run_forge(temp_root, timeout=timeout,
                               test_name="test_microscope_regression", verbosity=2)
        if not (run_dir / "forge_regression.json").exists():
            write_execution(run_dir / "forge_regression.json", regression)
        if regression.error:
            regression_result = None
            regression_reason = regression.error
        elif regression.returncode != 0:
            regression_result = None
            regression_reason = f"regression harness exited with status {regression.returncode}"
        else:
            regression_result = parse_forge_json(
                regression.stdout, expected_test="test_microscope_regression",
                expected_class=f"{template.kind}_regression",
            )
            regression_reason = regression_result.reason
        _progress(
            progress_callback, "regression",
            "complete" if regression_result is not None else "error",
            f"Regression result for {target}: {regression_result.outcome if regression_result else 'inconclusive'}"
            + (f" — {regression_reason}" if regression_reason else ""),
        )

    attack_status = attack_result.outcome if attack_result else "inconclusive"
    regression_status = regression_result.outcome if regression_result else "inconclusive"
    if attack_status == "reproduced" or regression_status == "regression_failed" or lock_self_check is False:
        final_status = Status.REGRESSION_FAILURE.value
        final_reason = (attack_reason if attack_status == "reproduced" else
                        regression_reason if regression_status == "regression_failed" else lock_reason)
    elif (attack_status == "not_reproduced" and regression_status == "regression_passed"
          and (lock_self_check is True or patch.kind != "reentrancy")):
        final_status = Status.MITIGATED_IN_TEST.value
        final_reason = None
    else:
        final_status = Status.INCONCLUSIVE.value
        final_reason = attack_reason or regression_reason or lock_reason or "patch verification was inconclusive"

    _progress(progress_callback, "patch", "complete" if final_status == Status.MITIGATED_IN_TEST.value else "inconclusive",
              f"Patch verification for {target}: {final_status}" + (f" — {final_reason}" if final_reason else ""))

    return final_status, final_reason, {
        "patch_kind": patch.kind, "patch_reason": lock_reason,
        "patched_status": attack_status, "patched_reason": attack_reason,
        "regression_status": regression_status, "regression_reason": regression_reason,
        "lock_self_check": lock_self_check,
    }


def run_file(
    source: str | Path,
    *,
    fixture: bool = False,
    runs_dir: str | Path = "runs",
    timeout: int = 180,
    progress_callback: ProgressCallback | None = None,
) -> tuple[list[dict[str, Any]], Path]:
    """Analyze, reproduce, patch, and regression-test supported findings."""
    started = time.monotonic()
    started_at = datetime.now(timezone.utc).isoformat()
    _progress(progress_callback, "static_analysis", "running", "Running Slither analysis and collecting contract facts.")
    facts, run_dir = analyze_file(source, fixture=fixture, runs_dir=runs_dir)
    _progress(progress_callback, "static_analysis", "complete",
              f"Static analysis finished · {len(facts.functions)} functions · {len(facts.detector_hits)} detector hits · mode {facts.mode}.")
    source_path = Path(source).resolve(strict=True)
    source_text = source_path.read_text(encoding="utf-8")
    suspects = build_hypotheses(facts)
    candidate_count = sum(suspect.status == Status.CANDIDATE for suspect in suspects)
    _progress(progress_callback, "hypotheses", "complete",
              f"Rule checks finished · {candidate_count} candidate(s) among {len(suspects)} hypothesis record(s).")
    findings: list[dict[str, Any]] = []
    generated_root = run_dir / "generated"

    for static_suspect in suspects:
        suspect = copy.deepcopy(static_suspect)
        if suspect.status != Status.CANDIDATE:
            _progress(progress_callback, "original_attack", "skipped",
                      f"No Foundry attack for {suspect.function_id}: static analysis did not establish a candidate.")
            suspect.template_support = Tri.UNKNOWN
            record = _finding_record(
                suspect, template_kind=None, outcome=Status.INCONCLUSIVE.value,
                reason="static analysis was inconclusive; no original attack was run",
            )
            findings.append(_p3_record(
                record, patch_kind=None, patch_reason="no patch: no static candidate was established",
            ))
            continue

        template, unsupported = render_attack(facts, suspect)
        if template is None:
            _progress(progress_callback, "original_attack", "skipped",
                      f"No supported Foundry attack for {suspect.function_id}: {unsupported or 'unsupported source shape'}.")
            suspect.template_support = Tri.FALSE
            suspect.status = Status.INCONCLUSIVE
            suspect.unknown_reasons = sorted(set(suspect.unknown_reasons + [unsupported or "no attack template for this shape"]))
            record = _finding_record(
                suspect, template_kind=None, outcome=Status.INCONCLUSIVE.value,
                reason=unsupported or "no attack template for this shape",
            )
            findings.append(_p3_record(record, patch_kind=None, patch_reason=unsupported))
            continue

        suspect.template_support = Tri.TRUE
        finding_slug = _slug(suspect.id)
        finding_dir = generated_root / finding_slug
        finding_dir.mkdir(parents=True, exist_ok=True)
        attack_path = finding_dir / "Attack.t.sol"
        attack_path.write_text(template.source, encoding="utf-8")
        suspect.assumptions = sorted(set(suspect.assumptions + template.assumptions))
        _progress(progress_callback, "attack_setup", "complete",
                  f"Generated a {template.kind} test for {suspect.function_id}; preparing an offline local EVM run.")

        with tempfile.TemporaryDirectory(prefix="microscope-forge-") as temp_name:
            temp_root = Path(temp_name)
            try:
                _write_foundry_project(temp_root, source_path, template.source)
            except OSError as exc:
                reason = f"could not prepare isolated Foundry project: {type(exc).__name__}"
                _progress(progress_callback, "original_attack", "error",
                          f"Could not prepare the isolated Foundry test for {suspect.function_id}: {type(exc).__name__}.")
                suspect.status = Status.INCONCLUSIVE
                suspect.unknown_reasons = sorted(set(suspect.unknown_reasons + [reason]))
                record = _finding_record(suspect, template_kind=template.kind,
                                         outcome=Status.INCONCLUSIVE.value, reason=reason)
                findings.append(_p3_record(record, patch_kind=None, patch_reason=reason))
                continue

            _progress(progress_callback, "original_attack", "running",
                      f"Foundry attack running now against original {suspect.function_id} in an isolated offline EVM.")
            execution = run_forge(temp_root, timeout=timeout)
            raw_path = finding_dir / "forge_original.json"
            write_execution(raw_path, execution)
            if not (run_dir / "forge_original.json").exists():
                write_execution(run_dir / "forge_original.json", execution)
            if execution.error:
                parsed_status = "inconclusive"
                reason = execution.error
                result_payload = None
            elif execution.returncode != 0:
                parsed_status = "inconclusive"
                reason = f"forge exited with status {execution.returncode}"
                result_payload = None
            else:
                parsed = parse_forge_json(execution.stdout, expected_class=template.kind)
                parsed_status = parsed.outcome
                reason = parsed.reason
                result_payload = parsed.payload
            _progress(
                progress_callback, "original_attack",
                "complete" if parsed_status in {"reproduced", "not_reproduced"} else "error",
                f"Original attack result for {suspect.function_id}: {parsed_status}"
                + (f" — {reason}" if reason else ""),
            )

        try:
            status = Status(parsed_status)
        except ValueError:
            status = Status.INCONCLUSIVE
            reason = reason or f"unsupported runner status: {parsed_status}"
        original_status = status
        original_reason = reason
        original_payload = result_payload
        p3: dict[str, Any] = {
            "patch_kind": None,
            "patch_reason": "original attack was not reproduced; patch mitigation was not assessed",
            "patched_status": None, "patched_reason": None,
            "regression_status": None, "regression_reason": None,
            "lock_self_check": None,
        }
        final_status = original_status.value
        final_reason = original_reason
        if original_status == Status.REPRODUCED:
            final_status, final_reason, p3 = _patch_and_verify(
                source_text, fixture, facts, suspect, template,
                run_dir, finding_dir, timeout, progress_callback,
            )
        else:
            _progress(progress_callback, "patch", "skipped",
                      f"Patch and regression tests not run for {suspect.function_id}: the original attack was not reproduced.")
        try:
            suspect.status = Status(final_status)
        except ValueError:
            suspect.status = Status.INCONCLUSIVE
            final_reason = final_reason or f"unsupported P3 status: {final_status}"
        if final_reason:
            suspect.unknown_reasons = sorted(set(suspect.unknown_reasons + [final_reason]))
        record = _finding_record(
            suspect, template_kind=template.kind, outcome=original_status.value,
            reason=original_reason, payload=original_payload,
        )
        record["patch_status"] = final_status
        record["patch_status_reason"] = final_reason
        findings.append(_p3_record(
            record, patch_kind=p3["patch_kind"], patch_reason=p3["patch_reason"],
            patched_status=p3["patched_status"], patched_reason=p3["patched_reason"],
            regression_status=p3["regression_status"], regression_reason=p3["regression_reason"],
            lock_self_check=p3["lock_self_check"],
        ))

    (run_dir / "suspects.json").write_text(json.dumps(to_jsonable(suspects), indent=2) + "\n", encoding="utf-8")
    (run_dir / "findings.json").write_text(json.dumps(findings, indent=2) + "\n", encoding="utf-8")
    meta = {
        "schema_version": "1.0",
        "run_id": run_dir.name,
        "source_name": source_path.name,
        "fixture": fixture,
        "started_at": started_at,
        "duration_seconds": round(time.monotonic() - started, 3),
        "tool_versions": facts.tool_versions,
        "analysis_mode": facts.mode,
        "source_sha256": facts.source_sha256,
        "timeouts_seconds": {"slither": 180, "forge": timeout},
    }
    (run_dir / "meta.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    _progress(progress_callback, "complete", "complete", f"Run artifacts saved locally · {run_dir.name}.")
    return findings, run_dir


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run Microscope static hypotheses and supported original attacks.")
    parser.add_argument("source", type=Path)
    parser.add_argument("--fixture", action="store_true", help="explicitly label this input as a demo fixture")
    parser.add_argument("--runs-dir", type=Path, default=Path("runs"))
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args(argv)
    try:
        findings, run_dir = run_file(args.source, fixture=args.fixture, runs_dir=args.runs_dir, timeout=args.timeout)
        sys.stdout.write(json.dumps({"run_dir": str(run_dir), "findings": findings}, indent=2) + "\n")
        return 0
    except Exception as exc:
        sys.stderr.write(f"analysis failed: {type(exc).__name__}: {exc}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
