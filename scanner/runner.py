"""Run isolated generated Foundry tests and interpret their machine result."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

FORGE_TIMEOUT_SECONDS = 180


@dataclass(frozen=True)
class ParsedForgeResult:
    outcome: str
    reason: str | None = None
    payload: dict[str, Any] | None = None
    test_name: str | None = None


@dataclass(frozen=True)
class ForgeExecution:
    stdout: str
    stderr: str
    returncode: int | None
    error: str | None = None
    timed_out: bool = False


def _strings(value: Any):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from _strings(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            yield from _strings(child)


def _marker_payload(decoded_logs: Any) -> dict[str, Any] | None:
    decoder = json.JSONDecoder()
    for text in _strings(decoded_logs):
        start = text.find("MICROSCOPE_RESULT")
        if start < 0:
            continue
        brace = text.find("{", start + len("MICROSCOPE_RESULT"))
        if brace < 0:
            continue
        try:
            payload, _ = decoder.raw_decode(text[brace:])
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            return payload
    return None


def parse_forge_json(
    payload: dict[str, Any] | str,
    *,
    expected_test: str = "test_microscope_attack",
    expected_class: str | None = None,
) -> ParsedForgeResult:
    """Parse Forge 1.8.5's root -> test_results -> decoded_logs JSON shape.

    The root is a map keyed by `<test-file>:<contract>`. Each suite contains
    `test_results`, and each test result carries `status`, `reason`, and
    `decoded_logs`. This matches the captured Forge 1.8.5 sample.
    """
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except json.JSONDecodeError as exc:
            return ParsedForgeResult("inconclusive", f"Forge output was not valid JSON: {exc.msg}")
    if not isinstance(payload, dict):
        return ParsedForgeResult("inconclusive", "Forge JSON root was not an object")

    matches: list[tuple[str, dict[str, Any]]] = []
    for suite_name, suite in payload.items():
        if not isinstance(suite, dict):
            continue
        test_results = suite.get("test_results")
        if not isinstance(test_results, dict):
            continue
        for test_name, result in test_results.items():
            if not isinstance(result, dict):
                continue
            clean_name = str(test_name).split("(", 1)[0]
            if clean_name == expected_test:
                matches.append((str(test_name), result))

    if not matches:
        return ParsedForgeResult("inconclusive", f"Forge JSON did not contain {expected_test}")
    if len(matches) != 1:
        return ParsedForgeResult("inconclusive", f"Forge JSON contained {len(matches)} matching test results")

    test_name, result = matches[0]
    status = str(result.get("status", ""))
    if status != "Success":
        reason = result.get("reason") or result.get("counterexample") or f"test status was {status or 'missing'}"
        return ParsedForgeResult("inconclusive", f"Harness/test failure: {str(reason)[:500]}", test_name=test_name)

    result_payload = _marker_payload(result.get("decoded_logs", []))
    if result_payload is None:
        return ParsedForgeResult("inconclusive", "Test completed without a decoded MICROSCOPE_RESULT log", test_name=test_name)
    if expected_class and result_payload.get("class") != expected_class:
        return ParsedForgeResult("inconclusive", "MICROSCOPE_RESULT class did not match the requested attack", result_payload, test_name)
    if str(result_payload.get("class", "")).endswith("_regression"):
        passed = result_payload.get("regression_passed")
        if not isinstance(passed, bool) or not isinstance(result_payload.get("steps"), list):
            return ParsedForgeResult("inconclusive", "regression marker was missing a boolean result or steps list", result_payload, test_name)
        return ParsedForgeResult("regression_passed" if passed else "regression_failed",
                                 None if passed else "regression behavior did not pass", result_payload, test_name)
    if not isinstance(result_payload.get("exploit_succeeded"), bool):
        return ParsedForgeResult("inconclusive", "MICROSCOPE_RESULT did not contain a boolean exploit_succeeded", result_payload, test_name)
    if not isinstance(result_payload.get("steps"), list):
        return ParsedForgeResult("inconclusive", "MICROSCOPE_RESULT did not contain a steps list", result_payload, test_name)

    outcome = "reproduced" if result_payload["exploit_succeeded"] else "not_reproduced"
    reason = None if result_payload["exploit_succeeded"] else "exploit was not reproduced under this test"
    return ParsedForgeResult(outcome, reason=reason, payload=result_payload, test_name=test_name)


def _minimal_env(temp_root: Path) -> dict[str, str]:
    env = {
        "PATH": os.environ.get("PATH", os.defpath),
        "TMPDIR": str(temp_root),
        "TEMP": str(temp_root),
        "TMP": str(temp_root),
        "FOUNDRY_OFFLINE": "true",
    }
    for name in ("HOME", "LANG", "LC_ALL"):
        value = os.environ.get(name)
        if value:
            env[name] = value
    return env


def run_forge(project_dir: str | Path, *, timeout: int = FORGE_TIMEOUT_SECONDS,
              test_name: str = "test_microscope_attack", verbosity: int = 2) -> ForgeExecution:
    """Execute the single generated test offline with a bounded subprocess."""
    root = Path(project_dir).resolve(strict=True)
    executable = shutil.which("forge")
    if not executable:
        return ForgeExecution("", "", None, "forge executable not found")
    try:
        result = subprocess.run(
            [executable, "test", "--json", "-" + ("v" * max(1, min(verbosity, 5))),
             "--offline", "--match-test", test_name],
            cwd=str(root), env=_minimal_env(root), capture_output=True, text=True,
            timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired:
        return ForgeExecution("", "", None, f"forge test timed out after {timeout}s", timed_out=True)
    except OSError as exc:
        return ForgeExecution("", "", None, f"forge could not start: {type(exc).__name__}")
    return ForgeExecution(result.stdout, result.stderr, result.returncode)


def run_forge_build(project_dir: str | Path, *, timeout: int = FORGE_TIMEOUT_SECONDS) -> ForgeExecution:
    """Compile a temporary patched project offline before assigning a patch result."""
    root = Path(project_dir).resolve(strict=True)
    executable = shutil.which("forge")
    if not executable:
        return ForgeExecution("", "", None, "forge executable not found")
    try:
        result = subprocess.run(
            [executable, "build", "--offline"], cwd=str(root), env=_minimal_env(root),
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired:
        return ForgeExecution("", "", None, f"forge build timed out after {timeout}s", timed_out=True)
    except OSError as exc:
        return ForgeExecution("", "", None, f"forge build could not start: {type(exc).__name__}")
    return ForgeExecution(result.stdout, result.stderr, result.returncode)


def write_execution(path: str | Path, execution: ForgeExecution) -> None:
    """Persist Forge JSON unchanged when valid, or an explicit error envelope."""
    destination = Path(path)
    if execution.error:
        destination.write_text(
            json.dumps({"error": execution.error, "timed_out": execution.timed_out}, indent=2) + "\n",
            encoding="utf-8",
        )
        return
    try:
        json.loads(execution.stdout)
        destination.write_text(execution.stdout, encoding="utf-8")
    except json.JSONDecodeError:
        destination.write_text(
            json.dumps({
                "error": "forge output was not valid JSON",
                "returncode": execution.returncode,
                "stdout_tail": execution.stdout[-2000:],
                "stderr_tail": execution.stderr[-2000:],
            }, indent=2) + "\n",
            encoding="utf-8",
        )
