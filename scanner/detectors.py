"""Slither CLI JSON normalization; detector hits are corroboration only."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

_DIAGNOSTIC_LIMIT = 16_000


def normalize_cli_json(payload: dict[str, Any] | str) -> list[dict[str, Any]]:
    """Normalize Slither's JSON shape without trusting source paths."""
    if isinstance(payload, str):
        payload = json.loads(payload)
    result = payload.get("results", {}) or {}
    normalized: list[dict[str, Any]] = []
    for detector in result.get("detectors", []) or []:
        check = str(detector.get("check", "unknown"))
        for element in detector.get("elements", []) or []:
            mapping = element.get("source_mapping", {}) or {}
            specific = element.get("type_specific_fields", {}) or {}
            parent = specific.get("parent", {}) or {}
            if isinstance(parent, dict):
                contract = parent.get("name") or parent.get("contract") or ""
            else:
                contract = str(parent)
            signature = specific.get("signature") or element.get("signature") or ""
            name = str(element.get("name", ""))
            function_name = signature or name.rsplit(".", 1)[-1]
            lines = mapping.get("lines", []) or []
            normalized.append(
                {
                    "check": check,
                    "impact": str(detector.get("impact", "")),
                    "confidence": str(detector.get("confidence", "")),
                    "contract": contract,
                    "function": function_name,
                    "name": name,
                    "source_lines": sorted({int(line) for line in lines if str(line).isdigit()}),
                    "description": str(detector.get("description", "")).strip(),
                }
            )
    return normalized


def _minimal_env() -> dict[str, str]:
    """Keep only the executable search path and locale needed by Slither."""
    env = {"PATH": os.environ.get("PATH", os.defpath)}
    for name in ("HOME", "TMPDIR", "TEMP", "TMP", "LANG", "LC_ALL"):
        value = os.environ.get(name)
        if value:
            env[name] = value
    return env


def _output_text(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value or "")


def _failure_classification(text: str) -> str:
    lowered = text.lower()
    compile_markers = (
        "invalid compilation", "solc compilation error", "parsererror", "compilererror",
        "syntax error", "expected '", "expected token", "expected identifier",
    )
    return "compilation_error" if any(marker in lowered for marker in compile_markers) else "tool_failure"


def _append_diagnostic(
    diagnostics: list[dict[str, Any]] | None,
    *,
    classification: str,
    message: str,
    returncode: int | None = None,
    stdout: Any = "",
    stderr: Any = "",
) -> None:
    if diagnostics is None:
        return
    item: dict[str, Any] = {
        "tool": "slither-cli",
        "stage": "detector_analysis",
        "classification": classification,
        "returncode": returncode,
        "message": _output_text(message)[-_DIAGNOSTIC_LIMIT:],
        "message_truncated": len(_output_text(message)) > _DIAGNOSTIC_LIMIT,
    }
    for name, value in (("stdout", stdout), ("stderr", stderr)):
        text = _output_text(value)
        if text:
            item[name] = text[-_DIAGNOSTIC_LIMIT:]
            item[f"{name}_truncated"] = len(text) > _DIAGNOSTIC_LIMIT
    diagnostics.append(item)


def collect_detector_hits(
    source: Path,
    cwd: Path,
    timeout: int = 120,
    *,
    diagnostics: list[dict[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Run Slither CLI in a neutral directory and return normalized hits/errors."""
    executable = shutil.which("slither")
    if not executable:
        message = "slither CLI not found"
        _append_diagnostic(diagnostics, classification="tool_unavailable", message=message)
        return [], [message]
    output = cwd / "slither.json"
    # Never accept a stale report left by a previous invocation as this run's result.
    output.unlink(missing_ok=True)
    command = [executable, str(source), "--compile-force-framework", "solc", "--json", str(output)]
    try:
        completed = subprocess.run(
            command,
            cwd=str(cwd),
            env=_minimal_env(),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        message = f"slither CLI timed out after {timeout}s"
        _append_diagnostic(
            diagnostics, classification="timeout", message=message,
            stdout=exc.stdout, stderr=exc.stderr,
        )
        return [], [message]
    except OSError as exc:
        message = f"slither CLI could not start: {exc.__class__.__name__}: {exc}"
        _append_diagnostic(diagnostics, classification="launch_error", message=message)
        return [], [message]

    if not output.is_file():
        detail = "\n".join(part for part in (completed.stderr, completed.stdout) if part).strip()
        reason = detail or f"Slither exited with status {completed.returncode} and produced no JSON."
        classification = _failure_classification(reason)
        _append_diagnostic(
            diagnostics, classification=classification, message=reason,
            returncode=completed.returncode, stdout=completed.stdout, stderr=completed.stderr,
        )
        return [], [f"slither CLI {classification}: {reason[-_DIAGNOSTIC_LIMIT:]}"]
    try:
        payload = json.loads(output.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            raise TypeError("top-level JSON value is not an object")
        success = payload.get("success")
        if success is not True:
            detail = payload.get("error")
            if isinstance(detail, (dict, list)):
                detail = json.dumps(detail, ensure_ascii=False)
            detail = str(detail or "Slither JSON did not affirm success.")
            classification = _failure_classification(detail) if success is False else "invalid_tool_output"
            _append_diagnostic(
                diagnostics, classification=classification, message=detail,
                returncode=completed.returncode, stdout=completed.stdout, stderr=completed.stderr,
            )
            return [], [f"slither CLI {classification}: {detail[-_DIAGNOSTIC_LIMIT:]}"]
        if completed.returncode != 0:
            # Preserve the process outcome, but trust neither it nor the JSON alone:
            # callers retain valid hits only because the document explicitly says success=true.
            message = "Slither exited nonzero although its JSON reported success=true."
            _append_diagnostic(
                diagnostics, classification="nonzero_exit_with_success_json", message=message,
                returncode=completed.returncode, stdout=completed.stdout, stderr=completed.stderr,
            )
        return normalize_cli_json(payload), []
    except (OSError, json.JSONDecodeError, TypeError) as exc:
        detail = f"{exc.__class__.__name__}: {exc}"
        _append_diagnostic(
            diagnostics, classification="invalid_tool_output", message=detail,
            returncode=completed.returncode, stdout=completed.stdout, stderr=completed.stderr,
        )
        return [], [f"slither CLI JSON could not be read: {detail}"]
