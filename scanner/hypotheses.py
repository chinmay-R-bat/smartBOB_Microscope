"""Rule-based hypotheses. Static analysis can emit only candidate/inconclusive."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .facts import analyze_file
from .schema import Facts, SourceRef, Status, Suspect, Tri, to_jsonable


def _hit_matches(hit: dict[str, Any], function: Any) -> bool:
    contract = str(hit.get("contract", ""))
    signature = str(hit.get("function", ""))
    if contract and contract not in {function.contract, function.contract.split(".")[-1]}:
        return False
    if not signature:
        return False
    return (
        signature == function.id
        or signature == function.name
        or signature.endswith("." + function.name)
        or signature.startswith(function.name + "(")
    )


def _corroboration(facts: Facts, function: Any, checks: set[str]) -> Tri:
    hits = [
        hit for hit in facts.detector_hits
        if hit.get("check") in checks and _hit_matches(hit, function)
    ]
    if hits:
        return Tri.TRUE
    if facts.mode == "cli_json_only" or any("detector" in error.lower() for error in function.analysis_errors):
        return Tri.UNKNOWN
    return Tri.FALSE


def build_hypotheses(facts: Facts) -> list[Suspect]:
    suspects: list[Suspect] = []
    privileged = set(facts.privileged_vars)

    fatal_notes = [note for note in facts.contract_notes if note.get("code") == "analysis_error"]
    if fatal_notes:
        return [
            Suspect(
                id="ANALYSIS-inconclusive", category="analysis", status=Status.INCONCLUSIVE,
                function_id="analysis", src=None,
                rule="ANALYSIS-ERROR", evidence=[], assumptions=[],
                unknown_reasons=[note.get("message", "Static analysis failed.") for note in fatal_notes],
                detector_corroboration=Tri.UNKNOWN, template_support=Tri.UNKNOWN,
            )
        ]

    if facts.mode == "cli_json_only":
        # The fallback has no CFG facts and deliberately cannot infer access control.
        for hit in facts.detector_hits:
            if hit.get("check") != "reentrancy-eth":
                continue
            function_name = str(hit.get("function") or hit.get("name") or "unknown")
            contract = str(hit.get("contract") or "unknown")
            source_lines = hit.get("source_lines") or [1]
            line = min(source_lines)
            function_id = function_name if "." in function_name else f"{contract}.{function_name}"
            suspects.append(
                Suspect(
                    id=f"RE-DET-{function_id}", category="reentrancy", status=Status.CANDIDATE,
                    function_id=function_id,
                    src=SourceRef(path="input.sol", start_line=line, end_line=max(source_lines)),
                    rule="DET-reentrancy-eth",
                    evidence=[hit.get("description") or "Slither emitted a reentrancy-eth detector hit."],
                    unknown_reasons=["API facts unavailable"],
                    detector_corroboration=Tri.TRUE,
                    template_support=Tri.UNKNOWN,
                )
            )
        return suspects

    for function in facts.functions:
        if not function.entry_point:
            continue

        affected = sorted(set(function.state_writes_all) & privileged)
        if affected:
            if function.protection.verdict.value == "unprotected":
                status = Status.CANDIDATE
                reasons: list[str] = []
            elif function.protection.verdict.value == "unknown":
                status = Status.INCONCLUSIVE
                reasons = list(function.protection.unknown_reasons) or ["authorization behavior could not be classified"]
            else:
                status = None
                reasons = []
            if status is not None:
                suspects.append(
                    Suspect(
                        id=f"AC-1-{function.id}", category="access_control", status=status,
                        function_id=function.id, src=function.src, rule="AC-1",
                        evidence=[f"Entry function writes privileged state: {', '.join(affected)}."],
                        unknown_reasons=reasons,
                        detector_corroboration=_corroboration(
                            facts, function, {"arbitrary-send-eth", "suicidal", "unprotected-upgrade"}
                        ),
                        template_support=Tri.UNKNOWN,
                    )
                )

        has_dangerous_sink = any(value == Tri.TRUE for value in function.sink_flags.values())
        if has_dangerous_sink and function.protection.verdict.value in {"unprotected", "unknown"}:
            status = Status.CANDIDATE if function.protection.verdict.value == "unprotected" else Status.INCONCLUSIVE
            reasons = [] if status == Status.CANDIDATE else list(function.protection.unknown_reasons)
            sinks = [name for name, value in function.sink_flags.items() if value == Tri.TRUE]
            suspects.append(
                Suspect(
                    id=f"AC-2-{function.id}", category="access_control", status=status,
                    function_id=function.id, src=function.src, rule="AC-2",
                    evidence=[f"Entry function closure contains dangerous primitive: {', '.join(sinks)}."],
                    assumptions=["A dangerous primitive may be security-sensitive; no attack template is implemented."],
                    unknown_reasons=reasons,
                    detector_corroboration=_corroboration(
                        facts, function, {"arbitrary-send-eth", "suicidal", "unprotected-upgrade"}
                    ),
                    template_support=Tri.FALSE,
                )
            )

        if function.reentrancy_guard.get("kind") == "lock_like_modifier":
            continue
        if not function.writes_after_eth_call:
            continue
        if function.uses_assembly or function.reentrancy_guard.get("kind") == "unknown":
            status = Status.INCONCLUSIVE
            reasons = list(function.analysis_errors)
            if function.uses_assembly:
                reasons.append("assembly in the function closure prevents reliable effect analysis")
            if function.reentrancy_guard.get("kind") == "unknown":
                reasons.append(str(function.reentrancy_guard.get("detail") or "reentrancy guard could not be classified"))
        else:
            status = Status.CANDIDATE
            reasons = []
        conflict_vars = sorted(
            {str(item.get("var")) for item in function.writes_after_eth_call if item.get("var")}
        )
        call_lines = sorted({int(item.get("lines", 0)) for item in function.eth_calls if item.get("lines")})
        write_lines = sorted({int(item.get("write_lines", 0)) for item in function.writes_after_eth_call if item.get("write_lines")})
        evidence = []
        if call_lines:
            evidence.append(f"External ETH call at line(s) {', '.join(map(str, call_lines))}.")
        if conflict_vars:
            evidence.append(
                f"State variable(s) {', '.join(conflict_vars)} are read before and written after the call."
            )
        if write_lines:
            evidence.append(f"Post-call write at line(s) {', '.join(map(str, write_lines))}.")
        suspects.append(
            Suspect(
                id=f"RE-1-{function.id}", category="reentrancy", status=status,
                function_id=function.id, src=function.src, rule="RE-1", evidence=evidence,
                unknown_reasons=sorted(set(reasons)),
                detector_corroboration=_corroboration(facts, function, {"reentrancy-eth"}),
                template_support=Tri.UNKNOWN,
            )
        )

    # Stable output helps reviewers compare runs and mutation tests.
    return sorted(suspects, key=lambda item: (item.category, item.function_id, item.rule))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build static Microscope hypotheses for a Solidity file.")
    parser.add_argument("source", type=Path)
    parser.add_argument("--fixture", action="store_true", help="explicitly label this input as a demo fixture")
    parser.add_argument("--runs-dir", type=Path, default=Path("runs"))
    args = parser.parse_args(argv)
    try:
        facts, run_dir = analyze_file(args.source, fixture=args.fixture, runs_dir=args.runs_dir)
        suspects = build_hypotheses(facts)
        target = run_dir / "suspects.json"
        target.write_text(json.dumps(to_jsonable(suspects), indent=2) + "\n", encoding="utf-8")
        sys.stdout.write(json.dumps(to_jsonable(suspects), indent=2) + "\n")
        return 0
    except Exception as exc:
        sys.stderr.write(f"analysis failed: {exc.__class__.__name__}: {exc}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
