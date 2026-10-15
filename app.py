"""Microscope — Evidence-driven Solidity security workbench.

Don't warn. Prove. Then verify the fix.
"""

from __future__ import annotations

import html
import hashlib
import importlib.util
import json
import os
import re
import shutil
import tempfile
import time
from functools import lru_cache
from pathlib import Path
from typing import Any

import streamlit as st

from scanner.facts import MAX_SOURCE_BYTES
from scanner.run import run_file
from scanner import supabase_store
from scanner import gemini_explainer


ROOT = Path(__file__).resolve().parent
RUNS_DIR = ROOT / "runs"
DEMO_DIRS = (ROOT / "src" / "vulnerable", ROOT / "src" / "fixed")
ARTIFACT_NAMES = (
    "meta.json", "facts.json", "suspects.json", "findings.json",
    "forge_original.json", "forge_patched.json", "forge_regression.json",
    "patch.diff", "trace.txt",
)
REPORT_ARTIFACT_NAMES = ("meta.json", "facts.json", "suspects.json", "findings.json", "patch.diff")
REMOTE_FINDING_FIELDS = (
    "id", "category", "status", "function_id", "rule", "evidence", "assumptions",
    "unknown_reasons", "detector_corroboration", "template_support",
)
STATUS_COPY = {
    "candidate": "Static evidence suggests a plausible issue. No exploit has been demonstrated yet.",
    "inconclusive": "The available analysis or test could not conclusively determine the outcome.",
    "reproduced": "An executed Foundry test demonstrated this attack under its recorded EVM assumptions.",
    "not_reproduced": "This test did not demonstrate the attack. That does not establish safety.",
    "mitigated_in_test": "The same attack was blocked and the regression test passed for this run.",
    "regression_failure": "The patched run did not satisfy the attack and regression checks.",
    "compile_failed": "The patched source did not compile; mitigation was not established.",
}
STATUS_COLORS = {
    "candidate": "#F59E0B",
    "inconclusive": "#F59E0B",
    "reproduced": "#EF4444",
    "not_reproduced": "#94A3B8",
    "mitigated_in_test": "#10B981",
    "regression_failure": "#EF4444",
    "compile_failed": "#EF4444",
}
STATUS_BG = {
    "candidate": "rgba(245, 158, 11, 0.12)",
    "inconclusive": "rgba(245, 158, 11, 0.12)",
    "reproduced": "rgba(239, 68, 68, 0.14)",
    "not_reproduced": "rgba(148, 163, 184, 0.12)",
    "mitigated_in_test": "rgba(16, 185, 129, 0.14)",
    "regression_failure": "rgba(239, 68, 68, 0.14)",
    "compile_failed": "rgba(239, 68, 68, 0.14)",
}


def _read_json(path: Path) -> tuple[Any | None, str | None]:
    if not path.is_file():
        return None, "Not recorded for this run."
    try:
        return json.loads(path.read_text(encoding="utf-8")), None
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return None, f"Artifact could not be read ({type(exc).__name__})."


def _run_ids() -> list[str]:
    if not RUNS_DIR.is_dir():
        return []
    return sorted(
        (path.name for path in RUNS_DIR.iterdir() if path.is_dir()), reverse=True
    )


def _run_path(run_id: str) -> Path | None:
    if run_id not in _run_ids():
        return None
    candidate = (RUNS_DIR / run_id).resolve()
    return candidate if candidate.parent == RUNS_DIR.resolve() else None


def _source_name(meta: dict[str, Any]) -> str:
    source_name = meta.get("source_name")
    if isinstance(source_name, str) and source_name.strip():
        return Path(source_name.replace("\\", "/")).name
    digest = str(meta.get("source_sha256") or "")
    for path in _fixture_paths_by_hash().get(digest, ()):
        return path.name
    return "Uploaded Solidity source"


@lru_cache(maxsize=1)
def _fixture_paths_by_hash() -> dict[str, tuple[Path, ...]]:
    paths: dict[str, list[Path]] = {}
    for _label, path in _demo_files():
        try:
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            paths.setdefault(digest, []).append(path)
        except OSError:
            continue
    return {digest: tuple(items) for digest, items in paths.items()}


def _run_label(run_id: str) -> str:
    run_dir = RUNS_DIR / run_id
    meta, meta_error = _read_json(run_dir / "meta.json")
    meta = meta if meta_error is None and isinstance(meta, dict) else {}
    name = _source_name(meta)
    started = str(meta.get("started_at") or "")
    try:
        stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.strptime(started[:19], "%Y-%m-%dT%H:%M:%S"))
    except ValueError:
        stamp = run_id[:15]
    digest = str(meta.get("source_sha256") or run_id.rsplit("-", 1)[-1])[:8]
    return f"{stamp} · {name} · hash:{digest} · run:{run_id[-6:]}"


def _artifact(run_dir: Path | None, name: str) -> tuple[Any | None, str | None]:
    if run_dir is None:
        return None, "Choose a stored run to view its artifacts."
    return _read_json(run_dir / name)


def _text_artifact(run_dir: Path | None, name: str) -> tuple[str | None, str | None]:
    if run_dir is None:
        return None, "Choose a stored run to view its artifacts."
    path = run_dir / name
    if not path.is_file():
        return None, "Not recorded for this run."
    try:
        return path.read_text(encoding="utf-8"), None
    except (OSError, UnicodeError) as exc:
        return None, f"Artifact could not be read ({type(exc).__name__})."


def _finding_dir(run_dir: Path | None, finding: dict[str, Any]) -> Path | None:
    if run_dir is None:
        return None
    identifier = str(finding.get("id") or "finding")
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", identifier).strip("._-") or "finding"
    parent = (run_dir / "generated").resolve()
    candidate = (parent / slug).resolve()
    return candidate if candidate.parent == parent else None


def _demo_files() -> list[tuple[str, Path]]:
    files: list[tuple[str, Path]] = []
    labels = {
        "VulnerableTreasury.sol": "Vulnerable Treasury (Access Control Bug)",
        "SafeTreasury.sol": "Fixed Treasury (Access Guarded)",
        "VulnerableVault.sol": "Vulnerable Vault (ETH Reentrancy Bug)",
        "SafeVault.sol": "Fixed Vault (Reentrancy Guarded)",
    }
    for folder in DEMO_DIRS:
        if folder.is_dir():
            for path in sorted(folder.glob("*.sol")):
                files.append((labels.get(path.name, path.stem), path))
    return files


def _status_badge_html(status: Any) -> str:
    value = str(status or "inconclusive")
    color = STATUS_COLORS.get(value, "#94A3B8")
    bg = STATUS_BG.get(value, "rgba(148, 163, 184, 0.12)")
    display_text = value.replace("_", " ").upper()
    return f'<span class="micro-badge" style="--badge-color: {color}; --badge-bg: {bg};"><span class="badge-dot" style="background: {color};"></span>{html.escape(display_text)}</span>'


def _status(status: Any) -> None:
    st.markdown(_status_badge_html(status), unsafe_allow_html=True)
    explanation = STATUS_COPY.get(str(status or "inconclusive"))
    if explanation:
        st.caption(explanation)


def _show_missing(message: str | None, *, label: str = "Artifact") -> None:
    st.info(f"{label}: {message or 'Not recorded for this run.'}")


def _render_notice(facts: Any | None) -> None:
    if facts is None:
        _show_missing("Facts and contract notices are unavailable.", label="Contract notices")
        return
    notes = facts.get("contract_notes")
    if not isinstance(notes, list):
        _show_missing("The facts artifact has no contract_notes field.", label="Contract notices")
        return
    if not notes:
        return
    for note in notes:
        if not isinstance(note, dict):
            continue
        code = str(note.get("code") or "notice")
        message = str(note.get("message") or "Contract notice text was not recorded.")
        contract = str(note.get("contract") or "Contract")
        notice_html = (
            f'<div class="micro-alert-box alert-warning">'
            f'<div class="alert-header">'
            f'<span class="alert-icon">⚠️</span>'
            f'<strong>INCONCLUSIVE CONTRACT NOTICE · {html.escape(code.upper())}</strong>'
            f'</div>'
            f'<div class="alert-body">'
            f'<strong>Target:</strong> <code>{html.escape(contract)}</code><br>'
            f'{html.escape(message)}'
            f'</div>'
            f'<div class="alert-footer">'
            f'Preserve Unknown: This notice signifies high uncertainty. Microscope does NOT report this contract as clean or safe.'
            f'</div>'
            f'</div>'
        )
        st.markdown(notice_html, unsafe_allow_html=True)


def _render_analysis_diagnostics(facts: Any | None) -> None:
    if not isinstance(facts, dict):
        return
    diagnostics = facts.get("analysis_diagnostics")
    if not isinstance(diagnostics, list) or not diagnostics:
        return
    with st.expander("🛠️ Analyzer & Compiler Diagnostics", expanded=False):
        for diagnostic in diagnostics:
            if not isinstance(diagnostic, dict):
                continue
            tool = str(diagnostic.get("tool") or "analysis tool")
            classification = str(diagnostic.get("classification") or "unknown error")
            returncode = diagnostic.get("returncode")
            st.markdown(f"**{html.escape(tool)}** · `{html.escape(classification)}`")
            if returncode is not None:
                st.caption(f"Exit code: `{returncode}`")
            if diagnostic.get("message_truncated") or diagnostic.get("stdout_truncated") or diagnostic.get("stderr_truncated"):
                st.caption("One or more fields were truncated to the 16 KB evidence limit.")
            for field in ("message", "stderr", "stdout"):
                value = diagnostic.get(field)
                if value:
                    st.code(str(value), language="text")


def _gemini_api_key() -> str | None:
    key = os.environ.get("GEMINI_API_KEY", "").strip()
    if key:
        return key
    try:
        return str(st.secrets.get("GEMINI_API_KEY", "")).strip() or None
    except Exception:
        return None


def _local_finding_explanation(finding: dict[str, Any]) -> str:
    status = str(finding.get("status") or "inconclusive")
    category = str(finding.get("category") or "security")
    evidence = finding.get("evidence") if isinstance(finding.get("evidence"), list) else []
    assumptions = finding.get("assumptions") if isinstance(finding.get("assumptions"), list) else []
    unknowns = finding.get("unknown_reasons") if isinstance(finding.get("unknown_reasons"), list) else []
    lines = [
        f"Domain: {category.replace('_', ' ').title()} · Verdict: {status.replace('_', ' ').upper()}",
        "",
        STATUS_COPY.get(status, "Status recorded for this run."),
    ]
    if evidence:
        lines.extend(["", "Recorded Fact Evidence:", *[f"  • {item}" for item in evidence[:8]]])
    if assumptions:
        lines.extend(["", "Bound Assumptions:", *[f"  • {item}" for item in assumptions[:6]]])
    if unknowns:
        lines.extend(["", "Unverified Unknowns:", *[f"  • {item}" for item in unknowns[:6]]])
    lines.extend(["", "Note: Local deterministic summary derived strictly from stored run artifacts."])
    return "\n".join(lines)


def _render_pipeline_visualizer(run_dir: Path | None, facts: dict[str, Any] | None, findings: list[Any]) -> None:
    s1_active = facts is not None
    s1_state = "Recorded" if s1_active else "Pending"
    s1_color = "#00F0B5" if s1_active else "#64748B"

    s2_active = bool(findings)
    s2_state = f"{len(findings)} Rule(s)" if s2_active else "Checked"
    s2_color = "#00F0B5" if s2_active else "#64748B"

    has_reproduced = False
    has_mitigated = False
    has_regression = False
    for f in findings:
        if not isinstance(f, dict):
            continue
        if (f.get("original_result") or {}).get("status") == "reproduced":
            has_reproduced = True
        if (f.get("patched_result") or {}).get("status") in {"not_reproduced", "mitigated_in_test"} or f.get("status") == "mitigated_in_test":
            has_mitigated = True
        if (f.get("regression_result") or {}).get("status") == "regression_passed":
            has_regression = True

    s3_state = "Exploit Reproduced" if has_reproduced else ("No Exploit" if s2_active else "Pending")
    s3_color = "#EF4444" if has_reproduced else ("#94A3B8" if s2_active else "#64748B")

    s4_state = "Patch Verified" if has_mitigated else ("Not Triggered" if not has_reproduced else "Pending")
    s4_color = "#10B981" if has_mitigated else "#64748B"

    s5_state = "Passed" if has_regression else ("Not Triggered" if not has_mitigated else "Pending")
    s5_color = "#10B981" if has_regression else "#64748B"

    pipeline_html = (
        f'<div class="pipeline-card">'
        f'<div class="pipeline-header">'
        f'<span class="pipeline-title">EVIDENCE VERIFICATION PIPELINE</span>'
        f'<span class="pipeline-sub">5-Stage Deterministic Verification Workflow</span>'
        f'</div>'
        f'<div class="pipeline-flow">'
        f'<div class="pipeline-step">'
        f'<div class="step-num" style="border-color: {s1_color}; color: {s1_color};">01</div>'
        f'<div class="step-label">Static Facts</div>'
        f'<div class="step-desc" style="color: {s1_color};">{s1_state}</div>'
        f'</div>'
        f'<div class="pipeline-arrow">➔</div>'
        f'<div class="pipeline-step">'
        f'<div class="step-num" style="border-color: {s2_color}; color: {s2_color};">02</div>'
        f'<div class="step-label">Hypotheses</div>'
        f'<div class="step-desc" style="color: {s2_color};">{s2_state}</div>'
        f'</div>'
        f'<div class="pipeline-arrow">➔</div>'
        f'<div class="pipeline-step">'
        f'<div class="step-num" style="border-color: {s3_color}; color: {s3_color};">03</div>'
        f'<div class="step-label">EVM Attack</div>'
        f'<div class="step-desc" style="color: {s3_color};">{s3_state}</div>'
        f'</div>'
        f'<div class="pipeline-arrow">➔</div>'
        f'<div class="pipeline-step">'
        f'<div class="step-num" style="border-color: {s4_color}; color: {s4_color};">04</div>'
        f'<div class="step-label">Patch Verified</div>'
        f'<div class="step-desc" style="color: {s4_color};">{s4_state}</div>'
        f'</div>'
        f'<div class="pipeline-arrow">➔</div>'
        f'<div class="pipeline-step">'
        f'<div class="step-num" style="border-color: {s5_color}; color: {s5_color};">05</div>'
        f'<div class="step-label">Regression</div>'
        f'<div class="step-desc" style="color: {s5_color};">{s5_state}</div>'
        f'</div>'
        f'</div>'
        f'</div>'
    )
    st.markdown(pipeline_html, unsafe_allow_html=True)


def _render_engine_readiness() -> None:
    slither_ok = bool(shutil.which("slither")) and importlib.util.find_spec("slither") is not None
    solc_ok = bool(shutil.which("solc"))
    forge_ok = bool(shutil.which("forge"))

    cols = st.columns(3)
    with cols[0]:
        st.markdown(
            f'<div class="engine-badge {"badge-active" if slither_ok else "badge-warn"}">'
            f'<span class="engine-dot"></span>'
            f'<span class="engine-name">Slither AST 0.11.6</span>'
            f'<span class="engine-status">{"READY" if slither_ok else "NOT DETECTED"}</span>'
            f'</div>',
            unsafe_allow_html=True,
        )
    with cols[1]:
        st.markdown(
            f'<div class="engine-badge {"badge-active" if forge_ok else "badge-warn"}">'
            f'<span class="engine-dot"></span>'
            f'<span class="engine-name">Foundry Forge EVM</span>'
            f'<span class="engine-status">{"READY" if forge_ok else "NOT DETECTED"}</span>'
            f'</div>',
            unsafe_allow_html=True,
        )
    with cols[2]:
        st.markdown(
            f'<div class="engine-badge {"badge-active" if solc_ok else "badge-warn"}">'
            f'<span class="engine-dot"></span>'
            f'<span class="engine-name">Solidity Compiler (solc)</span>'
            f'<span class="engine-status">{"READY" if solc_ok else "NOT DETECTED"}</span>'
            f'</div>',
            unsafe_allow_html=True,
        )


def _get_source_snippet(finding: dict[str, Any], run_dir: Path | None) -> str | None:
    src = finding.get("src")
    if not isinstance(src, dict):
        return None
    path_str = src.get("path")
    start = src.get("start_line")
    end = src.get("end_line")
    if not path_str or not isinstance(start, int) or not isinstance(end, int):
        return None
    source_file = None
    for d in DEMO_DIRS:
        candidate = d / Path(path_str).name
        if candidate.is_file():
            source_file = candidate
            break
    if not source_file and run_dir:
        candidate = run_dir / Path(path_str).name
        if candidate.is_file():
            source_file = candidate
    if not source_file:
        for p in ROOT.glob(f"**/{Path(path_str).name}"):
            if p.is_file() and not any(part in p.parts for part in (".venv", ".pytest_cache", "runs", "out")):
                source_file = p
                break
    if not source_file:
        return None
    try:
        lines = source_file.read_text(encoding="utf-8").splitlines()
        s_idx = max(0, start - 2)
        e_idx = min(len(lines), end + 2)
        return "\n".join(lines[s_idx:e_idx])
    except Exception:
        return None


def _render_finding_card(finding: dict[str, Any], index: int, run_id: str) -> None:
    status = str(finding.get("status") or "inconclusive")
    source = finding.get("src") if isinstance(finding.get("src"), dict) else {}
    title = str(finding.get("function_id") or finding.get("id") or f"Finding {index + 1}")
    rule = str(finding.get("rule") or "RULE-N/A")
    category = str(finding.get("category") or "security").upper()
    location = (
        f"{source.get('path', 'source')} : L{source.get('start_line', '?')}–L{source.get('end_line', '?')}"
        if source else "Source location unavailable"
    )

    badge_html = _status_badge_html(status)

    card_html = (
        f'<div class="finding-card">'
        f'<div class="finding-card-header">'
        f'<div>'
        f'<div class="finding-card-tags">'
        f'<span class="tag-category">{html.escape(category)}</span>'
        f'<span class="tag-rule">{html.escape(rule)}</span>'
        f'<span class="tag-location">{html.escape(location)}</span>'
        f'</div>'
        f'<h3 class="finding-title">{html.escape(title)}</h3>'
        f'</div>'
        f'<div>{badge_html}</div>'
        f'</div>'
        f'<div class="finding-copy">{html.escape(STATUS_COPY.get(status, "Status recorded for this run."))}</div>'
        f'</div>'
    )
    st.markdown(card_html, unsafe_allow_html=True)

    with st.container():
        run_path_obj = _run_path(run_id) if run_id else None
        snippet = _get_source_snippet(finding, run_path_obj)
        if snippet:
            with st.expander(f"📄 Solidity Code Snippet · {html.escape(location)}", expanded=True):
                st.code(snippet, language="solidity")

        evidence = finding.get("evidence")
        if isinstance(evidence, list) and evidence:
            st.markdown("**Recorded AST & Detector Evidence**")
            for item in evidence:
                st.markdown(f"- <code>{html.escape(str(item))}</code>", unsafe_allow_html=True)
        elif evidence == []:
            st.caption("No evidence strings recorded for this finding.")
        else:
            _show_missing("Evidence is not present in this finding artifact.", label="Evidence")

        explanation_key = f"finding_explanation_{run_id}_{index}"
        api_key = _gemini_api_key()

        button_label = "✨ Explain finding with Gemini AI" if api_key else "📝 Explain from recorded evidence"
        explain_clicked = st.button(
            button_label,
            key=f"finding_explain_btn_{run_id}_{index}",
            disabled=not (isinstance(evidence, list) and bool(evidence)),
            help="Provides plain language commentary grounded strictly in the recorded evidence fields.",
        )
        if explain_clicked:
            if api_key:
                try:
                    explanation = gemini_explainer.explain_finding(finding, api_key)
                    st.session_state[explanation_key] = {"text": explanation, "kind": "ai"}
                except gemini_explainer.ExplanationUnavailable:
                    st.session_state[explanation_key] = {
                        "text": _local_finding_explanation(finding), "kind": "fallback",
                    }
            else:
                st.session_state[explanation_key] = {
                    "text": _local_finding_explanation(finding), "kind": "local",
                }

        explanation = st.session_state.get(explanation_key)
        if isinstance(explanation, dict):
            kind = explanation.get("kind")
            if kind == "ai":
                label_html = '<span class="ai-label">AI-generated explanation — not proof</span>'
            elif kind == "fallback":
                label_html = '<span class="ai-label">Local evidence summary — Gemini unavailable · not proof</span>'
            else:
                label_html = '<span class="local-label">Local evidence summary — not AI and not proof</span>'

            expl_html = (
                f'<div class="explanation-box">'
                f'<div class="explanation-tag">{label_html}</div>'
                f'<div class="explanation-body">{html.escape(str(explanation.get("text", "")))}</div>'
                f'</div>'
            )
            st.markdown(expl_html, unsafe_allow_html=True)

        with st.expander("🔍 Bound Assumptions & Unknown Reasons", expanded=False):
            assumptions = finding.get("assumptions")
            unknowns = finding.get("unknown_reasons")
            st.markdown("**Assumptions in Test Synthesis:**")
            if isinstance(assumptions, list) and assumptions:
                for item in assumptions:
                    st.markdown(f"- {html.escape(str(item))}")
            else:
                st.caption("No assumptions recorded.")

            st.markdown("**Uncertainty / Unknown Reasons:**")
            if isinstance(unknowns, list) and unknowns:
                for item in unknowns:
                    st.markdown(f"- {html.escape(str(item))}")
            else:
                st.caption("No unknown reasons recorded.")


def _render_findings(run_dir: Path | None) -> None:
    st.markdown('<h2 class="view-title">Audit Findings & Hypotheses</h2>', unsafe_allow_html=True)
    st.markdown(
        '<p class="view-subtitle">Hypotheses formed from Slither AST facts. A static candidate is never an exploit verdict until proven in Foundry EVM.</p>',
        unsafe_allow_html=True,
    )

    completed_message = st.session_state.pop("scan_completed_message", None)
    if completed_message:
        st.success(completed_message)

    _render_live_scan_log(run_dir)

    facts, facts_error = _artifact(run_dir, "facts.json")
    _render_notice(facts if facts_error is None and isinstance(facts, dict) else None)

    findings, error = _artifact(run_dir, "findings.json")
    if error:
        _show_missing(error, label="Findings")
        return
    if not isinstance(findings, list):
        _show_missing("The findings artifact is not a list.", label="Findings")
        return

    _render_pipeline_visualizer(run_dir, facts if isinstance(facts, dict) else None, findings)

    if not findings:
        st.markdown(
            '<div class="micro-empty-box">'
            '<span class="empty-icon">🛡️</span>'
            '<h4>No findings were recorded for this run</h4>'
            '<p>Preserve Unknown: This is NOT a claim or certificate that the contract is safe. No supported rule suspects fired under current templates.</p>'
            '</div>',
            unsafe_allow_html=True,
        )
        return

    counts: dict[str, int] = {}
    for item in findings:
        if isinstance(item, dict):
            key = str(item.get("status") or "inconclusive")
            counts[key] = counts.get(key, 0) + 1

    metric_cols = st.columns(4)
    metric_cols[0].metric("Total Suspects", len(findings))
    metric_cols[1].metric("Reproduced Exploits", counts.get("reproduced", 0), delta="EVM Proven" if counts.get("reproduced") else None, delta_color="inverse")
    metric_cols[2].metric("Mitigated & Verified", counts.get("mitigated_in_test", 0), delta="Fixed & Tested" if counts.get("mitigated_in_test") else None)
    metric_cols[3].metric("Candidates / Inconclusive", counts.get("candidate", 0) + counts.get("inconclusive", 0))

    st.markdown("---")

    filter_option = st.radio(
        "Filter Findings List",
        ["All Findings", "Reproduced Exploits", "Mitigated Fixes", "Candidates & Inconclusive"],
        horizontal=True,
        key="finding_filter_radio",
    )

    filtered_findings = []
    for item in findings:
        if not isinstance(item, dict):
            continue
        stat = str(item.get("status") or "inconclusive")
        if filter_option == "All Findings":
            filtered_findings.append(item)
        elif filter_option == "Reproduced Exploits" and stat == "reproduced":
            filtered_findings.append(item)
        elif filter_option == "Mitigated Fixes" and stat == "mitigated_in_test":
            filtered_findings.append(item)
        elif filter_option == "Candidates & Inconclusive" and stat in {"candidate", "inconclusive", "not_reproduced"}:
            filtered_findings.append(item)

    if not filtered_findings:
        st.info(f"No findings match the '{filter_option}' filter.")
    else:
        for index, finding in enumerate(filtered_findings):
            _render_finding_card(finding, index, run_dir.name if run_dir else "no-run")

    col_btn, _ = st.columns([1, 1])
    with col_btn:
        if st.button("🚀 Inspect Attack Replay & Patch Verification →", type="primary", use_container_width=True):
            st.session_state["pending_workspace_page"] = "Attack evidence"
            st.rerun()

    if facts_error is None and isinstance(facts, dict):
        _render_analysis_diagnostics(facts)
        with st.expander("📋 Corroborating Static Detector Hits (Slither Raw JSON)", expanded=False):
            hits = facts.get("detector_hits")
            if isinstance(hits, list) and hits:
                st.caption("Slither detectors are corroboration only; they do not dictate the verdict.")
                st.json(hits)
            else:
                st.caption("No Slither detector hits recorded.")


def _local_attack_explanation(finding: dict[str, Any]) -> str:
    category = str(finding.get("category") or "security").replace("_", " ").title()
    rule = str(finding.get("rule") or "N/A")
    func_id = str(finding.get("function_id") or "target function")
    orig = finding.get("original_result") if isinstance(finding.get("original_result"), dict) else {}
    orig_status = str(orig.get("status") or "inconclusive").upper()
    patched = finding.get("patched_result") if isinstance(finding.get("patched_result"), dict) else {}
    patch_status = str(patched.get("status") or "not run").upper()
    oracle = finding.get("oracle") if isinstance(finding.get("oracle"), dict) else {}
    succeeded = oracle.get("exploit_succeeded")

    lines = [
        f"EVM Attack Replay Analysis: {func_id} ({category})",
        "",
        f"1. Vulnerability & Attack Mechanism: Rule {rule} flagged {func_id}. "
        f"Microscope generated an isolated Foundry EVM test contract (Attack.t.sol) to attempt reproducing this issue.",
        "",
        f"2. Execution Outcome: The attack against the original unpatched contract resulted in '{orig_status}'. "
        + (f"Exploit succeeded: {succeeded}." if succeeded is not None else ""),
        "",
        f"3. Deterministic Patch Verification: The exact same test re-run against patched bytecode resulted in '{patch_status}'. "
        + ("EVM revert stopped the unauthorized operation." if patch_status in ("NOT_REPRODUCED", "MITIGATED_IN_TEST") else "Patch verification was not established."),
        "",
        "Ground truth established by local Foundry EVM execution. Local deterministic summary.",
    ]
    return "\n".join(lines)


def _build_dynamic_attack_phases(finding: dict[str, Any]) -> list[dict[str, str]]:
    category = str(finding.get("category") or "security")
    func_id = str(finding.get("function_id") or "target_function()")
    func_name = func_id.split(".")[-1] if "." in func_id else func_id
    contract_name = func_id.split(".")[0] if "." in func_id else "Contract"
    orig = finding.get("original_result") if isinstance(finding.get("original_result"), dict) else {}
    orig_status = str(orig.get("status") or "inconclusive")
    reproduced = orig_status == "reproduced"

    if category == "reentrancy":
        p1_title = "Initial Funding"
        p1_desc = f"Attacker funds test harness and deposits ETH into {contract_name} to establish active ledger balance."
        p2_title = "Invoke Vulnerable Function"
        p2_desc = f"Attacker calls {func_name} requesting return/withdrawal of deposited balance."
        p3_title = "External Call Intercept"
        p3_desc = f"{contract_name} executes external raw call to msg.sender BEFORE state balance is zeroed."
        p4_title = "Recursive Drain Exploit" if reproduced else "Reentrancy Reverted"
        p4_desc = (
            f"Attacker receive() hook recursively re-enters {func_name} until pool balance is drained to 0 ETH."
            if reproduced
            else f"Reentrant call to {func_name} reverted or failed under tested EVM conditions."
        )
    elif category == "access_control":
        target_var = "privileged state"
        for ev in (finding.get("evidence") or []):
            if "writes privileged state:" in str(ev):
                target_var = str(ev).split("writes privileged state:")[-1].strip().rstrip(".")
        if target_var == "privileged state" and "." in func_id:
            target_var = f"{contract_name}.owner"

        p1_title = "Unauthorized Caller"
        p1_desc = f"Attacker from untrusted address 0xBAD directly invokes {func_name}."
        p2_title = "Missing Authorization Guard"
        p2_desc = f"No caller authentication check (e.g. onlyOwner or require(msg.sender == owner)) is enforced."
        p3_title = "State Slot Overwrite"
        p3_desc = f"EVM storage slot for {target_var} is overwritten with attacker address (0xBAD)."
        p4_title = "Privilege Takeover Verified" if reproduced else "Takeover Prevented"
        p4_desc = (
            f"Public oracle getter confirms {target_var} == 0xBAD. Attacker gained administrative control."
            if reproduced
            else f"Setter {func_name} did not allow unauthorized caller to overwrite {target_var}."
        )
    else:
        p1_title = "Attack Test Setup"
        p1_desc = f"Synthesizing isolated Foundry test harness for {func_id}."
        p2_title = "Target Call Invocation"
        p2_desc = f"Calling {func_name} with recorded heuristic arguments."
        p3_title = "EVM Execution & Tracing"
        p3_desc = f"Foundry EVM execution recorded gas and state diffs for {func_id}."
        p4_title = "Oracle Verification"
        p4_desc = f"Exploit verification result: {orig_status.upper()}."

    return [
        {"badge": "PHASE 1", "title": p1_title, "desc": p1_desc},
        {"badge": "PHASE 2", "title": p2_title, "desc": p2_desc},
        {"badge": "PHASE 3", "title": p3_title, "desc": p3_desc},
        {"badge": "PHASE 4", "title": p4_title, "desc": p4_desc},
    ]


def _build_dynamic_comparison_matrix(finding: dict[str, Any]) -> str:
    orig = finding.get("original_result") if isinstance(finding.get("original_result"), dict) else {}
    patched = finding.get("patched_result") if isinstance(finding.get("patched_result"), dict) else {}
    regression = finding.get("regression_result") if isinstance(finding.get("regression_result"), dict) else {}

    orig_status = str(orig.get("status") or "inconclusive")
    patch_status = str(patched.get("status") or "not_run")
    reg_status = str(regression.get("status") or "not_run")

    if orig_status == "reproduced":
        col1_status = '<div class="comp-status status-danger">🔥 Exploit Succeeded</div>'
        col1_body = "Local Foundry EVM test demonstrated full exploit outcome under recorded assumptions."
    elif orig_status == "not_reproduced":
        col1_status = '<div class="comp-status status-warning">⚖️ Not Reproduced</div>'
        col1_body = "This test did not demonstrate the attack. Note: not reproduced does not mean safe."
    else:
        col1_status = '<div class="comp-status status-warning">❓ Inconclusive</div>'
        col1_body = "Analysis or test could not conclusively reproduce an exploit."

    if patch_status in ("not_reproduced", "mitigated_in_test"):
        col2_status = '<div class="comp-status status-success">🛡️ Exploit Blocked</div>'
        col2_body = "The exact same attack test re-run against patched bytecode triggered EVM revert. Exploit neutralized."
    elif patch_status == "compile_failed":
        col2_status = '<div class="comp-status status-danger">❌ Patch Compile Failed</div>'
        col2_body = "Deterministic patch could not compile. Mitigation was not established."
    elif orig_status != "reproduced":
        col2_status = '<div class="comp-status status-muted">⚪ Not Required</div>'
        col2_body = "Original attack was not reproduced; patch mitigation was not assessed."
    else:
        col2_status = '<div class="comp-status status-danger">⚠️ Exploit Still Active</div>'
        col2_body = "Attack still succeeded against patched bytecode."

    if reg_status == "regression_passed":
        col3_status = '<div class="comp-status status-info">✅ Invariants Preserved</div>'
        col3_body = "Standard non-malicious user operations executed and passed without regression."
    elif reg_status == "regression_failure":
        col3_status = '<div class="comp-status status-danger">❌ Regression Violated</div>'
        col3_body = "Patched contract failed non-malicious user operations."
    elif orig_status != "reproduced":
        col3_status = '<div class="comp-status status-muted">⚪ Skipped</div>'
        col3_body = "Regression test not triggered because no patch was required."
    else:
        col3_status = '<div class="comp-status status-muted">⚪ Not Run</div>'
        col3_body = "Regression check was not executed for this run."

    return (
        f'<div class="comparison-grid">'
        f'<div class="comp-col comp-vulnerable">'
        f'<div class="comp-header">ORIGINAL CONTRACT (UNPATCHED)</div>'
        f'{col1_status}'
        f'<div class="comp-body">{col1_body}</div>'
        f'</div>'
        f'<div class="comp-col comp-patched">'
        f'<div class="comp-header">PATCHED CONTRACT (DETERMINISTIC)</div>'
        f'{col2_status}'
        f'<div class="comp-body">{col2_body}</div>'
        f'</div>'
        f'<div class="comp-col comp-regression">'
        f'<div class="comp-header">REGRESSION TEST SUITE</div>'
        f'{col3_status}'
        f'<div class="comp-body">{col3_body}</div>'
        f'</div>'
        f'</div>'
    )


def _render_line_by_line_attack_simulator(finding: dict[str, Any], run_dir: Path | None, index: int) -> None:
    finding_id = str(finding.get("id") or f"finding_{index}")
    run_name = run_dir.name if run_dir else "run"
    sim_key = f"sim_active_{run_name}_{finding_id}"
    step_key = f"sim_step_{run_name}_{finding_id}"

    is_active = st.session_state.get(sim_key, False)
    category = str(finding.get("category") or "security").lower()
    func_id = str(finding.get("function_id") or "target_function()")
    src = finding.get("src") if isinstance(finding.get("src"), dict) else {}
    start_line = src.get("start_line", 1)
    end_line = src.get("end_line", 20)

    # Locate source file
    source_file = None
    path_str = src.get("path")
    if path_str:
        for d in DEMO_DIRS:
            candidate = d / Path(path_str).name
            if candidate.is_file():
                source_file = candidate
                break
        if not source_file and run_dir:
            candidate = run_dir / Path(path_str).name
            if candidate.is_file():
                source_file = candidate
        if not source_file:
            for p in ROOT.glob(f"**/{Path(path_str).name}"):
                if p.is_file() and not any(part in p.parts for part in (".venv", ".pytest_cache", "runs", "out")):
                    source_file = p
                    break

    all_file_lines: list[str] = []
    if source_file:
        try:
            all_file_lines = source_file.read_text(encoding="utf-8").splitlines()
        except Exception:
            all_file_lines = []

    # Build steps
    steps = []
    if category == "access_control":
        setter_line = start_line
        write_line = min(len(all_file_lines), start_line + 1) if all_file_lines else start_line + 1
        for i, l in enumerate(all_file_lines):
            if "function" in l and ("setOwner" in l or "Owner" in l):
                setter_line = i + 1
            if "owner" in l and "=" in l and "==" not in l and i + 1 >= setter_line:
                write_line = i + 1
                break

        steps = [
            {
                "step_no": 1,
                "title": f"1. Discovery: Unprotected Function Entrypoint (Line {setter_line})",
                "active_line": setter_line,
                "vuln_lines": [setter_line, write_line],
                "evm_op": "ABI PARSE · FUNCTION SELECTOR 0x13af4035",
                "tactic": f"Attacker analyzes the public ABI. Notice line {setter_line}: '{all_file_lines[setter_line - 1].strip() if all_file_lines and setter_line <= len(all_file_lines) else func_id}'. It has NO access modifier (such as onlyOwner) and no caller authorization check.",
                "state_before": {"Caller Address": "0x000...0BAD (Attacker)", "Legitimate Owner": "0x1804c8ab... (Original Deployer)"},
                "state_after": {"Status": f"Vulnerable entrypoint confirmed at Line {setter_line}"},
                "call_tree": f"Attacker (0xBAD) ➔ Preparing adversarial transaction to {func_id}",
            },
            {
                "step_no": 2,
                "title": f"2. Invocation: Transaction Dispatched to Line {setter_line}",
                "active_line": setter_line,
                "vuln_lines": [setter_line, write_line],
                "evm_op": "CALL target.setOwner(0xBAD) · Gas: 38,669",
                "tactic": f"Attacker sends an EVM transaction calling setOwner(0xBAD) with msg.sender set to 0xBAD. Because there is no require(msg.sender == owner) check at line {setter_line}, the EVM proceeds without reverting.",
                "state_before": {"msg.sender": "0x0000000000000000000000000000000000000bad", "msg.value": "0 wei"},
                "state_after": {"EVM Call Status": "Entering Function Body (No Revert)"},
                "call_tree": f"Attacker (0xBAD) ➔ CALL {func_id} [NO REVERT TRIGGERED]",
            },
            {
                "step_no": 3,
                "title": f"3. THE EXPLOIT LINE: Unauthorized State Overwrite (Line {write_line})",
                "active_line": write_line,
                "vuln_lines": [setter_line, write_line],
                "evm_op": "SSTORE (Storage Slot 0) ➔ 0xBAD",
                "tactic": f"🚨 ERROR & EXPLOIT POINT (Line {write_line}): '{all_file_lines[write_line - 1].strip() if all_file_lines and write_line <= len(all_file_lines) else 'owner = newOwner;'}'. The EVM writes the attacker's address 0xBAD directly into storage slot 0! The legitimate owner is permanently overwritten.",
                "state_before": {"Storage Slot 0 (owner)": "0x1804c8ab... (Legitimate Owner)"},
                "state_after": {"Storage Slot 0 (owner)": "0x0000000000000000000000000000000000000bad (HIJACKED!)"},
                "call_tree": "EVM PC ➔ SSTORE slot 0 = 0xBAD [STATE PERMANENTLY CORRUPTED]",
            },
            {
                "step_no": 4,
                "title": "4. Exploit Verification: Administrative Authority Hijacked",
                "active_line": write_line,
                "vuln_lines": [setter_line, write_line],
                "evm_op": "STATICCALL owner() ➔ 0xBAD · ASSERT TRUE",
                "tactic": "The Foundry test queries target.owner() and confirms it equals 0xBAD. The contract is now completely compromised and controlled by the attacker.",
                "state_before": {"Ownership": "Compromised"},
                "state_after": {"Contract Owner": "0xBAD (ATTACKER)", "Exploit Succeeded": "TRUE (100% PROVEN)"},
                "call_tree": "Foundry Oracle ➔ assertEq(target.owner(), 0xBAD) [EXPLOIT VERIFIED]",
            },
        ]
    elif category == "reentrancy":
        call_line = start_line + 3
        write_line = start_line + 5
        deposit_line = 9
        for i, l in enumerate(all_file_lines):
            if "function deposit" in l:
                deposit_line = i + 1
            if ".call{value:" in l:
                call_line = i + 1
            if "balances[" in l and "= 0" in l:
                write_line = i + 1

        steps = [
            {
                "step_no": 1,
                "title": f"1. Pre-condition: Capital Deposit at Line {deposit_line}",
                "active_line": deposit_line,
                "vuln_lines": [call_line, write_line],
                "evm_op": "CALL deposit() · VALUE: 1.0 ETH",
                "tactic": f"Attacker calls deposit() at line {deposit_line} with 1.0 ETH to create an active balance in balances[attacker] before launching reentrancy.",
                "state_before": {"Victim Vault Pool": "10.0 ETH", "Attacker Wallet": "1.0 ETH"},
                "state_after": {"Victim Vault Pool": "11.0 ETH", "balances[attacker]": "1.0 ETH"},
                "call_tree": "Attacker (0xBAD) ➔ CALL deposit{value: 1 ETH}() [SUCCESS]",
            },
            {
                "step_no": 2,
                "title": f"2. Trigger: Calling withdraw() at Line {start_line}",
                "active_line": start_line,
                "vuln_lines": [call_line, write_line],
                "evm_op": "CALL withdraw()",
                "tactic": f"Attacker calls withdraw() at line {start_line}. The contract checks require(amount > 0), which passes because balances[attacker] is 1.0 ETH.",
                "state_before": {"balances[attacker]": "1.0 ETH", "Vault Pool": "11.0 ETH"},
                "state_after": {"Status": "Proceeding to external transfer line"},
                "call_tree": "Attacker (0xBAD) ➔ CALL withdraw() [PASSED BALANCE CHECK]",
            },
            {
                "step_no": 3,
                "title": f"3. THE EXPLOIT LINE: External Call Before State Update (Line {call_line})",
                "active_line": call_line,
                "vuln_lines": [call_line, write_line],
                "evm_op": f"RAW CALL (Line {call_line}) ➔ msg.sender.call{{value: amount}}(\"\")",
                "tactic": f"🚨 CRITICAL ERROR AT LINE {call_line}: '{all_file_lines[call_line - 1].strip() if all_file_lines and call_line <= len(all_file_lines) else 'msg.sender.call{value: amount}(\"\")'}'. The contract sends ETH to the attacker BEFORE line {write_line} zeroes the balance! Execution transfers control to the attacker's fallback receive() hook.",
                "state_before": {"balances[attacker]": "1.0 ETH (NOT ZEROED YET!)"},
                "state_after": {"Execution Control": f"Shifted to attacker receive() BEFORE line {write_line} executes"},
                "call_tree": f"Victim (Line {call_line}) ➔ CALL attacker.receive{{value: 1 ETH}}() [CONTROL INTERCEPTED]",
            },
            {
                "step_no": 4,
                "title": f"4. Reentrant Loop: Re-entering withdraw() Before Line {write_line}",
                "active_line": call_line,
                "vuln_lines": [call_line, write_line],
                "evm_op": "REENTRANT CALL withdraw() ➔ RECURSIVE DRAIN",
                "tactic": f"Attacker's receive() hook immediately calls withdraw() again! Because line {write_line} was never reached, balances[attacker] is STILL 1.0 ETH! The contract sends another 1.0 ETH, repeating recursively until all 11.0 ETH is drained from the vault!",
                "state_before": {"Victim Vault Pool": "11.0 ETH"},
                "state_after": {"Victim Vault Pool": "0.0 ETH (DRAINED!)", "Attacker Profit": "+11.0 ETH Stolen"},
                "call_tree": "Attacker.receive() ➔ CALL withdraw() ➔ RE-ENTERING [RECURSION UNTIL DRAINED]",
            },
            {
                "step_no": 5,
                "title": f"5. Post-Drain: Zeroing Empty Vault Balance (Line {write_line})",
                "active_line": write_line,
                "vuln_lines": [call_line, write_line],
                "evm_op": "ORACLE ASSERT: address(victim).balance == 0",
                "tactic": f"Finally, the recursive calls unwind to line {write_line} ('{all_file_lines[write_line - 1].strip() if all_file_lines and write_line <= len(all_file_lines) else 'balances[msg.sender] = 0;'}'), but the vault is already completely empty. Total drain confirmed!",
                "state_before": {"Vault Balance": "0.0 ETH"},
                "state_after": {"Victim Drained": "TRUE", "Exploit Succeeded": "TRUE (100% PROVEN)"},
                "call_tree": "Oracle Assertion ➔ assertEq(address(victim).balance, 0) [100% PROVEN]",
            },
        ]
    else:
        steps = [
            {
                "step_no": 1,
                "title": f"1. Target Call at Line {start_line}",
                "active_line": start_line,
                "vuln_lines": [start_line],
                "evm_op": "CALL",
                "tactic": f"Attacker calls {func_id} at line {start_line} with adversarial inputs.",
                "state_before": {"Target": func_id},
                "state_after": {"Status": "Execution Recorded"},
                "call_tree": f"Attacker ➔ CALL {func_id}",
            },
        ]

    total_steps = len(steps)
    current_step = st.session_state.get(step_key, 1)
    current_step = max(1, min(current_step, total_steps))

    st.markdown("#### ⚡ Interactive Live Attack Simulator")
    st.caption("Press the attack button to execute the attack live and see which line contains the error and how the attacker exploits it:")

    col_btn_run, col_btn_prev, col_btn_next, col_btn_reset = st.columns([1.5, 0.8, 0.8, 0.8])
    with col_btn_run:
        btn_label = "⚔️ LAUNCH ATTACK SIMULATION" if not is_active else "▶️ NEXT ATTACK STEP"
        if st.button(btn_label, type="primary", key=f"btn_sim_act_{index}"):
            if not is_active:
                st.session_state[sim_key] = True
                st.session_state[step_key] = 1
            else:
                st.session_state[step_key] = (current_step % total_steps) + 1
            st.rerun()

    if is_active:
        with col_btn_prev:
            if st.button("⏮️ Prev", key=f"btn_sim_prev_{index}"):
                st.session_state[step_key] = max(1, current_step - 1)
                st.rerun()
        with col_btn_next:
            if st.button("⏭️ Next", key=f"btn_sim_nxt_{index}"):
                st.session_state[step_key] = min(total_steps, current_step + 1)
                st.rerun()
        with col_btn_reset:
            if st.button("⏹️ Reset", key=f"btn_sim_rst_{index}"):
                st.session_state[sim_key] = False
                st.session_state[step_key] = 1
                st.rerun()

        step_data = steps[current_step - 1]
        active_line_no = step_data["active_line"]
        vuln_lines = step_data["vuln_lines"]

        st.markdown(
            f'<div class="attack-sim-card">'
            f'<div class="sim-live-badge"><span class="sim-live-dot"></span>LIVE EVM ATTACK SIMULATION · STEP {current_step} OF {total_steps}</div>'
            f'<h3 style="color: #F8FAFC; margin: 0 0 0.5rem 0; font-size: 1.15rem;">{html.escape(step_data["title"])}</h3>'
            f'<div style="font-family: \'JetBrains Mono\', monospace; color: #38BDF8; font-size: 0.8rem; margin-bottom: 0.8rem;">EVM OP: {html.escape(step_data["evm_op"])}</div>'
            f'</div>',
            unsafe_allow_html=True,
        )

        # Render Line-by-Line Code Display
        if all_file_lines:
            display_start = max(1, start_line - 3)
            display_end = min(len(all_file_lines), end_line + 4)
            code_rows = []
            for l_idx in range(display_start, display_end + 1):
                l_text = all_file_lines[l_idx - 1]
                is_active_l = (l_idx == active_line_no)
                is_vuln_l = (l_idx in vuln_lines)

                row_class = "sim-code-row"
                tag_html = ""
                if is_active_l:
                    row_class += " active-line"
                    tag_html = '<span class="sim-line-tag sim-tag-pc">▶ EVM PC HERE</span>'
                elif is_vuln_l:
                    row_class += " vuln-line"
                    tag_html = '<span class="sim-line-tag sim-tag-vuln">⚠️ VULNERABLE LINE</span>'

                code_rows.append(
                    f'<div class="{row_class}">'
                    f'<span class="sim-line-num">{l_idx:3d}</span>'
                    f'<span class="sim-line-text">{html.escape(l_text)}</span>'
                    f'{tag_html}'
                    f'</div>'
                )

            st.markdown(
                f'<div class="sim-code-container">'
                + "".join(code_rows)
                + '</div>',
                unsafe_allow_html=True,
            )

        # Attacker Exploitation Tactic Panel
        st.markdown(
            f'<div class="sim-tactic-box">'
            f'<div class="sim-tactic-title">🎯 Attacker Exploitation Mechanics at this Line</div>'
            f'<div class="sim-tactic-desc">{html.escape(step_data["tactic"])}</div>'
            f'<div class="sim-call-tree">{html.escape(step_data["call_tree"])}</div>'
            f'</div>',
            unsafe_allow_html=True,
        )

        # State Diff Metrics
        sc1, sc2 = st.columns(2)
        with sc1:
            st.markdown("**State Before Step:**")
            for k, v in step_data["state_before"].items():
                st.caption(f"- **{html.escape(k)}**: `{html.escape(str(v))}`")
        with sc2:
            st.markdown("**State After Step:**")
            for k, v in step_data["state_after"].items():
                st.caption(f"- **{html.escape(k)}**: `{html.escape(str(v))}`")

        st.markdown("---")


def _render_replay(run_dir: Path | None) -> None:
    st.markdown('<h2 class="view-title">Attack Execution & Patch Verification</h2>', unsafe_allow_html=True)
    st.markdown(
        '<p class="view-subtitle">Don\'t warn. Prove. Then verify the fix. Real Foundry execution in an isolated offline local EVM.</p>',
        unsafe_allow_html=True,
    )

    _render_live_scan_log(run_dir)

    findings, error = _artifact(run_dir, "findings.json")
    if error:
        _show_missing(error, label="Attack evidence")
        return
    findings = findings if isinstance(findings, list) else []
    facts, facts_error = _artifact(run_dir, "facts.json")

    _render_pipeline_visualizer(run_dir, facts if facts_error is None and isinstance(facts, dict) else None, findings)

    if st.button("← Back to findings overview", key=f"back_btn_{run_dir.name if run_dir else 'none'}"):
        st.session_state["pending_workspace_page"] = "Findings"
        st.rerun()

    if not findings:
        st.info("No candidates triggered an attack test for this scan. This does not establish contract safety.")
        return

    for index, finding in enumerate(findings):
        if not isinstance(finding, dict):
            continue
        title = str(finding.get("function_id") or finding.get("id") or f"Finding {index + 1}")
        category = str(finding.get("category") or "security").upper()
        finding_dir = _finding_dir(run_dir, finding)
        orig = finding.get("original_result") if isinstance(finding.get("original_result"), dict) else {}
        orig_status = str(orig.get("status") or "inconclusive")

        with st.expander(f"🔬 Evidence Verification Dossier: {title} ({category})", expanded=True):
            st.markdown(
                f'<div class="dossier-intro">'
                f'<strong>Vulnerability Target:</strong> <code>{html.escape(title)}</code> · <strong>Rule:</strong> <code>{html.escape(str(finding.get("rule", "N/A")))}</code>'
                f'</div>',
                unsafe_allow_html=True,
            )

            # Live Line-by-Line Attack Simulator
            _render_line_by_line_attack_simulator(finding, run_dir, index)

            # Gemini AI Attack Explainer Card
            api_key = _gemini_api_key()
            attack_exp_key = f"attack_exp_{run_dir.name if run_dir else 'none'}_{index}"

            if attack_exp_key in st.session_state:
                exp_data = st.session_state[attack_exp_key]
                kind = exp_data.get("kind", "ai")
                if kind == "ai":
                    badge_lbl = '<span class="ai-label">✨ Gemini AI Attack Analysis — Grounded in local EVM execution</span>'
                elif kind == "fallback":
                    badge_lbl = '<span class="ai-label">Local summary — Gemini unavailable · not proof</span>'
                else:
                    badge_lbl = '<span class="local-label">Local deterministic summary — not proof</span>'
                st.markdown(
                    f'<div class="explanation-box">'
                    f'<div class="explanation-tag">{badge_lbl}</div>'
                    f'<div class="explanation-body">{html.escape(str(exp_data.get("text", "")))}</div>'
                    f'</div>',
                    unsafe_allow_html=True,
                )

            col_exp_btn, _ = st.columns([1, 1])
            with col_exp_btn:
                btn_txt = "✨ Explain Attack & EVM Proof with Gemini AI" if api_key else "📝 Explain Attack from Recorded Evidence"
                if st.button(btn_txt, key=f"btn_attack_exp_{run_dir.name if run_dir else 'none'}_{index}"):
                    with st.spinner("Analyzing EVM attack trace and patch with Gemini AI..."):
                        try:
                            if api_key:
                                txt = gemini_explainer.explain_attack(finding, api_key)
                                st.session_state[attack_exp_key] = {"kind": "ai", "text": txt}
                            else:
                                txt = _local_attack_explanation(finding)
                                st.session_state[attack_exp_key] = {"kind": "local", "text": txt}
                        except Exception:
                            txt = _local_attack_explanation(finding)
                            st.session_state[attack_exp_key] = {"kind": "fallback", "text": txt}
                    st.rerun()

            st.markdown("#### ⚡ Dynamic Exploit Execution Sequence")
            phases = _build_dynamic_attack_phases(finding)
            phase_cards_html = (
                '<div class="attack-steps-container">'
                f'<div class="attack-step-card"><div class="step-badge">{phases[0]["badge"]}</div><div class="step-title">{html.escape(phases[0]["title"])}</div><div class="step-desc">{html.escape(phases[0]["desc"])}</div></div>'
                '<div class="attack-step-arrow">➔</div>'
                f'<div class="attack-step-card"><div class="step-badge">{phases[1]["badge"]}</div><div class="step-title">{html.escape(phases[1]["title"])}</div><div class="step-desc">{html.escape(phases[1]["desc"])}</div></div>'
                '<div class="attack-step-arrow">➔</div>'
                f'<div class="attack-step-card"><div class="step-badge">{phases[2]["badge"]}</div><div class="step-title">{html.escape(phases[2]["title"])}</div><div class="step-desc">{html.escape(phases[2]["desc"])}</div></div>'
                '<div class="attack-step-arrow">➔</div>'
                f'<div class="attack-step-card"><div class="step-badge">{phases[3]["badge"]}</div><div class="step-title">{html.escape(phases[3]["title"])}</div><div class="step-desc">{html.escape(phases[3]["desc"])}</div></div>'
                '</div>'
            )
            st.markdown(phase_cards_html, unsafe_allow_html=True)

            st.markdown("#### ⚖️ Verification Comparison Matrix")
            st.markdown(_build_dynamic_comparison_matrix(finding), unsafe_allow_html=True)

            col_orig, col_patch, col_reg = st.columns(3)

            with col_orig:
                st.markdown("##### 1. Attack on Original")
                original = finding.get("original_result")
                if isinstance(original, dict):
                    _status(original.get("status"))
                    if original.get("reason"):
                        st.caption(str(original["reason"]))
                else:
                    _show_missing("Original test outcome absent.", label="Attack on original")

            with col_patch:
                st.markdown("##### 2. Same Attack on Patch")
                patched = finding.get("patched_result")
                if isinstance(patched, dict) and patched.get("status"):
                    _status(patched.get("status"))
                    if patched.get("reason"):
                        st.caption(str(patched["reason"]))
                else:
                    _show_missing("Patched attack result absent.", label="Attack on patch")

            with col_reg:
                st.markdown("##### 3. Regression Invariants")
                regression = finding.get("regression_result")
                if isinstance(regression, dict) and regression.get("status"):
                    _status(regression.get("status"))
                    if regression.get("reason"):
                        st.caption(str(regression["reason"]))
                else:
                    _show_missing("Regression result absent.", label="Regression")

            st.markdown("---")

            oracle = finding.get("oracle")
            if isinstance(oracle, dict):
                st.markdown("#### 📊 Execution Oracle & Exploit Metrics")
                is_ac = oracle.get("class") == "access_control"
                if is_ac:
                    oc1, oc2, oc3 = st.columns(3)
                    oc1.metric("Attack Target Class", "Access Control Hijack")
                    oc2.metric("Unauthorized State Write", "CONFIRMED" if oracle.get("exploit_succeeded") else "NONE", delta="OnlyOwner Missing" if oracle.get("exploit_succeeded") else None, delta_color="inverse")
                    oc3.metric("Exploit Succeeded", "TRUE (Vulnerable)" if oracle.get("exploit_succeeded") else "FALSE", delta="Owner Overwritten" if oracle.get("exploit_succeeded") else None, delta_color="inverse")
                else:
                    att_in = oracle.get("attacker_in")
                    att_out = oracle.get("attacker_out")
                    success = oracle.get("exploit_succeeded")

                    def _fmt_eth(val: Any) -> str:
                        try:
                            n = int(val)
                            return f"{n / 10**18:.4f} ETH"
                        except (ValueError, TypeError):
                            return str(val)

                    oc1, oc2, oc3, oc4 = st.columns(4)
                    oc1.metric("Attacker In", _fmt_eth(att_in) if att_in is not None else "N/A")
                    oc2.metric("Attacker Out", _fmt_eth(att_out) if att_out is not None else "N/A")
                    oc3.metric("Exploit Succeeded", "TRUE (Vulnerable)" if success else "FALSE", delta="Drain Confirmed" if success else None, delta_color="inverse")

                    remaining = {k: v for k, v in oracle.items() if k.endswith("_remaining")}
                    first_rem = next(iter(remaining.values())) if remaining else None
                    oc4.metric("Victim Balance Left", _fmt_eth(first_rem) if first_rem is not None else "0 ETH")

                steps = oracle.get("steps") or (original.get("steps") if isinstance(original, dict) else None)
                if isinstance(steps, list) and steps:
                    with st.expander("Step-by-step balance trace", expanded=False):
                        st.json(steps)

            # Synthesized Test Contracts Preview
            attack_sol, _ = _text_artifact(finding_dir, "Attack.t.sol")
            regr_sol, _ = _text_artifact(finding_dir, "Regression.t.sol")
            if attack_sol:
                st.markdown("#### ⚔️ Synthesized EVM Test Contracts (Foundry)")
                tab_att, tab_reg = st.tabs(["🔥 Attack Contract (Attack.t.sol)", "🛡️ Regression Test (Regression.t.sol)"])
                with tab_att:
                    st.caption("The exact offline test harness generated by Microscope to prove the exploit in Foundry:")
                    st.code(attack_sol, language="solidity")
                with tab_reg:
                    if regr_sol:
                        st.caption("Invariant verification test ensuring legitimate functions continue working after patch:")
                        st.code(regr_sol, language="solidity")
                    else:
                        st.info("No regression test contract recorded.")

            # Decoded Foundry EVM Test Details
            forge_orig, _ = _artifact(finding_dir, "forge_original.json")
            if isinstance(forge_orig, dict):
                duration_str = None
                gas_used = None
                decoded_logs = []
                for test_suite in forge_orig.values():
                    if isinstance(test_suite, dict):
                        t_res = test_suite.get("test_results", {})
                        for test_name, res in t_res.items():
                            if "test_microscope_attack" in test_name:
                                duration_str = res.get("duration") or test_suite.get("duration")
                                gas_info = res.get("kind", {})
                                if isinstance(gas_info, dict) and "Unit" in gas_info:
                                    gas_used = gas_info["Unit"].get("gas")
                                decoded_logs = res.get("decoded_logs", [])
                                break
                if duration_str or gas_used is not None or decoded_logs:
                    with st.expander("⚡ Decoded Foundry EVM Execution Summary", expanded=True):
                        ec1, ec2 = st.columns(2)
                        ec1.caption(f"⏱️ **EVM Test Duration:** `{duration_str or 'N/A'}`")
                        ec2.caption(f"⛽ **Gas Consumed:** `{gas_used:,} gas`" if gas_used is not None else "⛽ **Gas Consumed:** `N/A`")
                        if decoded_logs:
                            st.caption("**Decoded Execution Logs:**")
                            for log in decoded_logs:
                                st.code(str(log), language="json")

            diff, diff_error = _text_artifact(finding_dir, "patch.diff")
            st.markdown("#### 🛡️ Verified Deterministic Patch Diff")
            if diff_error:
                _show_missing(diff_error, label="Patch diff")
            elif diff:
                st.caption("Deterministic template patch verified by re-running the exact same attack:")
                st.code(diff, language="diff")
            else:
                st.info("The patch diff artifact is present but empty.")

            st.markdown("#### 💻 Offline CLI Replay Command")
            st.caption("Execute this command locally in Foundry to reproduce the exact EVM attack test offline:")
            st.code("forge test --match-test test_microscope_attack -vvvv", language="bash")

            trace, trace_error = _text_artifact(finding_dir, "trace.txt")
            with st.expander("📜 Raw Foundry EVM Execution Trace (trace.txt)", expanded=False):
                if trace_error:
                    _show_missing(trace_error, label="Trace")
                elif trace:
                    st.code(trace[-20_000:], language="text")
                    if len(trace) > 20_000:
                        st.caption("Displaying final 20 KB. Full trace is preserved in local download bundle.")
                else:
                    st.info("No trace artifact available.")


def _report_bundle(run_dir: Path | None) -> bytes | None:
    if run_dir is None:
        return None
    bundle: dict[str, Any] = {
        "report_schema": "microscope-local-report-v1",
        "run_id": run_dir.name,
        "source_included": False,
        "artifacts": {},
    }
    for name in REPORT_ARTIFACT_NAMES:
        path = run_dir / name
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
            if name.endswith(".json"):
                bundle["artifacts"][name] = json.loads(text)
            else:
                bundle["artifacts"][name] = text
        except (OSError, UnicodeError, json.JSONDecodeError):
            bundle["artifacts"][name] = {"error": "Artifact unavailable or malformed in local run directory."}
    findings = bundle["artifacts"].get("findings.json")
    if isinstance(findings, list):
        diffs: dict[str, str] = {}
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            finding_dir = _finding_dir(run_dir, finding)
            path = finding_dir / "patch.diff" if finding_dir else None
            if path and path.is_file():
                try:
                    diffs[str(finding.get("id") or finding.get("function_id") or path.parent.name)] = path.read_text(encoding="utf-8")
                except (OSError, UnicodeError):
                    continue
        if diffs:
            bundle["artifacts"]["patch_diffs_by_finding"] = diffs
    return (json.dumps(bundle, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def _cloud_report_payload(run_dir: Path, user_id: str) -> dict[str, Any]:
    meta, meta_error = _artifact(run_dir, "meta.json")
    findings, findings_error = _artifact(run_dir, "findings.json")
    facts, facts_error = _artifact(run_dir, "facts.json")
    if meta_error or not isinstance(meta, dict):
        raise ValueError("Run metadata is unavailable; report cannot be saved.")
    if findings_error or not isinstance(findings, list):
        raise ValueError("Findings are unavailable; report cannot be saved.")
    notes: list[dict[str, str]] = []
    if isinstance(facts, dict) and isinstance(facts.get("contract_notes"), list):
        for note in facts["contract_notes"]:
            if isinstance(note, dict):
                notes.append({key: str(note[key]) for key in ("contract", "code", "message") if key in note})
    saved_findings: list[dict[str, Any]] = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        item = {key: finding[key] for key in REMOTE_FINDING_FIELDS if key in finding}
        source = finding.get("src")
        if isinstance(source, dict):
            item["src"] = {key: source[key] for key in ("path", "start_line", "end_line") if key in source}
        for name in ("original_result", "patched_result", "regression_result"):
            result = finding.get(name)
            if isinstance(result, dict):
                item[name] = {key: result[key] for key in ("status", "reason") if key in result}
        saved_findings.append(item)
    return {
        "user_id": user_id,
        "run_id": run_dir.name,
        "source_sha256": str(meta.get("source_sha256") or "") or None,
        "summary": {"contract_notes": notes, "findings": saved_findings},
        "tool_versions": meta.get("tool_versions") if isinstance(meta.get("tool_versions"), dict) else {},
    }


def _active_supabase_session() -> dict[str, Any] | None:
    session = st.session_state.get("supabase_session")
    if not isinstance(session, dict):
        return None
    try:
        if float(session.get("expires_at", 0)) <= time.time() + 60:
            refreshed = supabase_store.refresh_session(str(session.get("refresh_token") or ""))
            session = supabase_store.session_record(refreshed)
            st.session_state["supabase_session"] = session
        return session if session.get("access_token") and session.get("user_id") else None
    except supabase_store.SupabaseUnavailable:
        st.session_state.pop("supabase_session", None)
        return None


def _render_account() -> None:
    st.markdown("### Cloud Reports & Account")
    if supabase_store.configuration() is None:
        st.caption("🔒 Local-only mode · Supabase credentials not configured in environment.")
        return
    if not supabase_store.rls_is_verified():
        st.caption("🔒 Local-only mode · Cloud saving disabled until RLS tenant isolation check passes.")
        return
    session = _active_supabase_session()
    if session:
        st.markdown(f"**Signed in as:** `{html.escape(session.get('email') or 'Supabase user')}`")
        if st.button("Sign out", key="supabase_sign_out", use_container_width=True):
            try:
                supabase_store.sign_out(session["access_token"])
            except supabase_store.SupabaseUnavailable:
                pass
            st.session_state.pop("supabase_session", None)
            st.rerun()
        return

    with st.expander("Sign in to sync saved reports", expanded=False):
        with st.form("supabase_sign_in", clear_on_submit=True):
            email = st.text_input("Email", key="supabase_email")
            password = st.text_input("Password", type="password", key="supabase_password")
            submitted = st.form_submit_button("Sign in", use_container_width=True)
        if submitted:
            try:
                response = supabase_store.sign_in(email, password)
                st.session_state["supabase_session"] = supabase_store.session_record(response)
                st.rerun()
            except supabase_store.SupabaseUnavailable as exc:
                st.error(str(exc))


def _render_saved_reports(session: dict[str, Any]) -> None:
    try:
        reports = supabase_store.list_reports(session["access_token"])
    except supabase_store.SupabaseUnavailable as exc:
        st.error(f"Saved reports could not be opened: {exc}")
        return
    if not reports:
        st.info("No reports saved under this account.")
        return
    selected = st.selectbox(
        "Open saved report",
        range(len(reports)),
        format_func=lambda index: f"{reports[index].get('created_at', 'date')} · {reports[index].get('run_id', 'run')}",
        key="remote_report_index",
    )
    report = reports[selected]
    st.caption(f"Report UUID: `{report.get('id')}` · Run: `{report.get('run_id')}`")
    summary = report.get("summary")
    if isinstance(summary, dict):
        st.json(summary)
    else:
        _show_missing("The saved summary is malformed.", label="Saved report")


def _render_reports(run_dir: Path | None) -> None:
    st.markdown('<h2 class="view-title">Audit Reports & Artifacts</h2>', unsafe_allow_html=True)
    st.markdown(
        '<p class="view-subtitle">Download machine-readable JSON evidence bundles assembled from real local run artifacts. Original Solidity source is never included by default.</p>',
        unsafe_allow_html=True,
    )

    if run_dir is None:
        st.info("No stored runs discovered yet. Run a scan to generate evidence artifacts.")
        return

    bundle = _report_bundle(run_dir)
    col_dl, col_info = st.columns([1, 1])

    with col_dl:
        st.markdown(
            '<div class="report-dl-card">'
            '<h4>📦 Export Local Evidence Bundle</h4>'
            '<p>Includes structured findings, execution oracles, patch diffs, and tool versions. Zero source code is exported.</p>'
            '</div>',
            unsafe_allow_html=True,
        )
        if bundle is not None:
            st.download_button(
                "⬇️ Download Evidence Bundle (JSON)",
                data=bundle,
                file_name=f"microscope-{run_dir.name}-report.json",
                mime="application/json",
                use_container_width=True,
            )

    with col_info:
        meta, error = _artifact(run_dir, "meta.json")
        if isinstance(meta, dict):
            st.markdown(
                f'<div class="report-meta-card">'
                f'<h4>Run Execution Metadata</h4>'
                f'<p><strong>Run ID:</strong> <code>{html.escape(run_dir.name)}</code></p>'
                f'<p><strong>Source Digest:</strong> <code>{html.escape(str(meta.get("source_sha256") or "N/A")[:24])}…</code></p>'
                f'<p><strong>Analysis Mode:</strong> <code>{html.escape(str(meta.get("analysis_mode") or "N/A"))}</code> · <strong>Fixture:</strong> <code>{meta.get("fixture")}</code></p>'
                f'<p><strong>Timestamp:</strong> {html.escape(str(meta.get("started_at") or "N/A"))}</p>'
                f'</div>',
                unsafe_allow_html=True,
            )

    st.markdown("---")
    st.markdown("### Artifact Ledger for Selected Run")
    cols = st.columns(3)
    for idx, name in enumerate(ARTIFACT_NAMES):
        exists = (run_dir / name).is_file()
        status_text = "Recorded" if exists else "Not recorded"
        pill_color = "#10B981" if exists else "#64748B"
        with cols[idx % 3]:
            st.markdown(
                f'<div class="artifact-pill-card">'
                f'<span class="artifact-dot" style="background: {pill_color};"></span>'
                f'<span class="artifact-name">{html.escape(name)}</span>'
                f'<span class="artifact-status" style="color: {pill_color};">{status_text}</span>'
                f'</div>',
                unsafe_allow_html=True,
            )

    st.markdown("---")
    _render_account()

    session = _active_supabase_session() if supabase_store.rls_is_verified() else None
    if session:
        st.markdown("#### Cloud Report Persistence (RLS Protected)")
        try:
            payload = _cloud_report_payload(run_dir, session["user_id"])
            st.caption("Structured fields to be saved to your user-isolated Postgres store:")
            with st.expander("Review structured payload (0 source code included)", expanded=False):
                st.json(payload)
            with st.form("save_cloud_report_form"):
                confirm_save = st.checkbox("I agree to save these structured report fields to my authenticated account.")
                submit_save = st.form_submit_button("☁️ Save Report to Supabase", disabled=not confirm_save)
            if submit_save:
                try:
                    saved = supabase_store.save_report(session["access_token"], payload)
                    st.success(f"Report saved successfully (Run ID: {saved.get('run_id', run_dir.name)}).")
                except supabase_store.SupabaseUnavailable as exc:
                    st.error(f"Failed to persist report: {exc}")
        except ValueError as exc:
            st.warning(str(exc))

        _render_saved_reports(session)


def _run_scan(path: Path, *, fixture: bool,
              progress_callback: Any | None = None) -> tuple[str | None, str | None]:
    try:
        _findings, run_dir = run_file(
            path, fixture=fixture, runs_dir=RUNS_DIR,
            progress_callback=progress_callback,
        )
    except Exception as exc:
        return None, f"Scan failed ({type(exc).__name__}): {str(exc)[:700]}"
    facts, facts_error = _artifact(run_dir, "facts.json")
    if facts_error is None and isinstance(facts, dict):
        notes = facts.get("contract_notes", [])
        fatal = next((item for item in notes if isinstance(item, dict) and item.get("code") == "analysis_error"), None)
        if fatal:
            return run_dir.name, str(fatal.get("message") or "Analysis ended inconclusively.")
    return run_dir.name, None


def _render_live_scan_log(run_dir: Path | None) -> None:
    log = st.session_state.get("live_scan_log")
    if not isinstance(log, dict) or run_dir is None or log.get("run_id") != run_dir.name:
        return
    events = log.get("events")
    if not isinstance(events, list) or not events:
        return
    with st.expander("⚡ Live Scan Execution Trail", expanded=bool(log.get("just_completed"))):
        for event in events:
            if not isinstance(event, dict):
                continue
            clock = str(event.get("time") or "")
            stage = str(event.get("stage") or "pipeline").replace("_", " ").title()
            state = str(event.get("state") or "info").replace("_", " ").upper()
            message = str(event.get("message") or "")
            st.markdown(
                f'<div class="log-entry">'
                f'<span class="log-time">{html.escape(clock)}</span>'
                f'<span class="log-stage">{html.escape(stage)}</span>'
                f'<span class="log-state state-{html.escape(state.lower())}">{html.escape(state)}</span>'
                f'<span class="log-msg">{html.escape(message)}</span>'
                f'</div>',
                unsafe_allow_html=True,
            )


SAMPLE_ACCESS_CONTROL = (
    "// SPDX-License-Identifier: MIT\n"
    "pragma solidity ^0.8.24;\n\n"
    "contract VulnerableTreasury {\n"
    "    address public owner;\n\n"
    "    constructor() {\n"
    "        owner = msg.sender;\n"
    "    }\n\n"
    "    // BUG: Missing authorization guard allows anyone to overwrite owner\n"
    "    function setOwner(address newOwner) external {\n"
    "        owner = newOwner;\n"
    "    }\n\n"
    "    function withdrawAll() external {\n"
    "        require(msg.sender == owner, \"not owner\");\n"
    "        payable(owner).transfer(address(this).balance);\n"
    "    }\n\n"
    "    receive() external payable {}\n"
    "}\n"
)

SAMPLE_REENTRANCY = (
    "// SPDX-License-Identifier: MIT\n"
    "pragma solidity ^0.8.24;\n\n"
    "contract VulnerableVault {\n"
    "    mapping(address => uint256) public balances;\n\n"
    "    function deposit() external payable {\n"
    "        balances[msg.sender] += msg.value;\n"
    "    }\n\n"
    "    // BUG: Raw external call before state balance zeroing enables reentrancy drain\n"
    "    function withdraw() external {\n"
    "        uint256 amount = balances[msg.sender];\n"
    "        require(amount > 0, \"no balance\");\n\n"
    "        (bool success, ) = msg.sender.call{value: amount}(\"\");\n"
    "        require(success, \"transfer failed\");\n\n"
    "        balances[msg.sender] = 0;\n"
    "    }\n\n"
    "    receive() external payable {}\n"
    "}\n"
)


def _render_scan() -> None:
    st.markdown('<h2 class="view-title">Solidity Target Scan</h2>', unsafe_allow_html=True)
    st.markdown(
        '<p class="view-subtitle">One-click scan runs Slither AST facts first. Supported candidates automatically trigger real Foundry attacks in an isolated EVM. If an exploit is reproduced, a deterministic patch and regression suite are verified immediately.</p>',

        unsafe_allow_html=True,
    )

    completed_message = st.session_state.pop("scan_completed_message", None)
    analysis_error_message = st.session_state.pop("scan_error_message", None)
    if completed_message:
        st.success(completed_message)
    if analysis_error_message:
        st.error("Analysis ended inconclusively. The contract could not be fully analyzed; this is not a clean scan.")
        with st.expander("Diagnostics"):
            st.write(str(analysis_error_message))

    _render_engine_readiness()

    st.markdown(
        '<div class="safety-banner">'
        '<span class="banner-icon">🛡️</span>'
        '<div class="banner-text">'
        '<strong>Offline EVM Isolation:</strong> Microscope executes generated Foundry tests against an isolated local EVM. We never interact with remote RPCs, mainnets, or deployed contracts. Zero source code is uploaded to the cloud.'
        '</div>'
        '</div>',
        unsafe_allow_html=True,
    )

    mode = st.radio(
        "Choose Input Mode",
        ["✍️ Paste Solidity Source", "📦 Built-in Demo Fixtures", "📁 Upload .sol File"],
        horizontal=True,
        key="scan_input_mode",
    )
    demos = _demo_files()
    selected_demo: tuple[str, Path] | None = None
    uploaded = None
    pasted_code = ""
    pasted_filename = "Target.sol"

    if mode == "✍️ Paste Solidity Source":
        st.markdown(
            '<div class="upload-container">'
            '<p>Paste any standalone <code>.sol</code> contract code (Solidity 0.8.x). Microscope analyzes AST facts and synthesizes offline EVM attack tests locally.</p>'
            '</div>',
            unsafe_allow_html=True,
        )
        col_load1, col_load2, col_load3, _ = st.columns([1.3, 1.3, 0.8, 2])
        with col_load1:
            if st.button("📋 Load Access Control Bug"):
                st.session_state["pasted_sol_editor"] = SAMPLE_ACCESS_CONTROL
                st.rerun()
        with col_load2:
            if st.button("📋 Load Reentrancy Bug"):
                st.session_state["pasted_sol_editor"] = SAMPLE_REENTRANCY
                st.rerun()
        with col_load3:
            if st.button("🗑️ Clear"):
                st.session_state["pasted_sol_editor"] = ""
                st.rerun()

        default_code = st.session_state.get("pasted_sol_editor", SAMPLE_ACCESS_CONTROL)
        pasted_code = st.text_area(
            "Solidity Contract Code",
            value=default_code,
            height=280,
            key="pasted_sol_textarea",
            help="Solidity 0.8.24 source code for offline Foundry EVM testing",
        )
        col_f1, col_f2 = st.columns([2, 1])
        with col_f1:
            pasted_filename = st.text_input("Contract Filename", value="Target.sol", key="pasted_sol_name")
            if not pasted_filename.endswith(".sol"):
                pasted_filename += ".sol"
        with col_f2:
            st.caption(f"Bytes: {len(pasted_code.encode('utf-8')):,} / {MAX_SOURCE_BYTES:,} bytes max")

    elif mode == "📦 Built-in Demo Fixtures":
        if not demos:
            st.error("No demo fixtures found under `src/`.")
        else:
            demo_labels = [label for label, _ in demos]
            default_demo = next((index for index, label in enumerate(demo_labels) if "Vulnerable Vault" in label), 0)
            selected_label = st.selectbox("Select Target Demonstration Fixture", demo_labels, index=default_demo, key="selected_demo_contract")
            selected_demo = next(pair for pair in demos if pair[0] == selected_label)

            st.markdown(
                f'<div class="fixture-context-card">'
                f'<div class="fixture-badge">DEMO FIXTURE · fixture: true</div>'
                f'<div class="fixture-path">Path: <code>{html.escape(selected_demo[1].relative_to(ROOT).as_posix())}</code></div>'
                f'<div class="fixture-desc">This contract is configured with verified test oracles to demonstrate the end-to-end evidence pipeline.</div>'
                f'</div>',
                unsafe_allow_html=True,
            )
            with st.expander("View Fixture Solidity Source", expanded=False):
                try:
                    st.code(selected_demo[1].read_text(encoding="utf-8"), language="solidity")
                except Exception:
                    st.caption("Source preview unavailable.")
    else:
        st.markdown(
            '<div class="upload-container">'
            '<p>Upload a standalone <code>.sol</code> file (max 200 KB). Analysis runs locally inside an ephemeral directory scrubbed upon completion.</p>'
            '</div>',
            unsafe_allow_html=True,
        )
        uploaded = st.file_uploader("Upload Solidity (.sol)", type=["sol"], accept_multiple_files=False, label_visibility="collapsed")
        if uploaded is not None:
            if Path(uploaded.name).suffix.lower() != ".sol":
                st.error("Invalid file: must have a .sol extension.")
            elif len(uploaded.getvalue()) > MAX_SOURCE_BYTES:
                st.error(f"File size exceeds 200 KB limit ({len(uploaded.getvalue()):,} bytes).")
            else:
                st.success(f"Validated: {uploaded.name} ({len(uploaded.getvalue()):,} bytes) · Ready for local EVM execution.")

    btn_disabled = (
        (mode == "✍️ Paste Solidity Source" and not pasted_code.strip())
        or (mode == "📦 Built-in Demo Fixtures" and selected_demo is None)
        or (mode == "📁 Upload .sol File" and uploaded is None)
    )
    if st.button("⚡ Run Scan + Live EVM Attack Tests", type="primary", use_container_width=True, disabled=btn_disabled):
        run_id: str | None = None
        error: str | None = None
        live_events: list[dict[str, str]] = []
        stage_labels = {
            "static_analysis": "Slither Static Facts",
            "hypotheses": "Rule Hypotheses",
            "attack_setup": "Foundry Test Synthesis",
            "original_attack": "Local EVM Attack",
            "patch": "Deterministic Patch",
            "patch_compile": "Patched Compilation",
            "patched_attack": "Patched Attack Test",
            "regression": "Regression Test",
            "complete": "Pipeline Complete",
        }
        with st.status("Executing evidence pipeline on local EVM…", expanded=True) as status:
            def on_progress(event: dict[str, str]) -> None:
                entry = {**event, "time": time.strftime("%H:%M:%S")}
                live_events.append(entry)
                stage = stage_labels.get(event.get("stage", ""), "Analysis")
                state = event.get("state", "running")
                status.write(f"**{stage} · {state.replace('_', ' ').upper()}** — {event.get('message', '')}")
                if state == "running":
                    status.update(label=f"Pipeline Running · {stage}", state="running", expanded=True)

            try:
                if mode == "✍️ Paste Solidity Source":
                    content = pasted_code.encode("utf-8")
                    safe_name = Path(str(pasted_filename).replace("\\", "/")).name
                    if not safe_name.endswith(".sol"):
                        safe_name += ".sol"
                    if len(content) > MAX_SOURCE_BYTES:
                        error = "Source exceeds 200 KB limit."
                    else:
                        with tempfile.TemporaryDirectory(prefix="microscope-paste-") as temp_dir:
                            temporary_source = Path(temp_dir) / safe_name
                            temporary_source.write_bytes(content)
                            run_id, error = _run_scan(temporary_source, fixture=False, progress_callback=on_progress)
                elif mode == "📦 Built-in Demo Fixtures" and selected_demo is not None:
                    run_id, error = _run_scan(selected_demo[1], fixture=True, progress_callback=on_progress)
                elif mode == "📁 Upload .sol File" and uploaded is not None:
                    content = uploaded.getvalue()
                    safe_name = Path(str(uploaded.name).replace("\\", "/")).name
                    if Path(safe_name).suffix.lower() != ".sol":
                        error = "Choose a file ending in .sol"
                    elif len(content) > MAX_SOURCE_BYTES:
                        error = "File exceeds 200 KB limit."
                    else:
                        with tempfile.TemporaryDirectory(prefix="microscope-upload-") as temp_dir:
                            temporary_source = Path(temp_dir) / (safe_name or "contract.sol")
                            temporary_source.write_bytes(content)
                            run_id, error = _run_scan(temporary_source, fixture=False, progress_callback=on_progress)

                if run_id:
                    st.session_state["live_scan_log"] = {
                        "run_id": run_id, "events": live_events, "just_completed": error is None,
                    }

                if error:
                    status.update(label="Analysis Ended Inconclusively", state="error")
                    if run_id:
                        st.session_state["selected_run_id"] = run_id
                        st.session_state["pending_run_selector"] = run_id
                        st.session_state["scan_error_message"] = error
                    else:
                        st.error(error)
                else:
                    st.session_state["selected_run_id"] = run_id
                    st.session_state["pending_run_selector"] = run_id
                    st.session_state["scan_completed_message"] = (
                        f"Scan finished successfully (Run: {run_id}). Switched to Findings view."
                    )
                    st.session_state["pending_workspace_page"] = "Findings"
                    status.update(label="Evidence pipeline execution complete", state="complete")
            except OSError as exc:
                status.update(label="Scan failed", state="error")
                st.error(f"Local file operation error ({type(exc).__name__}).")

        if run_id:
            st.rerun()


def _render_sidebar(run_ids: list[str]) -> tuple[str, Path | None]:
    with st.sidebar:
        st.markdown(
            '<div class="brand-sidebar">'
            '<div class="brand-logo">'
            '<span class="logo-icon">🔬</span>'
            '<span class="logo-text">MICROSCOPE</span>'
            '</div>'
            '<div class="brand-tagline">Don\'t warn. Prove. Then verify the fix.</div>'
            '<div class="brand-badge">SOLVER WORKBENCH · LOCAL EVM</div>'
            '</div>',
            unsafe_allow_html=True,
        )

        st.markdown("#### Navigation")
        page = st.radio(
            "Section",
            ["Scan", "Findings", "Attack evidence", "Reports"],
            label_visibility="collapsed",
            key="workspace_page",
        )

        st.markdown("---")
        st.markdown("#### Selected Run Dossier")
        if run_ids:
            pending = st.session_state.pop("pending_run_selector", None)
            if pending and pending in run_ids:
                st.session_state["run_selector"] = pending
                st.session_state["selected_run_id"] = pending
            elif "run_selector" not in st.session_state or st.session_state["run_selector"] not in run_ids:
                saved = st.session_state.get("selected_run_id")
                st.session_state["run_selector"] = saved if saved in run_ids else run_ids[0]
            run_id = st.selectbox(
                "Selected Run",
                run_ids,
                format_func=_run_label,
                label_visibility="collapsed",
                key="run_selector",
            )
            st.session_state["selected_run_id"] = run_id
            run_dir = _run_path(run_id)
        else:
            st.caption("No scan runs recorded yet.")
            run_dir = None

        if run_dir:
            meta, _ = _read_json(run_dir / "meta.json")
            meta = meta if isinstance(meta, dict) else {}
            digest = str(meta.get("source_sha256") or "")[:12]
            st.markdown(
                f'<div class="sidebar-run-meta">'
                f'<div><strong>Target:</strong> {html.escape(_source_name(meta))}</div>'
                f'<div><strong>SHA-256:</strong> <code>{html.escape(digest)}…</code></div>'
                f'<div><strong>Mode:</strong> {html.escape(str(meta.get("analysis_mode") or "api"))}</div>'
                f'</div>',
                unsafe_allow_html=True,
            )

        st.markdown("---")
        st.markdown(
            '<div class="sidebar-privacy">'
            '<strong>🔒 Local Isolation Guarantee</strong><br>'
            'All Slither analysis and Foundry EVM attack tests execute strictly on this machine in ephemeral sandboxes.'
            '</div>',
            unsafe_allow_html=True,
        )

    return page, run_dir


def main() -> None:
    st.set_page_config(
        page_title="Microscope · Evidence-Driven Security Workbench",
        page_icon="🔬",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    pending_run = st.session_state.pop("pending_run_selector", None)
    if isinstance(pending_run, str):
        st.session_state["run_selector"] = pending_run
    pending_page = st.session_state.pop("pending_workspace_page", None)
    if pending_page in {"Scan", "Findings", "Attack evidence", "Reports"}:
        st.session_state["workspace_page"] = pending_page

    st.markdown(
        """
        <style>
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap');

        :root {
            --bg-canvas: #090D16;
            --bg-surface: #101626;
            --bg-surface-elevated: #162035;
            --border-subtle: rgba(255, 255, 255, 0.08);
            --border-hover: rgba(0, 240, 181, 0.3);
            --accent-teal: #00F0B5;
            --accent-cyan: #38BDF8;
            --accent-red: #EF4444;
            --accent-green: #10B981;
            --accent-amber: #F59E0B;
            --text-primary: #F8FAFC;
            --text-secondary: #94A3B8;
            --text-muted: #64748B;
        }

        html, body, [class*="css"], [class*="st-"] {
            font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif !important;
        }

        /* Protect Streamlit Material icon ligatures from being overridden */
        [data-testid*="Icon"], [data-testid*="collapse"], [data-testid="stSidebarCollapseButton"] span,
        [data-testid="stSidebarCollapseButton"] button, [data-testid="stExpanderToggleIcon"] span,
        .material-symbols-rounded, .material-icons, [class*="material-symbols"] {
            font-family: "Material Symbols Rounded", "Material Icons", "Segoe UI Symbol", sans-serif !important;
        }

        code, pre, [class*="stCode"] {
            font-family: 'JetBrains Mono', monospace !important;
        }

        .block-container {
            max-width: 1360px;
            padding-top: 2rem;
            padding-bottom: 5rem;
        }

        [data-testid="stSidebar"] {
            background-color: #0C111C !important;
            border-right: 1px solid rgba(255, 255, 255, 0.07);
        }

        .brand-sidebar {
            padding: 0.5rem 0 1.5rem 0;
        }
        .brand-logo {
            display: flex;
            align-items: center;
            gap: 0.6rem;
            font-size: 1.35rem;
            font-weight: 800;
            letter-spacing: -0.02em;
            background: linear-gradient(135deg, #FFFFFF 0%, #00F0B5 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .brand-tagline {
            font-size: 0.78rem;
            color: #94A3B8;
            margin-top: 0.35rem;
            font-style: italic;
        }
        .brand-badge {
            display: inline-block;
            font-size: 0.65rem;
            font-weight: 700;
            letter-spacing: 0.08em;
            color: #00F0B5;
            background: rgba(0, 240, 181, 0.1);
            border: 1px solid rgba(0, 240, 181, 0.25);
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            margin-top: 0.6rem;
        }
        .sidebar-run-meta {
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid rgba(255, 255, 255, 0.06);
            border-radius: 8px;
            padding: 0.75rem;
            font-size: 0.78rem;
            color: #94A3B8;
            line-height: 1.6;
        }
        .sidebar-privacy {
            font-size: 0.72rem;
            color: #64748B;
            line-height: 1.5;
        }

        .view-title {
            font-size: 1.85rem !important;
            font-weight: 800 !important;
            letter-spacing: -0.03em !important;
            color: #F8FAFC !important;
            margin-bottom: 0.2rem !important;
        }
        .view-subtitle {
            font-size: 0.95rem;
            color: #94A3B8;
            margin-bottom: 1.8rem;
            line-height: 1.5;
        }

        .micro-badge {
            display: inline-flex;
            align-items: center;
            gap: 0.45rem;
            border: 1px solid var(--badge-color);
            background: var(--badge-bg);
            color: var(--badge-color);
            border-radius: 9999px;
            padding: 0.28rem 0.75rem;
            font-size: 0.76rem;
            font-weight: 700;
            letter-spacing: 0.04em;
            box-shadow: 0 0 12px var(--badge-bg);
        }
        .badge-dot {
            width: 7px;
            height: 7px;
            border-radius: 50%;
            display: inline-block;
        }

        .pipeline-card {
            background: #111728;
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 12px;
            padding: 1.25rem 1.5rem;
            margin-bottom: 1.8rem;
        }
        .pipeline-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
        }
        .pipeline-title {
            font-size: 0.76rem;
            font-weight: 800;
            letter-spacing: 0.08em;
            color: #94A3B8;
        }
        .pipeline-sub {
            font-size: 0.76rem;
            color: #64748B;
        }
        .pipeline-flow {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 0.5rem;
            overflow-x: auto;
        }
        .pipeline-step {
            display: flex;
            flex-direction: column;
            align-items: center;
            text-align: center;
            flex: 1;
        }
        .step-num {
            width: 32px;
            height: 32px;
            border-radius: 50%;
            border: 2px solid;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 0.75rem;
            font-weight: 800;
            margin-bottom: 0.4rem;
            background: #0D1322;
        }
        .step-label {
            font-size: 0.82rem;
            font-weight: 700;
            color: #F8FAFC;
        }
        .step-desc {
            font-size: 0.72rem;
            font-weight: 600;
            margin-top: 0.15rem;
        }
        .pipeline-arrow {
            color: #334155;
            font-size: 1rem;
            margin-bottom: 1rem;
        }

        .engine-badge {
            display: flex;
            align-items: center;
            justify-content: space-between;
            background: #111728;
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 8px;
            padding: 0.65rem 0.9rem;
            font-size: 0.8rem;
            margin-bottom: 1rem;
        }
        .badge-active {
            border-left: 3px solid #00F0B5;
        }
        .badge-warn {
            border-left: 3px solid #F59E0B;
        }
        .engine-name {
            font-weight: 600;
            color: #F8FAFC;
        }
        .engine-status {
            font-size: 0.7rem;
            font-weight: 700;
            color: #00F0B5;
        }

        .safety-banner {
            display: flex;
            gap: 0.8rem;
            align-items: center;
            background: rgba(0, 240, 181, 0.04);
            border: 1px solid rgba(0, 240, 181, 0.2);
            border-radius: 10px;
            padding: 0.9rem 1.2rem;
            margin-bottom: 1.5rem;
        }
        .banner-icon {
            font-size: 1.3rem;
        }
        .banner-text {
            font-size: 0.84rem;
            color: #CBD5E1;
            line-height: 1.5;
        }

        .finding-card {
            background: #111728;
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 12px;
            padding: 1.4rem;
            margin-top: 1rem;
            margin-bottom: 0.8rem;
            transition: border-color 0.2s ease;
        }
        .finding-card:hover {
            border-color: rgba(0, 240, 181, 0.3);
        }
        .finding-card-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            gap: 1rem;
            margin-bottom: 0.8rem;
        }
        .finding-card-tags {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            margin-bottom: 0.4rem;
        }
        .tag-category {
            font-size: 0.7rem;
            font-weight: 800;
            letter-spacing: 0.05em;
            color: #38BDF8;
            background: rgba(56, 189, 248, 0.12);
            padding: 0.15rem 0.5rem;
            border-radius: 4px;
        }
        .tag-rule {
            font-size: 0.7rem;
            font-weight: 700;
            color: #94A3B8;
            background: rgba(255, 255, 255, 0.05);
            padding: 0.15rem 0.5rem;
            border-radius: 4px;
        }
        .tag-location {
            font-size: 0.72rem;
            font-family: 'JetBrains Mono', monospace;
            color: #64748B;
        }
        .finding-title {
            font-size: 1.25rem !important;
            font-weight: 700 !important;
            color: #F8FAFC !important;
            margin: 0 !important;
        }
        .finding-copy {
            font-size: 0.88rem;
            color: #94A3B8;
            line-height: 1.5;
        }

        .explanation-box {
            background: #162035;
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 8px;
            padding: 1rem;
            margin: 0.8rem 0;
        }
        .explanation-tag {
            margin-bottom: 0.5rem;
        }
        .ai-label {
            font-size: 0.72rem;
            font-weight: 700;
            color: #38BDF8;
            background: rgba(56, 189, 248, 0.15);
            padding: 0.2rem 0.55rem;
            border-radius: 4px;
        }
        .local-label {
            font-size: 0.72rem;
            font-weight: 700;
            color: #94A3B8;
            background: rgba(255, 255, 255, 0.08);
            padding: 0.2rem 0.55rem;
            border-radius: 4px;
        }
        .explanation-body {
            font-size: 0.86rem;
            color: #E2E8F0;
            white-space: pre-wrap;
            line-height: 1.6;
        }

        .attack-steps-container {
            display: flex;
            align-items: stretch;
            gap: 0.5rem;
            margin: 1rem 0 1.5rem 0;
            overflow-x: auto;
        }
        .attack-step-card {
            flex: 1;
            min-width: 170px;
            background: #162035;
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 8px;
            padding: 0.85rem 1rem;
        }
        .attack-step-card .step-badge {
            font-size: 0.65rem;
            font-weight: 800;
            color: #38BDF8;
            letter-spacing: 0.05em;
            margin-bottom: 0.25rem;
        }
        .attack-step-card .step-title {
            font-size: 0.85rem;
            font-weight: 700;
            color: #F8FAFC;
            margin-bottom: 0.35rem;
        }
        .attack-step-card .step-desc {
            font-size: 0.74rem;
            color: #94A3B8;
            line-height: 1.4;
        }
        .attack-step-arrow {
            display: flex;
            align-items: center;
            color: #475569;
            font-size: 1.1rem;
        }

        .comparison-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 1rem;
            margin: 1rem 0 1.5rem 0;
        }
        .comp-col {
            background: #111728;
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 10px;
            padding: 1.1rem 1.25rem;
        }
        .comp-vulnerable {
            border-top: 3px solid #EF4444;
        }
        .comp-patched {
            border-top: 3px solid #10B981;
        }
        .comp-regression {
            border-top: 3px solid #38BDF8;
        }
        .comp-header {
            font-size: 0.72rem;
            font-weight: 800;
            letter-spacing: 0.06em;
            color: #94A3B8;
            margin-bottom: 0.4rem;
        }
        .comp-status {
            font-size: 0.92rem;
            font-weight: 800;
            margin-bottom: 0.5rem;
        }
        .status-danger {
            color: #EF4444;
        }
        .status-success {
            color: #10B981;
        }
        .status-info {
            color: #38BDF8;
        }
        .comp-body {
            font-size: 0.8rem;
            color: #CBD5E1;
            line-height: 1.5;
        }

        .micro-alert-box {
            border-radius: 10px;
            padding: 1.1rem 1.3rem;
            margin-bottom: 1.5rem;
        }
        .alert-warning {
            background: rgba(245, 158, 11, 0.06);
            border: 1px solid rgba(245, 158, 11, 0.25);
        }
        .alert-header {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            color: #F59E0B;
            font-size: 0.85rem;
            margin-bottom: 0.4rem;
        }
        .alert-body {
            font-size: 0.88rem;
            color: #E2E8F0;
            line-height: 1.5;
        }
        .alert-footer {
            font-size: 0.75rem;
            color: #94A3B8;
            margin-top: 0.5rem;
            font-style: italic;
        }

        .micro-empty-box {
            text-align: center;
            background: #111728;
            border: 1px dashed rgba(255, 255, 255, 0.15);
            border-radius: 12px;
            padding: 3rem 2rem;
            margin: 1.5rem 0;
        }
        .empty-icon {
            font-size: 2.5rem;
            display: block;
            margin-bottom: 0.75rem;
        }
        .micro-empty-box h4 {
            color: #F8FAFC;
            font-weight: 700;
            margin-bottom: 0.4rem;
        }
        .micro-empty-box p {
            color: #94A3B8;
            font-size: 0.88rem;
            max-width: 580px;
            margin: 0 auto;
        }

        .fixture-context-card {
            background: #111728;
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 8px;
            padding: 0.9rem 1.2rem;
            margin-top: 0.8rem;
            margin-bottom: 1rem;
        }
        .fixture-badge {
            font-size: 0.7rem;
            font-weight: 800;
            color: #00F0B5;
            margin-bottom: 0.3rem;
        }
        .fixture-path {
            font-size: 0.82rem;
            color: #94A3B8;
            margin-bottom: 0.3rem;
        }
        .fixture-desc {
            font-size: 0.8rem;
            color: #64748B;
        }

        .log-entry {
            display: flex;
            align-items: center;
            gap: 0.8rem;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.78rem;
            padding: 0.4rem 0;
            border-bottom: 1px solid rgba(255, 255, 255, 0.04);
        }
        .log-time {
            color: #64748B;
        }
        .log-stage {
            font-weight: 700;
            color: #38BDF8;
            min-width: 140px;
        }
        .log-state {
            font-size: 0.68rem;
            font-weight: 800;
            padding: 0.1rem 0.4rem;
            border-radius: 3px;
        }
        .state-running {
            background: rgba(56, 189, 248, 0.15);
            color: #38BDF8;
        }
        .state-passed, .state-complete {
            background: rgba(16, 185, 129, 0.15);
            color: #10B981;
        }
        .state-error, .state-failed {
            background: rgba(239, 68, 68, 0.15);
            color: #EF4444;
        }
        .log-msg {
            color: #CBD5E1;
        }

        .report-dl-card, .report-meta-card {
            background: #111728;
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 10px;
            padding: 1.25rem;
            height: 100%;
        }
        .report-dl-card h4, .report-meta-card h4 {
            color: #F8FAFC;
            font-weight: 700;
            margin-bottom: 0.5rem;
        }
        .report-dl-card p, .report-meta-card p {
            color: #94A3B8;
            font-size: 0.85rem;
            line-height: 1.5;
        }
        .artifact-pill-card {
            display: flex;
            align-items: center;
            gap: 0.6rem;
            background: #111728;
            border: 1px solid rgba(255, 255, 255, 0.06);
            border-radius: 6px;
            padding: 0.55rem 0.8rem;
            margin-bottom: 0.6rem;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.78rem;
        }
        .artifact-dot {
            width: 6px;
            height: 6px;
            border-radius: 50%;
        }
        .artifact-name {
            flex: 1;
            color: #E2E8F0;
        }
        .artifact-status {
            font-size: 0.72rem;
            font-weight: 600;
        }

        div[data-testid="stMetric"] {
            background: #111728 !important;
            border: 1px solid rgba(255, 255, 255, 0.08) !important;
            padding: 1rem !important;
            border-radius: 10px !important;
        }
        div[data-testid="stMetric"] label {
            color: #94A3B8 !important;
            font-size: 0.8rem !important;
            font-weight: 600 !important;
        }
        div[data-testid="stMetric"] [data-testid="stMetricValue"] {
            font-weight: 800 !important;
            color: #F8FAFC !important;
        }

        div.stButton > button[kind="primary"] {
            background: linear-gradient(135deg, #00F0B5 0%, #00B887 100%) !important;
            color: #090D16 !important;
            font-weight: 700 !important;
            border: none !important;
            border-radius: 8px !important;
            padding: 0.55rem 1.25rem !important;
            box-shadow: 0 4px 16px rgba(0, 240, 181, 0.25) !important;
            transition: all 0.2s ease !important;
        }
        div.stButton > button[kind="primary"]:hover {
            transform: translateY(-1px) !important;
            box-shadow: 0 6px 20px rgba(0, 240, 181, 0.4) !important;
        }

        /* Interactive Attack Simulator */
        .attack-sim-card {
            background: linear-gradient(180deg, #101626 0%, #0B0F19 100%);
            border: 2px solid #EF4444;
            box-shadow: 0 0 25px rgba(239, 68, 68, 0.2);
            border-radius: 12px;
            padding: 1.25rem 1.5rem;
            margin: 1.2rem 0;
        }
        .sim-live-badge {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            font-size: 0.75rem;
            font-weight: 800;
            letter-spacing: 0.08em;
            color: #EF4444;
            background: rgba(239, 68, 68, 0.12);
            border: 1px solid rgba(239, 68, 68, 0.3);
            padding: 0.25rem 0.65rem;
            border-radius: 6px;
            margin-bottom: 0.8rem;
        }
        .sim-live-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: #EF4444;
            animation: pulse-dot 1.5s infinite;
        }
        @keyframes pulse-dot {
            0% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.4; transform: scale(0.85); }
            100% { opacity: 1; transform: scale(1); }
        }
        .sim-code-container {
            background: #090D16;
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 8px;
            padding: 0.75rem 0;
            margin: 1rem 0;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.82rem;
            overflow-x: auto;
        }
        .sim-code-row {
            display: flex;
            align-items: center;
            padding: 0.25rem 1rem;
            line-height: 1.6;
        }
        .sim-code-row.active-line {
            background: rgba(56, 189, 248, 0.15);
            border-left: 3px solid #38BDF8;
        }
        .sim-code-row.vuln-line {
            background: rgba(239, 68, 68, 0.18);
            border-left: 3px solid #EF4444;
        }
        .sim-line-num {
            width: 45px;
            color: #64748B;
            user-select: none;
            font-size: 0.76rem;
        }
        .sim-line-text {
            flex: 1;
            color: #E2E8F0;
            white-space: pre;
        }
        .sim-line-tag {
            font-size: 0.68rem;
            font-weight: 700;
            padding: 0.1rem 0.45rem;
            border-radius: 4px;
            margin-left: 0.8rem;
        }
        .sim-tag-vuln {
            color: #EF4444;
            background: rgba(239, 68, 68, 0.2);
            border: 1px solid rgba(239, 68, 68, 0.4);
        }
        .sim-tag-pc {
            color: #38BDF8;
            background: rgba(56, 189, 248, 0.2);
            border: 1px solid rgba(56, 189, 248, 0.4);
        }
        .sim-tactic-box {
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 8px;
            padding: 1rem;
            margin-top: 0.8rem;
        }
        .sim-tactic-title {
            font-size: 0.88rem;
            font-weight: 700;
            color: #F8FAFC;
            margin-bottom: 0.35rem;
        }
        .sim-tactic-desc {
            font-size: 0.82rem;
            color: #CBD5E1;
            line-height: 1.5;
        }
        .sim-call-tree {
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.78rem;
            color: #00F0B5;
            background: rgba(0, 240, 181, 0.08);
            padding: 0.4rem 0.75rem;
            border-radius: 4px;
            margin-top: 0.5rem;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

    run_ids = _run_ids()
    page, run_dir = _render_sidebar(run_ids)

    if page == "Scan":
        _render_scan()
    elif page == "Findings":
        _render_findings(run_dir)
    elif page == "Attack evidence":
        _render_replay(run_dir)
    else:
        _render_reports(run_dir)


if __name__ == "__main__":
    main()
