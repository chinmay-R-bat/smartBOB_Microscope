"""Deterministic source-range patches for the two supported P3 shapes."""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass

from .schema import Facts, Suspect
from .template_engine import AttackTemplate, _render

_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


@dataclass(frozen=True)
class PatchResult:
    source: str | None
    diff: str
    kind: str | None
    reason: str | None = None


def _line_offset(source: str, line: int) -> int:
    if line < 1:
        return 0
    offset = 0
    for _ in range(line - 1):
        newline = source.find("\n", offset)
        if newline < 0:
            return len(source)
        offset = newline + 1
    return offset


def _find_brace(source: str, start: int, end: int) -> int | None:
    """Find the first Solidity code brace, skipping comments and quoted strings."""
    index = start
    state = "code"
    while index < min(end, len(source)):
        char = source[index]
        nxt = source[index + 1] if index + 1 < len(source) else ""
        if state == "line_comment":
            if char == "\n":
                state = "code"
        elif state == "block_comment":
            if char == "*" and nxt == "/":
                state = "code"
                index += 1
        elif state in {"string", "unicode_string"}:
            if char == "\\":
                index += 1
            elif char == '"':
                state = "code"
        elif state == "single_string":
            if char == "\\":
                index += 1
            elif char == "'":
                state = "code"
        elif char == "/" and nxt == "/":
            state = "line_comment"
            index += 1
        elif char == "/" and nxt == "*":
            state = "block_comment"
            index += 1
        elif char == '"':
            state = "string"
        elif char == "'":
            state = "single_string"
        elif char == "{" :
            return index
        index += 1
    return None


def _contract_open(source: str, contract_name: str) -> int | None:
    pattern = re.compile(r"\b(?:abstract\s+)?contract\s+" + re.escape(contract_name) + r"\b")
    match = pattern.search(source)
    if not match:
        return None
    return _find_brace(source, match.end(), len(source))


def _function_open(source: str, suspect: Suspect) -> int | None:
    start = _line_offset(source, suspect.src.start_line)
    end = _line_offset(source, suspect.src.end_line + 1)
    if end <= start:
        end = len(source)
    return _find_brace(source, start, end)


def _diff(before: str, after: str) -> str:
    return "".join(difflib.unified_diff(
        before.splitlines(keepends=True), after.splitlines(keepends=True),
        fromfile="a/input.sol", tofile="b/input.sol",
    ))


def build_patch(source: str, facts: Facts, suspect: Suspect) -> PatchResult:
    """Return a unified diff and patched source, or a precise unsupported reason."""
    target = next((function for function in facts.functions if function.id == suspect.function_id), None)
    if target is None:
        return PatchResult(None, "", None, "patch unavailable: target function facts are missing")
    function_open = _function_open(source, suspect)
    if function_open is None:
        return PatchResult(None, "", None, "patch unavailable: function body brace was not found in its Slither source range")

    if suspect.rule == "AC-1":
        written = set(target.state_writes_all)
        eligible = [
            (qualified, record) for qualified, record in facts.privileged_vars.items()
            if qualified in written and record.get("kind") == "address_eq"
            and record.get("public_getter") is True
        ]
        if len(eligible) != 1:
            return PatchResult(None, "", None,
                               "patch unavailable: expected one written address_eq variable with a public getter")
        variable_name = eligible[0][0].rsplit(".", 1)[-1]
        if not _IDENTIFIER.fullmatch(variable_name):
            return PatchResult(None, "", None, "patch unavailable: privileged state variable identifier is unsupported")
        line_start = source.rfind("\n", 0, function_open) + 1
        function_indent = re.match(r"\s*", source[line_start:function_open]).group(0)
        body_indent = function_indent + "    "
        insertion = "\n" + body_indent + f'require(msg.sender == {variable_name}, "unauthorized");' + "\n" + body_indent
        patched = source[:function_open + 1] + insertion + source[function_open + 1:]
        return PatchResult(patched, _diff(source, patched), "access_control")

    if suspect.rule == "RE-1":
        if re.search(r"\b_microscopeLock\b|\bmicroscopeNonReentrant\b", source):
            return PatchResult(None, "", None, "patch unavailable: patch identifiers already exist in the input")
        contract_open = _contract_open(source, target.contract)
        if contract_open is None:
            return PatchResult(None, "", None, "patch unavailable: contract body brace was not found")
        contract_line_start = source.rfind("\n", 0, contract_open) + 1
        contract_indent = re.match(r"\s*", source[contract_line_start:contract_open]).group(0)
        member_indent = contract_indent + "    "
        nested_indent = member_indent + "    "
        member = (
            "\n" + member_indent + "bool private _microscopeLock;\n\n"
            + member_indent + "modifier microscopeNonReentrant() {\n"
            + nested_indent + 'require(!_microscopeLock, "reentrant");\n'
            + nested_indent + "_microscopeLock = true;\n"
            + nested_indent + "_;\n"
            + nested_indent + "_microscopeLock = false;\n"
            + member_indent + "}\n" + member_indent
        )
        patched = source[:contract_open + 1] + member + source[contract_open + 1:]
        shifted_function_open = function_open + len(member) if function_open > contract_open else function_open
        prefix = "" if patched[shifted_function_open - 1:shifted_function_open].isspace() else " "
        patched = (patched[:shifted_function_open] + prefix + "microscopeNonReentrant "
                   + patched[shifted_function_open:])
        return PatchResult(patched, _diff(source, patched), "reentrancy")

    return PatchResult(None, "", None, f"patch unavailable: no deterministic patch for rule {suspect.rule}")


def render_regression_test(template: AttackTemplate) -> tuple[str | None, str | None]:
    """Render the matching owner/honest-depositor regression check."""
    filename = {
        "access_control": "access_control_regression.t.sol.j2",
        "reentrancy": "reentrancy_regression.t.sol.j2",
    }.get(template.kind)
    if filename is None:
        return None, f"regression template unavailable for {template.kind}"
    context = dict(template.context)
    if template.kind == "access_control":
        context["next_owner_arguments"] = [
            "nextOwner" if arg == "RANDOM" else arg for arg in context["arguments"]
        ]
    try:
        return _render(filename, **context), None
    except Exception as exc:
        return None, f"regression template could not be rendered: {type(exc).__name__}: {exc}"
