"""Build normalized Slither facts and contract-level notices for one Solidity file."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import shutil
import subprocess
import sys
import tempfile
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .api_check import check_api
from .detectors import collect_detector_hits
from .schema import Facts, FunctionFacts, Protection, ProtectionFact, SourceRef, Tri, to_jsonable

try:
    from slither import Slither  # exposed for runtime use and the documented fallback-path probe
except Exception:
    Slither = None  # type: ignore[assignment,misc]

MAX_SOURCE_BYTES = 200_000
WORKER_TIMEOUT_SECONDS = 180


def _canonical(value: Any) -> str:
    return str(getattr(value, "canonical_name", None) or getattr(value, "name", None) or value)


def _lines(value: Any) -> list[int]:
    try:
        return sorted({int(line) for line in value.source_mapping.lines if int(line) > 0})
    except Exception:
        return []


def _src_ref(value: Any, label: str) -> SourceRef:
    lines = _lines(value)
    return SourceRef(label, min(lines, default=1), max(lines, default=1))


def _nodes_from_entry(function: Any) -> tuple[list[Any], list[str]]:
    """Traverse CFG from entry_point using sons; node-list order is never flow order."""
    try:
        entry = function.entry_point
    except Exception as exc:
        return [], [f"entry_point unavailable: {type(exc).__name__}"]
    if entry is None:
        return [], ["function has no CFG entry point"]
    queue: deque[Any] = deque([entry])
    visited: set[int] = set()
    result: list[Any] = []
    errors: list[str] = []
    while queue:
        node = queue.popleft()
        if id(node) in visited:
            continue
        visited.add(id(node))
        result.append(node)
        try:
            queue.extend(list(node.sons or []))
        except Exception as exc:
            errors.append(f"CFG sons unavailable: {type(exc).__name__}")
    return result, errors


def _nodes_from_modifier(modifier: Any) -> tuple[list[Any], list[str]]:
    try:
        nodes = list(modifier.nodes or [])
    except Exception as exc:
        return [], [f"modifier nodes unavailable: {type(exc).__name__}"]
    if not nodes:
        return [], ["modifier has no CFG nodes"]
    node_ids = {id(node) for node in nodes}
    roots = []
    for node in nodes:
        try:
            fathers = [father for father in (node.fathers or []) if id(father) in node_ids]
        except Exception:
            fathers = []
        if not fathers:
            roots.append(node)
    if not roots:
        return [], ["modifier CFG has no root node"]
    queue: deque[Any] = deque(roots)
    visited: set[int] = set()
    result: list[Any] = []
    errors: list[str] = []
    while queue:
        node = queue.popleft()
        if id(node) in visited:
            continue
        visited.add(id(node))
        result.append(node)
        try:
            queue.extend(child for child in (node.sons or []) if id(child) in node_ids)
        except Exception as exc:
            errors.append(f"modifier CFG sons unavailable: {type(exc).__name__}")
    if len(visited) != len(node_ids):
        errors.append("modifier CFG contains unreachable nodes")
    return result, errors


def _closure(function: Any) -> tuple[list[tuple[str, Any, str, list[Any]]], list[str]]:
    """Return function/modifier closure and its CFG nodes, cycle-safe."""
    entries: list[tuple[str, Any, str, list[Any]]] = []
    errors: list[str] = []
    queue: deque[tuple[Any, str]] = deque([(function, "body")])
    seen_functions: set[int] = set()
    seen_modifiers: set[int] = set()
    while queue:
        current, via = queue.popleft()
        if id(current) in seen_functions:
            continue
        seen_functions.add(id(current))
        nodes, node_errors = _nodes_from_entry(current)
        entries.append(("function", current, via, nodes))
        errors.extend(node_errors)
        try:
            modifiers = list(current.modifiers or [])
        except Exception as exc:
            modifiers = []
            errors.append(f"function modifiers unavailable: {type(exc).__name__}")
        for index, modifier in enumerate(modifiers):
            if id(modifier) in seen_modifiers:
                continue
            seen_modifiers.add(id(modifier))
            mod_nodes, mod_errors = _nodes_from_modifier(modifier)
            entries.append(("modifier", modifier, f"modifier:{index}", mod_nodes))
            errors.extend(mod_errors)
            for node in mod_nodes:
                for callee in _internal_callees(node):
                    queue.append((callee, "body"))
        for node in nodes:
            for callee in _internal_callees(node):
                queue.append((callee, "body"))
    return entries, errors


def _internal_callees(node: Any) -> list[Any]:
    try:
        calls = list(node.internal_calls or [])
    except Exception:
        return []
    result = []
    for call in calls:
        target = getattr(call, "function", None)
        if target is None:
            continue
        class_name = type(target).__name__.lower()
        if "solidityfunction" in class_name or "builtin" in class_name:
            continue
        if not callable(getattr(target, "all_internal_calls", None)) and not hasattr(target, "nodes"):
            continue
        result.append(target)
    return result


def _name(value: Any) -> str:
    return str(getattr(value, "name", None) or value)


def _is_sender(value: Any) -> bool:
    text = _name(value).replace(" ", "").lower()
    return text in {"msg.sender", "msgsender"} or text.endswith("msg.sender")


def _is_tx_origin(value: Any) -> bool:
    text = _name(value).replace(" ", "").lower()
    return text in {"tx.origin", "txorigin"} or text.endswith("tx.origin")


def _state_var(value: Any) -> bool:
    if type(value).__name__ == "StateVariable":
        return True
    try:
        return all(hasattr(value, attr) for attr in ("canonical_name", "type", "visibility"))
    except Exception:
        return False


def _address_state(value: Any) -> bool:
    if not _state_var(value):
        return False
    type_text = str(getattr(value, "type", "")).lower().replace(" ", "")
    return type_text.startswith("address") or "contract " in type_text


def _mapping_address_bool(value: Any) -> bool:
    if not _state_var(value):
        return False
    type_text = str(getattr(value, "type", "")).lower().replace(" ", "")
    return type_text.startswith("mapping(address=>bool)")


def _binary_kind(ir: Any) -> str:
    value = getattr(ir, "type", "")
    return str(getattr(value, "name", value)).lower().replace(" ", "")


def _is_auth_call(ir: Any) -> bool:
    if type(ir).__name__ != "SolidityCall":
        return False
    function = getattr(ir, "function", None)
    return str(getattr(function, "name", "")).startswith(("require", "assert"))


def _ir_nodes(node: Any) -> list[Any]:
    try:
        return list(node.irs or [])
    except Exception:
        return []


def _condition(node: Any) -> bool:
    try:
        return bool(node.is_conditional(include_loop=False))
    except TypeError:
        try:
            return bool(node.is_conditional())
        except Exception:
            return False
    except Exception:
        return False


def _classify_guard(node: Any, function_id: str, via: str) -> tuple[list[dict[str, Any]], list[str]]:
    guards: list[dict[str, Any]] = []
    unknown: list[str] = []
    if not _condition(node):
        return guards, unknown
    irs = _ir_nodes(node)
    auth_call = any(_is_auth_call(ir) for ir in irs)
    binaries = [ir for ir in irs if type(ir).__name__ == "Binary"]
    indexes = [ir for ir in irs if type(ir).__name__ == "Index"]
    state_vars = []
    sender_seen = False
    tx_origin = False
    for ir in irs:
        for attr in ("variable_left", "variable_right", "lvalue"):
            value = getattr(ir, attr, None)
            if value is not None:
                sender_seen = sender_seen or _is_sender(value)
                tx_origin = tx_origin or _is_tx_origin(value)
                if _state_var(value):
                    state_vars.append(value)
        for value in list(getattr(ir, "read", []) or []):
            sender_seen = sender_seen or _is_sender(value)
            tx_origin = tx_origin or _is_tx_origin(value)

    if tx_origin:
        unknown.append(f"condition@L{min(_lines(node) or [1])} reads tx.origin")

    if auth_call:
        for binary in binaries:
            kind = _binary_kind(binary)
            left = getattr(binary, "variable_left", None)
            right = getattr(binary, "variable_right", None)
            if "not_equal" in kind or "notequal" in kind:
                continue
            if "equal" not in kind:
                continue
            if _is_sender(left) and _address_state(right):
                guard_var = right
            elif _is_sender(right) and _address_state(left):
                guard_var = left
            else:
                continue
            guards.append(
                {"kind": "sender_eq_state", "function": function_id, "lines": _lines(node),
                 "state_var": _canonical(guard_var), "via": via}
            )
        for index in indexes:
            mapping = getattr(index, "variable_left", None)
            key = getattr(index, "variable_right", None)
            if _is_sender(key) and _mapping_address_bool(mapping):
                guards.append(
                    {"kind": "sender_role_mapping", "function": function_id, "lines": _lines(node),
                     "state_var": _canonical(mapping), "via": via}
                )

    for ir in irs:
        ir_type = type(ir).__name__
        if ir_type in {"InternalCall", "HighLevelCall", "LibraryCall"}:
            target = getattr(ir, "function", None)
            if target is not None and "solidityfunction" not in type(target).__name__.lower():
                unknown.append(f"condition@L{min(_lines(node) or [1])} depends on call to {_canonical(target)}")

    if not guards:
        for binary in binaries:
            kind = _binary_kind(binary)
            if "equal" not in kind and "not_equal" not in kind and "notequal" not in kind:
                continue
            left = getattr(binary, "variable_left", None)
            right = getattr(binary, "variable_right", None)
            if ("not_equal" in kind or "notequal" in kind) and (
                (_is_sender(left) and _address_state(right)) or (_is_sender(right) and _address_state(left))
            ):
                unknown.append(f"condition@L{min(_lines(node) or [1])} uses an unclassified sender inequality guard")
            if (_address_state(left) or _address_state(right)) and not (_is_sender(left) or _is_sender(right)):
                unknown.append(f"condition@L{min(_lines(node) or [1])} compares an address state value without a direct msg.sender check")
    if sender_seen and not guards and not indexes:
        unknown.append(f"condition@L{min(_lines(node) or [1])} reads msg.sender in an unclassified condition")
    # A sender-indexed balance/allowance test is an ordinary check, not auth or unknown.
    if sender_seen and not guards and indexes and not unknown:
        return guards, unknown
    return guards, unknown


def _modifier_lock(function: Any) -> tuple[dict[str, str], bool]:
    try:
        modifiers = list(function.modifiers or [])
    except Exception:
        return {"kind": "unknown", "detail": "modifier list unavailable"}, False
    for modifier in modifiers:
        nodes, _ = _nodes_from_modifier(modifier)
        conditional_reads: set[str] = set()
        writes: set[str] = set()
        placeholder = False
        for node in nodes:
            if type(getattr(node, "type", None)).__name__ == "NodeType" and str(getattr(node, "type", "")).endswith("PLACEHOLDER"):
                placeholder = True
            for variable in list(getattr(node, "state_variables_written", []) or []):
                writes.add(_canonical(variable))
            if _condition(node):
                for variable in list(getattr(node, "state_variables_read", []) or []):
                    type_text = str(getattr(variable, "type", "")).lower()
                    if "bool" in type_text:
                        conditional_reads.add(_canonical(variable))
        if placeholder and (conditional_reads & writes):
            return {"kind": "lock_like_modifier", "detail": "modifier condition reads and writes the same boolean state variable"}, True
    return {"kind": "none", "detail": "no structural lock-like modifier recognized"}, False


def _function_facts(contract: Any, function: Any, label: str, detector_hits: list[dict[str, Any]], api_warnings: list[str]) -> tuple[FunctionFacts, list[dict[str, Any]]]:
    errors: list[str] = []
    entries, closure_errors = _closure(function)
    errors.extend(closure_errors)
    function_id = _canonical(function)
    contract_name = str(getattr(contract, "name", "unknown"))
    visibility = str(getattr(function, "visibility", "unknown"))
    is_constructor = bool(getattr(function, "is_constructor", False))
    entry_point = visibility in {"public", "external"} and not is_constructor
    guards: list[dict[str, Any]] = []
    unknown_reasons: list[str] = []
    closure_writes: set[str] = set()
    uses_assembly = False
    sink_flags = {"selfdestruct": False, "delegatecall": False}
    reads_msg_value = False

    parameter_types_available = True
    try:
        parameter_types = [str(getattr(parameter, "type", "unknown")) for parameter in function.parameters]
    except Exception:
        parameter_types = []
        parameter_types_available = False

    for kind, owner, via, nodes in entries:
        owner_id = _canonical(owner)
        if kind == "function":
            try:
                uses_assembly = uses_assembly or bool(owner.contains_assembly)
            except Exception as exc:
                errors.append(f"contains_assembly unavailable for {owner_id}: {type(exc).__name__}")
        for node in nodes:
            try:
                reads_msg_value = reads_msg_value or any(_name(value).replace(" ", "").lower() == "msg.value" for value in (node.solidity_variables_read or []))
            except Exception:
                pass
            if _condition(node):
                node_guards, node_unknown = _classify_guard(node, owner_id, via)
                guards.extend(node_guards)
                unknown_reasons.extend(node_unknown)
            for variable in list(getattr(node, "state_variables_written", []) or []):
                closure_writes.add(_canonical(variable))
            for ir in _ir_nodes(node):
                ir_type = type(ir).__name__
                if ir_type in {"LowLevelCall", "HighLevelCall"}:
                    if str(getattr(ir, "function_name", "")).lower() == "delegatecall":
                        sink_flags["delegatecall"] = True
                if ir_type == "SolidityCall":
                    function_name = str(getattr(getattr(ir, "function", None), "name", "")).lower()
                    if function_name.startswith(("selfdestruct", "suicide")):
                        sink_flags["selfdestruct"] = True

    # Only API failures that affect the authorization classifier downgrade it.
    relevant_api = [
        warning for warning in api_warnings
        if ":no_sample" not in warning and any(token in warning for token in (
            "Node.is_conditional", "Node.sons", "Node.fathers", "Node.state_variables_read",
            "Node.state_variables_written", "Modifier.nodes", "StateVariable.type", "Binary.type",
            "LowLevelCall.call_value", "LowLevelCall.function_name",
        ))
    ]
    if relevant_api:
        unknown_reasons.extend(relevant_api)
    if uses_assembly:
        unknown_reasons.append("assembly in the function closure is not classified")

    unique_guards: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for guard in guards:
        key = (guard["kind"], guard["state_var"], guard["function"], guard["via"])
        unique_guards[key] = guard
    guards = sorted(unique_guards.values(), key=lambda g: (g["state_var"], g["function"], g["via"]))
    if guards:
        verdict = Protection.PROTECTED
    elif unknown_reasons or errors:
        verdict = Protection.UNKNOWN
    else:
        verdict = Protection.UNPROTECTED
    try:
        slither_is_protected = bool(function.is_protected())
    except Exception:
        slither_is_protected = False

    eth_calls: list[dict[str, Any]] = []
    after_writes: list[dict[str, Any]] = []
    direct_nodes, direct_errors = _nodes_from_entry(function)
    errors.extend(direct_errors)
    effect_cache: dict[int, tuple[set[str], set[str], list[tuple[Any, Any]]]] = {}

    def effects(node: Any) -> tuple[set[str], set[str], list[tuple[Any, Any]]]:
        if id(node) in effect_cache:
            return effect_cache[id(node)]
        reads = {_canonical(v) for v in list(getattr(node, "state_variables_read", []) or [])}
        writes = {_canonical(v) for v in list(getattr(node, "state_variables_written", []) or [])}
        calls: list[tuple[Any, Any]] = []
        for ir in _ir_nodes(node):
            if type(ir).__name__ == "LowLevelCall":
                calls.append((ir, None))
            if type(ir).__name__ == "InternalCall":
                target = getattr(ir, "function", None)
                if target is not None:
                    for value in list(getattr(target, "all_state_variables_read", lambda: [])() or []):
                        reads.add(_canonical(value))
                    for value in list(getattr(target, "all_state_variables_written", lambda: [])() or []):
                        writes.add(_canonical(value))
                    target_nodes, _ = _nodes_from_entry(target)
                    for target_node in target_nodes:
                        for target_ir in _ir_nodes(target_node):
                            if type(target_ir).__name__ == "LowLevelCall":
                                calls.append((target_ir, target))
        result = (reads, writes, calls)
        effect_cache[id(node)] = result
        return result

    def graph_walk(start: Any, relation: str) -> list[Any]:
        queue: deque[Any] = deque(list(getattr(start, relation, []) or []))
        visited: set[int] = {id(start)}
        result: list[Any] = []
        while queue:
            current = queue.popleft()
            if id(current) in visited:
                continue
            visited.add(id(current))
            result.append(current)
            queue.extend(list(getattr(current, relation, []) or []))
        return result

    for node in direct_nodes:
        reads_here, writes_here, call_items = effects(node)
        for low_level, internal_target in call_items:
            if str(getattr(low_level, "function_name", "")).lower() != "call":
                continue
            if getattr(low_level, "call_value", None) is None:
                continue
            call_lines = _lines(node)
            call_info = {
                "node_id": getattr(node, "node_id", None),
                "lines": min(call_lines, default=1),
                "kind": "low_level_call_value",
                "via_internal": _canonical(internal_target) if internal_target is not None else None,
            }
            eth_calls.append(call_info)
            ancestors = graph_walk(node, "fathers") + [node]
            descendants = graph_walk(node, "sons")
            read_before: set[str] = set()
            for ancestor in ancestors:
                read_before.update(effects(ancestor)[0])
            write_after: dict[str, int] = {}
            for descendant in descendants:
                for variable in effects(descendant)[1]:
                    line = min(_lines(descendant), default=1)
                    write_after[variable] = min(write_after.get(variable, line), line)
            for variable in sorted(read_before & set(write_after)):
                after_writes.append(
                    {"call_node": call_info["node_id"], "var": variable, "read_before": True,
                     "write_lines": write_after[variable]}
                )

    # Record transfer/send calls as facts but never treat them as RE-1 evidence.
    for node in direct_nodes:
        for ir in _ir_nodes(node):
            if type(ir).__name__ in {"LowLevelCall", "HighLevelCall"}:
                fname = str(getattr(ir, "function_name", "")).lower()
                if fname in {"transfer", "send"}:
                    eth_calls.append({"node_id": getattr(node, "node_id", None), "lines": min(_lines(node) or [1]),
                                      "kind": fname, "via_internal": None})

    lock_info, _ = _modifier_lock(function)
    if uses_assembly:
        lock_info = {"kind": "unknown", "detail": "assembly in the function closure prevents lock classification"}
    elif (relevant_api or any("CFG" in error or "entry_point" in error for error in errors)) and lock_info["kind"] == "none":
        lock_info = {"kind": "unknown", "detail": "Slither API warning prevents reliable lock classification"}

    result = FunctionFacts(
        id=function_id, contract=contract_name, name=str(getattr(function, "name", function_id)),
        visibility=visibility, payable=bool(getattr(function, "payable", False)),
        entry_point=entry_point, is_constructor=is_constructor, src=_src_ref(function, label),
        protection=ProtectionFact(verdict, guards, sorted(set(unknown_reasons)), slither_is_protected),
        parameter_types=parameter_types, parameter_types_available=parameter_types_available,
        reads_msg_value=reads_msg_value,
        state_writes_all=sorted(closure_writes),
        eth_calls=sorted(eth_calls, key=lambda item: (item.get("lines", 0), str(item.get("kind", "")))),
        writes_after_eth_call=sorted(after_writes, key=lambda item: (item["write_lines"], item["var"])),
        sink_flags={key: Tri.TRUE if value else Tri.FALSE for key, value in sink_flags.items()},
        reentrancy_guard=lock_info, uses_assembly=uses_assembly,
        detector_hits=[], analysis_errors=sorted(set(errors)),
    )
    result.detector_hits = sorted({hit["check"] for hit in detector_hits if _hit_for_function(hit, result)})
    return result, guards


def _hit_for_function(hit: dict[str, Any], function: FunctionFacts) -> bool:
    contract = str(hit.get("contract", ""))
    if contract and contract not in {function.contract, function.contract.split(".")[-1]}:
        return False
    signature = str(hit.get("function", ""))
    return bool(signature) and (
        signature == function.id or signature == function.name or signature.endswith("." + function.name)
        or signature.startswith(function.name + "(")
    )


def _tool_versions() -> dict[str, str]:
    versions = {"python": sys.version.split()[0]}
    try:
        import slither

        versions["slither"] = str(getattr(slither, "__version__", "unknown"))
    except Exception:
        versions["slither"] = "unavailable"
    try:
        versions["crytic_compile"] = importlib.metadata.version("crytic-compile")
    except importlib.metadata.PackageNotFoundError:
        versions["crytic_compile"] = "unavailable"
    try:
        result = subprocess.run(["solc", "--version"], capture_output=True, text=True, timeout=10, check=False,
                                env={"PATH": os.environ.get("PATH", os.defpath)})
        versions["solc"] = next((line.strip() for line in result.stdout.splitlines() if "Version:" in line), "unavailable")
    except (OSError, subprocess.TimeoutExpired):
        versions["solc"] = "unavailable"
    return versions


def _worker_analyze(source: Path, label: str, source_hash: str, fixture: bool) -> Facts:
    versions = _tool_versions()
    diagnostics: list[dict[str, Any]] = []
    detector_hits, detector_errors = collect_detector_hits(
        source, source.parent, timeout=120, diagnostics=diagnostics,
    )
    api_warnings: list[str] = []
    functions: list[FunctionFacts] = []
    privileged_vars: dict[str, dict[str, Any]] = {}
    public_state_vars_global: set[str] = set()
    notes: list[dict[str, str]] = []
    mode = "api"
    try:
        import slither
        if Slither is None:
            raise ImportError("Slither Python API is unavailable")
        versions["slither"] = str(getattr(slither, "__version__", versions.get("slither", "unknown")))
        parsed = Slither(str(source), cwd=str(source.parent), compile_force_framework="solc")
        api_warnings = check_api(parsed)
        for contract in list(parsed.contracts_derived):
            contract_name = str(getattr(contract, "name", "unknown"))
            contract_guards: list[dict[str, Any]] = []
            declared = list(contract.functions_declared)
            public_state_vars = {
                _canonical(variable) for variable in list(contract.state_variables_declared)
                if str(getattr(variable, "visibility", "")) == "public"
            }
            public_state_vars_global.update(public_state_vars)
            for function in declared:
                item, guards = _function_facts(contract, function, label, detector_hits, api_warnings)
                functions.append(item)
                contract_guards.extend(guards)
            for guard in contract_guards:
                variable = guard["state_var"]
                kind = "role_mapping" if guard["kind"] == "sender_role_mapping" else "address_eq"
                record = privileged_vars.setdefault(
                    variable, {"kind": kind, "evidence": [], "public_getter": variable in public_state_vars}
                )
                evidence = {"path": label, "start_line": min(guard["lines"] or [1]),
                            "end_line": max(guard["lines"] or [1]), "via": guard["via"],
                            "function": guard["function"]}
                if evidence not in record["evidence"]:
                    record["evidence"].append(evidence)
            writes_entry = any(item.entry_point and item.state_writes_all for item in functions if item.contract == contract_name)
            if writes_entry and not contract_guards:
                notes.append(
                    {"contract": contract_name, "code": "no_privileged_var_inferred",
                     "message": "No authorization guard recognised anywhere in this contract, so rule AC-1 cannot infer a privileged variable. This is NOT evidence of safety."}
                )
    except Exception as exc:
        mode = "cli_json_only"
        api_message = f"{type(exc).__name__}: {exc}"
        api_warnings.append(f"Slither API load failed: {api_message[:16_000]}")
        lowered = api_message.lower()
        compilation_error = any(marker in lowered for marker in (
            "invalid compilation", "solc compilation error", "parsererror",
            "compilererror", "syntax error", "expected ",
        ))
        diagnostics.append({
            "tool": "slither-python",
            "stage": "compilation_analysis",
            "classification": "compilation_error" if compilation_error else "tool_failure",
            "exception_type": type(exc).__name__,
            "message": api_message[-16_000:],
            "message_truncated": len(api_message) > 16_000,
        })
        if detector_errors:
            api_warnings.extend(f"detector fallback: {error}" for error in detector_errors)
        compilation_diagnostic = next(
            (item for item in diagnostics if item.get("classification") == "compilation_error"),
            None,
        )
        if compilation_diagnostic or not detector_hits:
            primary = compilation_diagnostic or next(
                (item for item in diagnostics if item.get("tool") == "slither-python"),
                None,
            )
            detail = str(primary.get("message")) if primary else (
                api_warnings[0] if api_warnings else "No detector evidence was available."
            )
            explanation = "Solidity compilation failed." if compilation_diagnostic else "Static analysis could not load this input."
            notes.append({"contract": "", "code": "analysis_error",
                          "message": f"{explanation} {detail}"})

    return Facts(
        schema_version="1.0", fixture=fixture, mode=mode, tool_versions=versions,
        source_sha256=source_hash, privileged_vars=privileged_vars, functions=functions,
        public_state_vars=sorted(public_state_vars_global),
        detector_hits=detector_hits, api_warnings=sorted(set(api_warnings)), contract_notes=notes,
        analysis_diagnostics=diagnostics,
    )


def _minimal_python_env(project_root: Path, temp_dir: Path) -> dict[str, str]:
    env = {
        "PATH": os.environ.get("PATH", os.defpath),
        "PYTHONPATH": str(project_root),
        "TMPDIR": str(temp_dir),
        "TEMP": str(temp_dir),
        "TMP": str(temp_dir),
        "PYTHONNOUSERSITE": "1",
    }
    # solc-select uses its per-user installation/configuration under HOME.
    # Keep only this path; credential-bearing variables are not inherited.
    if os.environ.get("HOME"):
        env["HOME"] = os.environ["HOME"]
    if os.name == "nt" and os.environ.get("SYSTEMROOT"):
        env["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
    return env


def analyze_file(source: str | Path, *, fixture: bool = False, runs_dir: str | Path = "runs") -> tuple[Facts, Path]:
    """Analyze a single Solidity file locally and persist only normalized facts.

    Source is copied to an isolated temporary directory with a fixed filename,
    compiled there, and removed when analysis ends. The run artifact contains
    a digest and normalized evidence, never the source text.
    """
    original = Path(source).resolve(strict=True)
    if original.suffix.lower() != ".sol":
        raise ValueError("input must be a .sol file")
    if not original.is_file():
        raise ValueError("input must be a regular file")
    source_bytes = original.read_bytes()
    if len(source_bytes) > MAX_SOURCE_BYTES:
        raise ValueError(f"Solidity input exceeds {MAX_SOURCE_BYTES} bytes")
    try:
        source_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError("Solidity input must be valid UTF-8 text") from exc
    source_hash = hashlib.sha256(source_bytes).hexdigest()
    # Multiple quick scans of the same source must still get distinct run dirs.
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    run_dir = Path(runs_dir).resolve() / f"{timestamp}-{source_hash[:8]}"
    run_dir.mkdir(parents=True, exist_ok=False)
    project_root = Path(__file__).resolve().parent.parent
    with tempfile.TemporaryDirectory(prefix="microscope-") as work:
        temp_dir = Path(work)
        temp_source = temp_dir / "input.sol"
        temp_source.write_bytes(source_bytes)
        output = temp_dir / "facts.json"
        worker_args = [
            sys.executable, "-m", "scanner.facts", "--worker", str(temp_source),
            "--source-label", original.name, "--source-sha256", source_hash,
            "--output", str(output), "--fixture" if fixture else "--not-fixture",
        ]
        try:
            completed = subprocess.run(
                worker_args, cwd=str(temp_dir), env=_minimal_python_env(project_root, temp_dir),
                capture_output=True, text=True, timeout=WORKER_TIMEOUT_SECONDS, check=False,
            )
            if completed.returncode != 0 or not output.is_file():
                detail = (completed.stderr or completed.stdout or "worker produced no facts").strip().splitlines()
                raise RuntimeError(detail[-1][:500] if detail else "facts worker failed")
            payload = json.loads(output.read_text(encoding="utf-8"))
        except subprocess.TimeoutExpired as exc:
            payload = {
                "schema_version": "1.0", "fixture": fixture, "mode": "cli_json_only",
                "tool_versions": _tool_versions(), "source_sha256": source_hash,
                "privileged_vars": {}, "functions": [], "detector_hits": [],
                "api_warnings": [f"facts worker timed out after {WORKER_TIMEOUT_SECONDS}s"],
                "contract_notes": [{"contract": "", "code": "analysis_error",
                                    "message": "Static analysis timed out; no verdict was produced."}],
            }
        except (RuntimeError, json.JSONDecodeError) as exc:
            payload = {
                "schema_version": "1.0", "fixture": fixture, "mode": "cli_json_only",
                "tool_versions": _tool_versions(), "source_sha256": source_hash,
                "privileged_vars": {}, "functions": [], "detector_hits": [],
                "api_warnings": [f"facts worker failed: {type(exc).__name__}: {exc}"],
                "contract_notes": [{"contract": "", "code": "analysis_error",
                                    "message": "Static analysis failed to produce facts. The result is inconclusive."}],
            }
    facts_file = run_dir / "facts.json"
    facts_file.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    from .schema import facts_from_dict

    return facts_from_dict(payload), run_dir


def _worker_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--worker", type=Path, required=True)
    parser.add_argument("--source-label", required=True)
    parser.add_argument("--source-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--fixture", action="store_true")
    parser.add_argument("--not-fixture", action="store_true")
    args = parser.parse_args(argv)
    facts = _worker_analyze(args.worker, args.source_label, args.source_sha256, args.fixture)
    args.output.write_text(json.dumps(to_jsonable(facts), indent=2) + "\n", encoding="utf-8")
    return 0


def main(argv: list[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    if raw and raw[0] == "--worker":
        return _worker_main(raw)
    parser = argparse.ArgumentParser(description="Collect local Slither facts for a Solidity file.")
    parser.add_argument("source", type=Path)
    parser.add_argument("--fixture", action="store_true", help="explicitly label input as a demo fixture")
    parser.add_argument("--runs-dir", type=Path, default=Path("runs"))
    args = parser.parse_args(raw)
    facts, _ = analyze_file(args.source, fixture=args.fixture, runs_dir=args.runs_dir)
    sys.stdout.write(json.dumps(to_jsonable(facts), indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
