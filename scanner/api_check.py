"""Runtime capability checks for the Slither API used by the facts layer."""

from __future__ import annotations

from typing import Any


def _has(obj: Any, name: str) -> bool:
    try:
        getattr(obj, name)
        return True
    except Exception:
        return False


def check_api(slither: Any) -> list[str]:
    """Return capability warnings without making API drift fatal.

    Slither properties often require a compiled sample object and therefore
    cannot be checked reliably on the class itself. Probe loaded objects and
    retain each failure as a warning for the function-level conservative path.
    """
    warnings: list[str] = []
    try:
        contracts = list(getattr(slither, "contracts_derived", []) or [])
    except Exception as exc:
        return [f"api:contracts_derived:{type(exc).__name__}"]

    if not contracts:
        return ["api:no_derived_contracts_to_probe"]

    functions = []
    nodes = []
    modifiers = []
    state_variables = []
    for contract in contracts:
        try:
            functions.extend(list(getattr(contract, "functions_declared", []) or []))
            state_variables.extend(list(getattr(contract, "state_variables_declared", []) or []))
        except Exception as exc:
            warnings.append(f"api:contract_members:{type(exc).__name__}")
        for function in list(getattr(contract, "functions_declared", []) or []):
            try:
                nodes.extend(list(getattr(function, "nodes", []) or []))
                modifiers.extend(list(getattr(function, "modifiers", []) or []))
            except Exception as exc:
                warnings.append(f"api:function_members:{type(exc).__name__}")

    probes = [
        (functions, "entry_point", "Function.entry_point"),
        (functions, "all_internal_calls", "Function.all_internal_calls"),
        (functions, "contains_assembly", "Function.contains_assembly"),
        (nodes, "sons", "Node.sons"),
        (nodes, "fathers", "Node.fathers"),
        (nodes, "is_conditional", "Node.is_conditional"),
        (nodes, "internal_calls", "Node.internal_calls"),
        (nodes, "state_variables_read", "Node.state_variables_read"),
        (nodes, "state_variables_written", "Node.state_variables_written"),
        (nodes, "solidity_variables_read", "Node.solidity_variables_read"),
        (modifiers, "nodes", "Modifier.nodes"),
        (state_variables, "type", "StateVariable.type"),
    ]
    for objects, attribute, label in probes:
        if not objects:
            warnings.append(f"api:{label}:no_sample")
        elif not any(_has(obj, attribute) for obj in objects):
            warnings.append(f"api:{label}:missing")

    # Probe nested IR features when they occur in the loaded sample.
    try:
        from slither.slithir.operations import Binary, Index, LowLevelCall, SolidityCall

        irs = [ir for node in nodes for ir in (getattr(node, "irs", []) or [])]
        for ir_type, attributes, label in (
            (Binary, ("type", "variable_left", "variable_right"), "Binary"),
            (Index, ("variable_left", "variable_right"), "Index"),
            (LowLevelCall, ("call_value", "function_name"), "LowLevelCall"),
            (SolidityCall, ("function",), "SolidityCall"),
        ):
            samples = [ir for ir in irs if isinstance(ir, ir_type)]
            for attribute in attributes:
                if samples and not any(_has(sample, attribute) for sample in samples):
                    warnings.append(f"api:{label}.{attribute}:missing")
    except Exception as exc:
        warnings.append(f"api:slithir_probe:{type(exc).__name__}")

    try:
        from slither.core.cfg.node import NodeType

        if not hasattr(NodeType, "PLACEHOLDER"):
            warnings.append("api:NodeType.PLACEHOLDER:missing")
    except Exception as exc:
        warnings.append(f"api:NodeType.PLACEHOLDER:{type(exc).__name__}")

    return sorted(set(warnings))
