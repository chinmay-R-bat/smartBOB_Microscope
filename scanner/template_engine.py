"""Generate the two narrow P2 attack-test shapes from P1 facts."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .schema import Facts, Status, Suspect

_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_INTEGER = re.compile(r"^(?:u?int)(?:[0-9]+)?$")


@dataclass(frozen=True)
class AttackTemplate:
    kind: str
    source: str
    assumptions: list[str]
    context: dict[str, Any]


def _function(facts: Facts, suspect: Suspect):
    return next((item for item in facts.functions if item.id == suspect.function_id), None)


def _valid_identifier(value: str) -> bool:
    return bool(_IDENTIFIER.fullmatch(value))


def _render(filename: str, **context: Any) -> str:
    try:
        from jinja2 import Environment, FileSystemLoader, StrictUndefined
    except ImportError as exc:
        raise RuntimeError("Jinja2 is required to render attack templates") from exc
    environment = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        undefined=StrictUndefined,
        autoescape=False,
        keep_trailing_newline=True,
    )
    return environment.get_template(filename).render(**context)


def _constructor_supported(facts: Facts, contract: str) -> bool:
    constructors = [item for item in facts.functions if item.contract == contract and item.is_constructor]
    return not constructors or all(item.parameter_types_available and not item.parameter_types for item in constructors)


def _render_reentrancy(facts: Facts, suspect: Suspect) -> tuple[AttackTemplate | None, str | None]:
    target = _function(facts, suspect)
    if target is None or not target.entry_point or not target.parameter_types_available or target.parameter_types:
        return None, "no template for this shape: reentrancy target must be a no-argument entry point"
    if not _valid_identifier(target.contract) or not _valid_identifier(target.name):
        return None, "no template for this shape: contract or function identifier is unsupported"
    if not _constructor_supported(facts, target.contract):
        return None, "no template for this shape: constructor arguments are unsupported"

    conflict_vars = {
        str(item.get("var")) for item in target.writes_after_eth_call if item.get("var")
    }
    if len(conflict_vars) != 1:
        return None, "no template for this shape: expected exactly one conflicted state variable"
    balance_getter = next(iter(conflict_vars)).rsplit(".", 1)[-1]
    if not _valid_identifier(balance_getter):
        return None, "no template for this shape: conflicted state getter identifier is unsupported"
    if not conflict_vars.issubset(set(facts.public_state_vars)):
        return None, "no template for this shape: conflicted state mapping has no verified public getter for the regression test"
    deposits = [
        item for item in facts.functions
        if item.contract == target.contract
        and item.id != target.id
        and item.entry_point
        and item.payable
        and item.parameter_types_available
        and not item.parameter_types
        and item.reads_msg_value
        and bool(set(item.state_writes_all) & conflict_vars)
        and _valid_identifier(item.name)
    ]
    if len(deposits) != 1:
        return None, "no template for this shape: expected one payable no-argument deposit that reads msg.value and writes the conflicted state"

    try:
        rendered = _render(
            "reentrancy.t.sol.j2",
            contract_name=target.contract,
            deposit_name=deposits[0].name,
            withdraw_name=target.name,
        )
    except Exception as exc:
        return None, f"attack template could not be rendered: {type(exc).__name__}: {exc}"
    return AttackTemplate(
        kind="reentrancy",
        source=rendered,
        assumptions=[
            "The payable function that reads msg.value and writes the conflicted state is the victim deposit path.",
            "A successful reentrant drain is measured as attacker ETH balance exceeding the 1 ETH contribution.",
        ],
        context={"contract_name": target.contract, "deposit_name": deposits[0].name,
                 "withdraw_name": target.name, "balance_getter": balance_getter},
    ), None


def _access_argument(solidity_type: str) -> str | None:
    normalized = "".join(solidity_type.split())
    if normalized == "address":
        return "RANDOM"
    if _INTEGER.fullmatch(normalized):
        return "1"
    if normalized == "bytes":
        return 'hex""'
    return None


def _render_access_control(facts: Facts, suspect: Suspect) -> tuple[AttackTemplate | None, str | None]:
    target = _function(facts, suspect)
    if target is None or not target.entry_point or not target.parameter_types_available:
        return None, "no template for this shape: target function facts are unavailable"
    if not _valid_identifier(target.contract) or not _valid_identifier(target.name):
        return None, "no template for this shape: contract or function identifier is unsupported"
    if not _constructor_supported(facts, target.contract):
        return None, "no template for this shape: constructor arguments are unsupported"

    written = set(target.state_writes_all)
    eligible = [
        (name, record) for name, record in facts.privileged_vars.items()
        if name in written and record.get("kind") == "address_eq" and record.get("public_getter") is True
    ]
    if len(eligible) != 1:
        return None, "no template for this shape: expected one written address_eq privileged variable with a public getter"

    args = [_access_argument(value) for value in target.parameter_types]
    if any(value is None for value in args):
        return None, "no template for this shape: only address, integer, and bytes arguments are supported"
    getter_name = eligible[0][0].rsplit(".", 1)[-1]
    if not _valid_identifier(getter_name):
        return None, "no template for this shape: privileged getter identifier is unsupported"

    try:
        rendered = _render(
            "access_control.t.sol.j2",
            contract_name=target.contract,
            function_name=target.name,
            getter_name=getter_name,
            arguments=[value for value in args if value is not None],
        )
    except Exception as exc:
        return None, f"attack template could not be rendered: {type(exc).__name__}: {exc}"
    return AttackTemplate(
        kind="access_control",
        source=rendered,
        assumptions=[
            f"The public getter for {eligible[0][0]} is the oracle for unauthorized state change.",
            "Address arguments use a fixed non-owner address; integer arguments use 1 and bytes arguments use empty bytes.",
        ],
        context={"contract_name": target.contract, "function_name": target.name,
                 "getter_name": getter_name,
                 "arguments": [value for value in args if value is not None],
                 "next_owner_arguments": [
                     "nextOwner" if value == "RANDOM" else value
                     for value in args if value is not None
                 ]},
    ), None


def render_attack(facts: Facts, suspect: Suspect) -> tuple[AttackTemplate | None, str | None]:
    """Return a supported generated Foundry test, or an explicit limitation."""
    if suspect.status != Status.CANDIDATE:
        return None, "static result is inconclusive; no attack template was run"
    if suspect.rule == "RE-1":
        return _render_reentrancy(facts, suspect)
    if suspect.rule == "AC-1":
        target = _function(facts, suspect)
        if target is None:
            return None, "no template for this shape: target function facts are unavailable"
        record_kinds = {
            record.get("kind") for name, record in facts.privileged_vars.items()
            if name in set(target.state_writes_all)
        }
        if "role_mapping" in record_kinds:
            return None, "role mapping templates not implemented"
        return _render_access_control(facts, suspect)
    return None, "no attack template for this rule or sink"
