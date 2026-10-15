from __future__ import annotations

import re

from scanner.schema import Facts, FunctionFacts, Protection, ProtectionFact, SourceRef, Status, Suspect, Tri
from scanner.template_engine import render_attack


def _function(identifier, contract, name, *, payable=False, parameters=None, **kwargs):
    return FunctionFacts(
        id=identifier, contract=contract, name=name, visibility="external", payable=payable,
        entry_point=True, src=SourceRef("fixture.sol", 1, 10),
        protection=ProtectionFact(Protection.UNPROTECTED),
        parameter_types=list(parameters or []), **kwargs,
    )


def _suspect(rule, function_id, category):
    return Suspect(
        id=f"{rule}-{function_id}", category=category, status=Status.CANDIDATE,
        function_id=function_id, src=SourceRef("fixture.sol", 1, 10), rule=rule,
        evidence=[], assumptions=[], unknown_reasons=[],
        detector_corroboration=Tri.UNKNOWN, template_support=Tri.UNKNOWN,
    )


def _facts(functions, privileged_vars=None):
    return Facts(
        schema_version="1.0", fixture=True, mode="api",
        tool_versions={"slither": "0.11.6"}, source_sha256="0" * 64,
        privileged_vars=privileged_vars or {}, functions=functions,
        public_state_vars=["Vault.balances"],
    )


def test_reentrancy_template_requires_value_deposit_and_does_not_assert_exploit():
    deposit = _function(
        "Vault.deposit()", "Vault", "deposit", payable=True,
        reads_msg_value=True, state_writes_all=["Vault.balances"],
    )
    withdraw = _function(
        "Vault.withdraw()", "Vault", "withdraw",
        writes_after_eth_call=[{"var": "Vault.balances", "write_lines": 8}],
    )
    template, reason = render_attack(
        _facts([deposit, withdraw]), _suspect("RE-1", withdraw.id, "reentrancy")
    )
    assert reason is None
    assert template.kind == "reentrancy"
    compact = re.sub(r"\s+", "", template.source)
    assert "victim.deposit{value:1ether}()" in compact
    assert "victim.withdraw()" in compact
    assert "MICROSCOPE_RESULT" in template.source
    assert "assert" not in template.source


def test_access_control_template_requires_public_getter_and_no_exploit_assert():
    setter = _function("Treasury.setOwner(address)", "Treasury", "setOwner", parameters=["address"],
                       state_writes_all=["Treasury.owner"])
    facts = _facts([setter], {
        "Treasury.owner": {"kind": "address_eq", "public_getter": True, "evidence": []},
    })
    template, reason = render_attack(facts, _suspect("AC-1", setter.id, "access_control"))
    assert reason is None
    assert template.kind == "access_control"
    assert "target.setOwner(RANDOM)" in template.source
    assert "target.owner() == RANDOM" in template.source
    assert "MICROSCOPE_RESULT" in template.source
    assert "assert" not in template.source


def test_role_mapping_is_explicitly_unsupported():
    grant = _function("Roles.grant(address)", "Roles", "grant", parameters=["address"],
                      state_writes_all=["Roles.admins"])
    facts = _facts([grant], {"Roles.admins": {"kind": "role_mapping", "public_getter": True}})
    template, reason = render_attack(facts, _suspect("AC-1", grant.id, "access_control"))
    assert template is None
    assert reason == "role mapping templates not implemented"
