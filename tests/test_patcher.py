from __future__ import annotations

from scanner.patcher import build_patch, render_regression_test
from scanner.schema import Facts, FunctionFacts, Protection, ProtectionFact, SourceRef, Status, Suspect, Tri
from scanner.template_engine import render_attack


def _facts(functions, privileged_vars=None):
    return Facts(
        schema_version="1.0", fixture=True, mode="api", tool_versions={},
        source_sha256="0" * 64, privileged_vars=privileged_vars or {}, functions=functions,
        public_state_vars=["Vault.credit"],
    )


def _function(identifier, contract, name, start, end, **kwargs):
    kwargs.setdefault("payable", False)
    return FunctionFacts(
        id=identifier, contract=contract, name=name, visibility="external",
        entry_point=True, src=SourceRef("input.sol", start, end),
        protection=ProtectionFact(Protection.UNPROTECTED), **kwargs,
    )


def _suspect(rule, function_id, start, end):
    return Suspect(
        id=f"{rule}-{function_id}", category="security", status=Status.CANDIDATE,
        function_id=function_id, src=SourceRef("input.sol", start, end), rule=rule,
        detector_corroboration=Tri.UNKNOWN,
    )


def test_access_patch_inserts_owner_check_as_first_body_statement():
    source = """pragma solidity ^0.8.24;
contract Treasury {
    address public owner;
    function setOwner(address newOwner) external {
        owner = newOwner;
    }
}
"""
    setter = _function("Treasury.setOwner(address)", "Treasury", "setOwner", 4, 6,
                       state_writes_all=["Treasury.owner"], parameter_types=["address"])
    facts = _facts([setter], {"Treasury.owner": {"kind": "address_eq", "public_getter": True}})
    patch = build_patch(source, facts, _suspect("AC-1", setter.id, 4, 6))
    assert patch.reason is None
    assert patch.kind == "access_control"
    assert patch.source.index('require(msg.sender == owner, "unauthorized");') < patch.source.index("owner = newOwner;")
    assert "--- a/input.sol" in patch.diff


def test_reentrancy_patch_adds_lock_and_modifier_to_slither_function_range():
    source = """pragma solidity ^0.8.24;
contract Vault {
    mapping(address => uint256) public balances;
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] = 0;
    }
}
"""
    withdraw = _function(
        "Vault.withdraw()", "Vault", "withdraw", 4, 9,
        writes_after_eth_call=[{"var": "Vault.balances", "write_lines": 8}],
    )
    patch = build_patch(source, _facts([withdraw]), _suspect("RE-1", withdraw.id, 4, 9))
    assert patch.reason is None
    assert "bool private _microscopeLock;" in patch.source
    assert "modifier microscopeNonReentrant()" in patch.source
    assert "function withdraw() external  microscopeNonReentrant{" in patch.source or "microscopeNonReentrant" in patch.source


def test_access_regression_template_checks_owner_can_still_change_owner():
    setter = _function("Treasury.setOwner(address)", "Treasury", "setOwner", 4, 6,
                       state_writes_all=["Treasury.owner"], parameter_types=["address"])
    facts = _facts([setter], {"Treasury.owner": {"kind": "address_eq", "public_getter": True}})
    suspect = _suspect("AC-1", setter.id, 4, 6)
    attack, reason = render_attack(facts, suspect)
    assert reason is None
    regression, reason = render_regression_test(attack)
    assert reason is None
    assert "try target.setOwner(nextOwner)" in regression
    # Solidity escapes JSON quotes inside the marker string literal.
    assert "regression_passed" in regression
    assert "assert" not in regression


def test_reentrancy_regression_uses_actual_state_mapping_getter():
    deposit = _function("Vault.deposit()", "Vault", "deposit", 3, 5,
                         payable=True, reads_msg_value=True,
                         state_writes_all=["Vault.credit"])
    withdraw = _function("Vault.withdraw()", "Vault", "withdraw", 6, 10,
                         writes_after_eth_call=[{"var": "Vault.credit", "write_lines": 9}])
    attack, reason = render_attack(
        _facts([deposit, withdraw]), _suspect("RE-1", withdraw.id, 6, 10)
    )
    assert reason is None
    regression, reason = render_regression_test(attack)
    assert reason is None
    assert "target.credit(address(this)) == 0" in regression
