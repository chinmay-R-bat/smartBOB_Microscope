from __future__ import annotations

from pathlib import Path

from conftest import PROJECT


def by_name(facts, function_name):
    return [item for item in facts.functions if item.name == function_name]


def test_vulnerable_treasury_access_hypothesis(scan):
    facts, suspects = scan(PROJECT / "src/vulnerable/VulnerableTreasury.sol", fixture=True)
    ac = [item for item in suspects if item.rule == "AC-1"]
    assert len(ac) == 1
    assert ac[0].function_id.endswith(".setOwner(address)")
    assert ac[0].status.value == "candidate"
    assert not any(item.function_id.endswith("withdrawAll()") for item in suspects)
    assert not any(item.function_id.endswith(".receive()") for item in suspects)
    assert facts.fixture is True
    assert "VulnerableTreasury.owner" in facts.privileged_vars


def test_safe_treasury_modifier_guard_is_recorded(scan):
    facts, suspects = scan(PROJECT / "src/fixed/SafeTreasury.sol", fixture=True)
    assert suspects == []
    setter = by_name(facts, "setOwner")
    assert len(setter) == 1
    assert setter[0].protection.verdict.value == "protected"
    assert any(guard["via"].startswith("modifier:") for guard in setter[0].protection.guards)
    assert isinstance(setter[0].protection.slither_is_protected, bool)


def test_vulnerable_vault_reentrancy_hypothesis(scan):
    facts, suspects = scan(PROJECT / "src/vulnerable/VulnerableVault.sol", fixture=True)
    reentrancy = [item for item in suspects if item.rule == "RE-1"]
    assert len(reentrancy) == 1
    assert reentrancy[0].status.value == "candidate"
    assert any(value.endswith(".balances") for item in by_name(facts, "withdraw") for value in item.state_writes_all)
    assert any(item.detector_corroboration.value == "true" for item in reentrancy)
    assert not any(item.function_id.endswith(".deposit()") for item in suspects)


def test_safe_vault_low_level_call_is_not_reentrancy(scan):
    facts, suspects = scan(PROJECT / "src/fixed/SafeVault.sol", fixture=True)
    assert not any(item.rule == "RE-1" for item in suspects)
    assert any(hit["check"] == "low-level-calls" for hit in facts.detector_hits)
    assert not any(item.detector_corroboration.value == "true" for item in suspects if item.rule == "RE-1")
