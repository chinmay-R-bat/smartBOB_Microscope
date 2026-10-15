from __future__ import annotations

import re

import pytest

from conftest import PROJECT, hypothesis_shape


RENAMES = {
    "VulnerableTreasury": "C1", "SafeTreasury": "C2",
    "VulnerableVault": "C3", "SafeVault": "C4",
    "onlyOwner": "gate", "withdrawAll": "releaseAll", "setOwner": "changeBoss",
    "withdraw": "pullOut", "deposit": "addFunds", "balances": "ledger",
    "owner": "boss", "newOwner": "newBoss", "amount": "qty", "ok": "success",
}


def renamed(source: str) -> str:
    for old, new in RENAMES.items():
        source = re.sub(rf"\b{re.escape(old)}\b", new, source)
    return source


@pytest.mark.parametrize(
    "fixture_path",
    [
        PROJECT / "src/vulnerable/VulnerableTreasury.sol",
        PROJECT / "src/fixed/SafeTreasury.sol",
        PROJECT / "src/vulnerable/VulnerableVault.sol",
        PROJECT / "src/fixed/SafeVault.sol",
    ],
)
def test_renamed_and_randomly_named_fixture_has_same_hypotheses(scan, fixture_path, tmp_path):
    original_facts, original = scan(fixture_path, fixture=True)
    renamed_path = tmp_path / "randomized-name.sol"
    renamed_path.write_text(renamed(fixture_path.read_text(encoding="utf-8")), encoding="utf-8")
    renamed_facts, renamed_suspects = scan(renamed_path, fixture=True)
    assert hypothesis_shape(original) == hypothesis_shape(renamed_suspects)
    assert original_facts.fixture == renamed_facts.fixture is True


def test_no_guard_notice_survives_identifier_renaming(scan, tmp_path):
    source_path = PROJECT / "tests/cases/case_17_no_guard_anywhere.sol"
    original_facts, original = scan(source_path)
    copy = tmp_path / "unrelated-random-name.sol"
    copy.write_text(renamed(source_path.read_text(encoding="utf-8")), encoding="utf-8")
    changed_facts, changed = scan(copy)
    assert hypothesis_shape(original) == hypothesis_shape(changed)
    assert any(note["code"] == "no_privileged_var_inferred" for note in changed_facts.contract_notes)
