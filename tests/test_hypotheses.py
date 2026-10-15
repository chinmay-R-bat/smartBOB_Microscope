from __future__ import annotations

import hashlib
from pathlib import Path

from conftest import CASES
from scanner import facts as facts_module
from scanner.hypotheses import build_hypotheses


def run_case(scan, filename):
    return scan(CASES / filename)


def test_empty_onlyowner_name_does_not_protect(scan):
    facts, suspects = run_case(scan, "case_01_empty_named_modifier.sol")
    setter = [item for item in suspects if item.rule == "AC-1"]
    assert len(setter) == 1 and setter[0].status.value == "candidate"
    assert any(item.protection.verdict.value == "unprotected" for item in facts.functions if item.name == "mutate")


def test_custom_modifier_with_real_guard_protects(scan):
    facts, suspects = run_case(scan, "case_02_custom_guard.sol")
    assert suspects == []
    assert any(item.protection.verdict.value == "protected" for item in facts.functions if item.name == "change")


def test_role_mapping_is_inferred_but_stays_candidate(scan):
    facts, suspects = run_case(scan, "case_03_role_mapping.sol")
    grant = [item for item in suspects if item.rule == "AC-1"]
    assert len(grant) == 1 and grant[0].status.value == "candidate"
    assert any(value["kind"] == "role_mapping" for value in facts.privileged_vars.values())
    assert grant[0].template_support.value == "unknown"


def test_helper_auth_stays_unknown(scan):
    _, suspects = run_case(scan, "case_04_auth_helper.sol")
    finding = [item for item in suspects if item.rule == "AC-1"]
    assert len(finding) == 1 and finding[0].status.value == "inconclusive"


def test_external_registry_auth_stays_unknown(scan):
    _, suspects = run_case(scan, "case_05_external_registry.sol")
    finding = [item for item in suspects if item.rule == "AC-1"]
    assert len(finding) == 1 and finding[0].status.value == "inconclusive"


def test_local_sender_alias_stays_unknown(scan):
    _, suspects = run_case(scan, "case_06_local_sender_alias.sol")
    finding = [item for item in suspects if item.rule == "AC-1"]
    assert len(finding) == 1 and finding[0].status.value == "inconclusive"


def test_assembly_downgrades_access_analysis(scan):
    facts, suspects = run_case(scan, "case_07_assembly_write.sol")
    finding = [item for item in suspects if item.rule == "AC-1"]
    assert len(finding) == 1 and finding[0].status.value == "inconclusive"
    assert any(item.uses_assembly for item in facts.functions if item.name == "change")


def test_balance_mapping_check_is_not_authorization(scan):
    facts, suspects = run_case(scan, "case_08_balance_guard.sol")
    assert not any(item.rule == "AC-1" for item in suspects)
    assert facts.privileged_vars == {}


def test_constructor_write_does_not_create_entry_suspect(scan):
    _, suspects = run_case(scan, "case_09_constructor_only.sol")
    assert not any(item.rule == "AC-1" for item in suspects)


def test_structural_lock_modifier_suppresses_reentrancy(scan):
    facts, suspects = run_case(scan, "case_10_custom_mutex.sol")
    assert not any(item.rule == "RE-1" for item in suspects)
    assert any(item.reentrancy_guard["kind"] == "lock_like_modifier" for item in facts.functions if item.name == "withdraw")


def test_unread_state_write_after_call_is_not_reentrancy(scan):
    _, suspects = run_case(scan, "case_11_counter_after_call.sol")
    assert not any(item.rule == "RE-1" for item in suspects)


def test_transfer_is_outside_initial_reentrancy_rule(scan):
    _, suspects = run_case(scan, "case_12_transfer_only.sol")
    assert not any(item.rule == "RE-1" for item in suspects)


def test_cei_internal_send_is_not_reentrancy(scan):
    _, suspects = run_case(scan, "case_13_cei_internal_send.sol")
    assert not any(item.rule == "RE-1" for item in suspects)


def test_internal_send_then_write_is_reentrancy_candidate(scan):
    _, suspects = run_case(scan, "case_14_helper_call_then_write.sol")
    finding = [item for item in suspects if item.rule == "RE-1"]
    assert len(finding) == 1 and finding[0].status.value == "candidate"


def test_compile_error_is_inconclusive(scan):
    facts, suspects = run_case(scan, "case_16_compile_error.sol")
    assert facts.mode == "cli_json_only"
    assert any(item.status.value == "inconclusive" for item in suspects)


def test_api_failure_uses_detector_only_fallback(monkeypatch, tmp_path):
    source = tmp_path / "case_15_api_failure.sol"
    source.write_bytes((CASES / "case_15_api_failure.sol").read_bytes())
    digest = hashlib.sha256(source.read_bytes()).hexdigest()

    def fail_api(*args, **kwargs):
        raise RuntimeError("simulated Slither API load failure")

    monkeypatch.setattr(facts_module, "Slither", fail_api)
    facts = facts_module._worker_analyze(source, source.name, digest, fixture=True)
    suspects = build_hypotheses(facts)
    assert facts.mode == "cli_json_only"
    assert any(item.rule == "DET-reentrancy-eth" and item.status.value == "candidate" for item in suspects)
    assert all(item.category != "access_control" for item in suspects)


def test_no_guard_emits_contract_notice(scan):
    facts, suspects = run_case(scan, "case_17_no_guard_anywhere.sol")
    assert not any(item.rule == "AC-1" for item in suspects)
    assert any(note["code"] == "no_privileged_var_inferred" for note in facts.contract_notes)
