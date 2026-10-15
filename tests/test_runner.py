from __future__ import annotations

import json
from pathlib import Path

from scanner.runner import parse_forge_json


SAMPLE = Path(__file__).resolve().parent / "fixtures" / "forge_json_sample.json"


def _sample():
    return json.loads(SAMPLE.read_text(encoding="utf-8"))


def _test_name(payload):
    suite = next(iter(payload.values()))
    return next(iter(suite["test_results"]))


def test_captured_forge_185_shape_is_read_and_empty_decoded_logs_are_inconclusive():
    payload = _sample()
    result = parse_forge_json(payload, expected_test="test_Reentrancy_REPRODUCED_on_original")
    assert result.outcome == "inconclusive"
    assert result.reason == "Test completed without a decoded MICROSCOPE_RESULT log"


def test_decoded_marker_produces_reproduced_from_captured_forge_shape():
    payload = _sample()
    test_name = _test_name(payload)
    test_result = next(iter(payload.values()))["test_results"][test_name]
    test_result["decoded_logs"] = [
        'MICROSCOPE_RESULT {"class":"reentrancy","attacker_in":"1000000000000000000",'
        '"attacker_out":"11000000000000000000","exploit_succeeded":true,"steps":[]}'
    ]
    result = parse_forge_json(payload, expected_test=test_name.split("(", 1)[0], expected_class="reentrancy")
    assert result.outcome == "reproduced"
    assert result.payload["attacker_out"] == "11000000000000000000"


def test_false_oracle_is_not_reproduced_not_safe():
    payload = _sample()
    test_name = _test_name(payload)
    next(iter(payload.values()))["test_results"][test_name]["decoded_logs"] = [
        'MICROSCOPE_RESULT {"class":"access_control","exploit_succeeded":false,"steps":[]}'
    ]
    result = parse_forge_json(payload, expected_test=test_name.split("(", 1)[0], expected_class="access_control")
    assert result.outcome == "not_reproduced"
    assert result.reason == "exploit was not reproduced under this test"


def test_failed_harness_never_becomes_not_reproduced():
    payload = _sample()
    test_name = _test_name(payload)
    test_result = next(iter(payload.values()))["test_results"][test_name]
    test_result["status"] = "Failure"
    test_result["reason"] = "deployment failed"
    result = parse_forge_json(payload, expected_test=test_name.split("(", 1)[0])
    assert result.outcome == "inconclusive"
    assert "Harness/test failure" in result.reason


def test_missing_expected_test_is_inconclusive():
    assert parse_forge_json(_sample(), expected_test="test_does_not_exist").outcome == "inconclusive"


def test_regression_marker_uses_separate_passed_failed_outcomes():
    payload = _sample()
    test_name = _test_name(payload)
    result_data = next(iter(payload.values()))["test_results"][test_name]
    result_data["decoded_logs"] = [
        'MICROSCOPE_RESULT {"class":"access_control_regression",'
        '"regression_passed":true,"steps":[]}'
    ]
    result = parse_forge_json(payload, expected_test=test_name.split("(", 1)[0],
                              expected_class="access_control_regression")
    assert result.outcome == "regression_passed"
