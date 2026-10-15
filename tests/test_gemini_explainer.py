from __future__ import annotations

import copy
import json
from urllib.error import URLError

import pytest

from scanner import gemini_explainer


class _Response:
    def __init__(self, body: bytes):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def read(self, _limit: int):
        return self.body


def _finding():
    return {
        "id": "RE-1-Vault.withdraw()",
        "category": "reentrancy",
        "rule": "RE-1",
        "status": "reproduced",
        "function_id": "Vault.withdraw()",
        "src": {"path": "Vault.sol", "start_line": 10, "end_line": 18},
        "evidence": ["External call at line 14", "Balance write after call at line 17"],
        "assumptions": ["The test uses the recorded attacker contract."],
        "unknown_reasons": [],
        "original_result": {"status": "reproduced", "steps": [{"trace": "private trace"}]},
        "patched_result": {"status": "not_reproduced", "reason": "private result detail"},
        "regression_result": {"status": "regression_passed"},
        "source": "FULL CONTRACT SOURCE MUST NOT LEAVE THE MACHINE",
        "trace": "RAW TRACE MUST NOT LEAVE THE MACHINE",
    }


def test_sanitized_payload_is_allowlisted_and_bounded():
    source = _finding()
    payload = gemini_explainer.sanitized_finding(source)
    assert set(payload) == {
        "category", "rule", "status", "src", "evidence", "assumptions",
        "unknown_reasons", "original_result", "patched_result", "regression_result",
    }
    assert payload["original_result"] == {"status": "reproduced"}
    assert "FULL CONTRACT" not in json.dumps(payload)
    assert "RAW TRACE" not in json.dumps(payload)
    source["evidence"] = ["x" * 2_000]
    assert len(gemini_explainer.sanitized_finding(source)["evidence"][0]) == 500


def test_explanation_request_cannot_change_finding_status(monkeypatch):
    finding = _finding()
    before = copy.deepcopy(finding)
    captured = {}

    def fake_urlopen(request, timeout):
        captured["request"] = request
        captured["timeout"] = timeout
        body = json.dumps({"candidates": [{"content": {"parts": [{"text": "This is commentary, not proof."}]}}]}).encode()
        return _Response(body)

    monkeypatch.setattr(gemini_explainer, "urlopen", fake_urlopen)
    result = gemini_explainer.explain_finding(finding, "test-only-key")
    sent = captured["request"].data.decode()
    assert result == "This is commentary, not proof."
    assert captured["request"].get_header("X-goog-api-key") == "test-only-key"
    assert captured["timeout"] == gemini_explainer.TIMEOUT_SECONDS
    assert "FULL CONTRACT SOURCE" not in sent
    assert "RAW TRACE" not in sent
    assert finding == before
    assert finding["status"] == "reproduced"
    assert finding["original_result"]["status"] == "reproduced"
    assert finding["patched_result"]["status"] == "not_reproduced"


def test_missing_key_and_malformed_response_use_fixed_unavailable_error(monkeypatch):
    with pytest.raises(gemini_explainer.ExplanationUnavailable, match="^Explanation unavailable"):
        gemini_explainer.explain_finding(_finding(), None)

    monkeypatch.setattr(gemini_explainer, "urlopen", lambda *_args, **_kwargs: _Response(b"not json"))
    with pytest.raises(gemini_explainer.ExplanationUnavailable) as error:
        gemini_explainer.explain_finding(_finding(), "test-only-key")
    assert str(error.value) == gemini_explainer.UNAVAILABLE_MESSAGE

    def provider_failure(*_args, **_kwargs):
        raise URLError("provider unavailable; details must stay hidden")

    monkeypatch.setattr(gemini_explainer, "urlopen", provider_failure)
    with pytest.raises(gemini_explainer.ExplanationUnavailable) as error:
        gemini_explainer.explain_finding(_finding(), "test-only-key")
    assert str(error.value) == gemini_explainer.UNAVAILABLE_MESSAGE
