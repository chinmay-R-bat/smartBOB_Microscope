from __future__ import annotations

from pathlib import Path

import pytest

from scanner.facts import analyze_file
from scanner.hypotheses import build_hypotheses


PROJECT = Path(__file__).resolve().parents[1]
CASES = Path(__file__).resolve().parent / "cases"


@pytest.fixture
def scan(tmp_path):
    def _scan(source: Path | str, *, fixture: bool = False):
        path = Path(source)
        facts, _ = analyze_file(path, fixture=fixture, runs_dir=tmp_path / "runs")
        return facts, build_hypotheses(facts)

    return _scan


def hypothesis_shape(suspects):
    return sorted((item.category, item.rule, item.status.value) for item in suspects)
