"""Stable JSON schema shared by the P1 static-analysis modules."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, is_dataclass
from enum import Enum
from typing import Any


class Tri(str, Enum):
    TRUE = "true"
    FALSE = "false"
    UNKNOWN = "unknown"


class Protection(str, Enum):
    PROTECTED = "protected"
    UNPROTECTED = "unprotected"
    UNKNOWN = "unknown"


class Status(str, Enum):
    CANDIDATE = "candidate"
    INCONCLUSIVE = "inconclusive"
    REPRODUCED = "reproduced"
    NOT_REPRODUCED = "not_reproduced"
    MITIGATED_IN_TEST = "mitigated_in_test"
    REGRESSION_FAILURE = "regression_failure"
    COMPILE_FAILED = "compile_failed"


@dataclass(frozen=True)
class SourceRef:
    path: str
    start_line: int
    end_line: int


@dataclass
class ProtectionFact:
    verdict: Protection = Protection.UNKNOWN
    guards: list[dict[str, Any]] = field(default_factory=list)
    unknown_reasons: list[str] = field(default_factory=list)
    # Slither's heuristic is retained for comparison and must never drive verdicts.
    slither_is_protected: bool = False


@dataclass
class FunctionFacts:
    id: str
    contract: str
    name: str
    visibility: str
    payable: bool
    entry_point: bool
    src: SourceRef
    protection: ProtectionFact
    is_constructor: bool = False
    parameter_types: list[str] = field(default_factory=list)
    parameter_types_available: bool = True
    reads_msg_value: bool = False
    state_writes_all: list[str] = field(default_factory=list)
    eth_calls: list[dict[str, Any]] = field(default_factory=list)
    writes_after_eth_call: list[dict[str, Any]] = field(default_factory=list)
    sink_flags: dict[str, Tri] = field(
        default_factory=lambda: {"selfdestruct": Tri.FALSE, "delegatecall": Tri.FALSE}
    )
    reentrancy_guard: dict[str, Any] = field(default_factory=lambda: {"kind": "none", "detail": ""})
    uses_assembly: bool = False
    detector_hits: list[str] = field(default_factory=list)
    analysis_errors: list[str] = field(default_factory=list)


@dataclass
class Facts:
    schema_version: str
    fixture: bool
    mode: str
    tool_versions: dict[str, str]
    source_sha256: str
    privileged_vars: dict[str, dict[str, Any]]
    functions: list[FunctionFacts]
    public_state_vars: list[str] = field(default_factory=list)
    detector_hits: list[dict[str, Any]] = field(default_factory=list)
    api_warnings: list[str] = field(default_factory=list)
    contract_notes: list[dict[str, str]] = field(default_factory=list)
    analysis_diagnostics: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class Suspect:
    id: str
    category: str
    status: Status
    function_id: str
    src: SourceRef | None
    rule: str
    evidence: list[str] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)
    unknown_reasons: list[str] = field(default_factory=list)
    detector_corroboration: Tri = Tri.UNKNOWN
    template_support: Tri = Tri.UNKNOWN


def to_jsonable(value: Any) -> Any:
    """Convert dataclasses/enums/containers to deterministic JSON primitives."""
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        return {key: to_jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, dict):
        return {str(key): to_jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_jsonable(item) for item in value]
    return value


def facts_from_dict(data: dict[str, Any]) -> Facts:
    """Rehydrate a serialized Facts object at module boundaries."""
    functions: list[FunctionFacts] = []
    for raw in data.get("functions", []):
        protection_raw = raw.get("protection", {})
        protection = ProtectionFact(
            verdict=Protection(protection_raw.get("verdict", Protection.UNKNOWN.value)),
            guards=list(protection_raw.get("guards", [])),
            unknown_reasons=list(protection_raw.get("unknown_reasons", [])),
            slither_is_protected=bool(protection_raw.get("slither_is_protected", False)),
        )
        functions.append(
            FunctionFacts(
                id=raw["id"], contract=raw["contract"], name=raw["name"],
                visibility=raw["visibility"], payable=bool(raw["payable"]),
                entry_point=bool(raw["entry_point"]),
                is_constructor=bool(raw.get("is_constructor", False)),
                src=SourceRef(**raw["src"]), protection=protection,
                parameter_types=list(raw.get("parameter_types", [])),
                parameter_types_available=bool(raw.get("parameter_types_available", True)),
                reads_msg_value=bool(raw.get("reads_msg_value", False)),
                state_writes_all=list(raw.get("state_writes_all", [])),
                eth_calls=list(raw.get("eth_calls", [])),
                writes_after_eth_call=list(raw.get("writes_after_eth_call", [])),
                sink_flags={k: Tri(v) for k, v in raw.get("sink_flags", {}).items()},
                reentrancy_guard=dict(raw.get("reentrancy_guard", {"kind": "none", "detail": ""})),
                uses_assembly=bool(raw.get("uses_assembly", False)),
                detector_hits=list(raw.get("detector_hits", [])),
                analysis_errors=list(raw.get("analysis_errors", [])),
            )
        )
    return Facts(
        schema_version=data["schema_version"], fixture=bool(data["fixture"]),
        mode=data["mode"], tool_versions=dict(data.get("tool_versions", {})),
        source_sha256=data["source_sha256"], privileged_vars=dict(data.get("privileged_vars", {})),
        functions=functions, detector_hits=list(data.get("detector_hits", [])),
        public_state_vars=list(data.get("public_state_vars", [])),
        api_warnings=list(data.get("api_warnings", [])),
        contract_notes=list(data.get("contract_notes", [])),
        analysis_diagnostics=list(data.get("analysis_diagnostics", [])),
    )
