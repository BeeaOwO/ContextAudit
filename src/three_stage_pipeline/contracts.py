from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any


REQUIRED_FIELDS = {
    "A": {
        "non_standard_external_calls",
        "data_flow_path",
        "vulnerability_node",
        "confidence",
        "additional_context_needed",
    },
    "B": {
        "data_flow_path",
        "vulnerability_node",
        "cwe_type",
        "depends_on_caller",
        "caller_constraint",
    },
    "C": {
        "variable_match_score",
        "step_position_score",
        "dataflow_path_score",
        "overall_consistency",
        "comment",
    },
}

PHASE_C_SCORE_FIELDS = (
    "variable_match_score",
    "step_position_score",
    "dataflow_path_score",
)
def validate_phase_output(phase: str, value: Any) -> dict[str, Any]:
    """Return a plain dictionary after validating untrusted model output."""
    if phase not in REQUIRED_FIELDS:
        raise ValueError(f"unknown phase {phase!r}")
    if not isinstance(value, Mapping):
        raise ValueError(f"phase {phase} output must be a JSON object")

    result = dict(value)
    missing = REQUIRED_FIELDS[phase] - result.keys()
    if missing:
        raise ValueError(f"phase {phase} output is missing fields: {sorted(missing)}")

    if phase == "A":
        calls = result["non_standard_external_calls"]
        if not isinstance(calls, list) or not all(isinstance(item, str) for item in calls):
            raise ValueError("phase A non_standard_external_calls must be a string array")
        _require_string(result, "data_flow_path", "A", allow_empty=False)
        _validate_vulnerability_node(result["vulnerability_node"], "A")
        context = result["additional_context_needed"]
        if context is not None and not isinstance(context, str):
            raise ValueError("phase A additional_context_needed must be a string or null")
        confidence = result["confidence"]
        if isinstance(confidence, bool) or not isinstance(confidence, int):
            raise ValueError("phase A confidence must be an integer")
        if not 0 <= confidence <= 100:
            raise ValueError("phase A confidence must be in [0, 100]")
    elif phase == "B":
        for field in ("data_flow_path", "cwe_type"):
            _require_string(result, field, "B", allow_empty=False)
        _validate_vulnerability_node(result["vulnerability_node"], "B")
        if not isinstance(result["depends_on_caller"], bool):
            raise ValueError("phase B depends_on_caller must be boolean")
        constraint = result["caller_constraint"]
        if constraint is not None and not isinstance(constraint, str):
            raise ValueError("phase B caller_constraint must be a string or null")
    else:
        for field in PHASE_C_SCORE_FIELDS:
            score = result[field]
            if isinstance(score, bool) or not isinstance(score, (int, float)):
                raise ValueError(f"phase C {field} must be numeric")
        _require_string(result, "overall_consistency", "C", allow_empty=False)
        if isinstance(result["comment"], Mapping):
            result["comment"] = json.dumps(
                dict(result["comment"]),
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
            )
        _require_string(result, "comment", "C", allow_empty=False)

    return result


def _validate_vulnerability_node(value: Any, phase: str) -> None:
    if not isinstance(value, Mapping):
        raise ValueError(f"phase {phase} vulnerability_node must be a JSON object")
    required = {"variable_name", "step_location", "issue_description"}
    missing = required - value.keys()
    if missing:
        raise ValueError(
            f"phase {phase} vulnerability_node is missing fields: {sorted(missing)}"
        )
    for field in sorted(required):
        _require_string(value, field, phase, allow_empty=False)


def _require_string(
    value: Mapping[str, Any], field: str, phase: str, *, allow_empty: bool = True
) -> None:
    item = value[field]
    if not isinstance(item, str) or (not allow_empty and not item.strip()):
        suffix = "non-empty string" if not allow_empty else "string"
        raise ValueError(f"phase {phase} {field} must be a {suffix}")
