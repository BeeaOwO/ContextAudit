from __future__ import annotations

import json
import hashlib
import os
import re
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Protocol

from .contracts import validate_phase_output
from .prompts import PROMPTS
from .results import write_final_record


class JsonModel(Protocol):
    def complete_json(self, system_prompt: str, user_prompt: str, phase: str) -> dict:
        """Return one decoded JSON object."""


class PhaseOutputValidationError(ValueError):
    """A decoded model response did not satisfy the phase contract."""

    def __init__(
        self, phase: str, model_output: dict[str, Any], cause: Exception
    ) -> None:
        self.phase = phase
        self.model_output = _redact_detail(model_output)
        super().__init__(
            f"phase {phase} output validation failed: "
            f"{type(cause).__name__}: {_safe_error_message(cause)}"
        )


@dataclass(frozen=True)
class PipelineInput:
    sample_id: str
    func_before: str
    func_after: str
    commit_msg: str = "No commit message"
    bug_description: str = "No description"
    commit_id: str = ""
    project: str = ""
    cwe: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.sample_id, str) or not self.sample_id.strip():
            raise ValueError("sample_id must be a non-empty string")
        for field in (
            "func_before",
            "func_after",
            "commit_msg",
            "bug_description",
            "commit_id",
            "project",
            "cwe",
        ):
            if not isinstance(getattr(self, field), str):
                raise ValueError(f"{field} must be a string")


@dataclass(frozen=True)
class PipelineIssue:
    sample_id: str
    phase: str
    error_type: str
    message: str
    timestamp_utc: str
    details: dict[str, Any]

    @classmethod
    def from_error(
        cls, sample_id: str, phase: str, error: Exception
    ) -> "PipelineIssue":
        return cls(
            sample_id=sample_id,
            phase=phase,
            error_type=type(error).__name__,
            message=_safe_error_message(error),
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
            details=_error_details(error),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp_utc": self.timestamp_utc,
            "sample_id": self.sample_id,
            "phase": self.phase,
            "error_type": self.error_type,
            "message": self.message,
            "details": self.details,
        }


@dataclass(frozen=True)
class PipelineRun:
    phase_a: dict[str, Any]
    phase_b: dict[str, Any]
    phase_c: dict[str, Any]
    result: dict[str, Any]
    issues: tuple[PipelineIssue, ...]


class ThreeStagePipeline:
    def __init__(
        self,
        model: JsonModel,
        output_dir: Path | str = "output",
        issue_reporter: Callable[[PipelineIssue], None] | None = None,
    ) -> None:
        self.model = model
        self.output_dir = Path(output_dir)
        self.issue_reporter = issue_reporter
        self.issues: list[PipelineIssue] = []

    def run(self, sample: PipelineInput) -> dict[str, Any]:
        analysis = self.analyze(sample)
        self.persist(sample, analysis)
        return analysis.result

    def analyze(self, sample: PipelineInput) -> PipelineRun:
        issue_count_before = len(self.issues)
        phase_a = self._run_phase_resilient(
            sample,
            "A",
            func_before=sample.func_before,
            bug_type=sample.cwe,
        )

        phase_b = self._run_phase_resilient(
            sample,
            "B",
            func_before=sample.func_before,
            func_after=sample.func_after,
            commit_msg=sample.commit_msg,
            bug_description=sample.bug_description,
            cwe_id=sample.cwe,
        )

        phase_c = self._run_phase_resilient(
            sample,
            "C",
            blind_report=json.dumps(phase_a, ensure_ascii=False, indent=2),
            omniscient_report=json.dumps(phase_b, ensure_ascii=False, indent=2),
        )

        result = _combined_result(sample, phase_a, phase_b, phase_c)
        return PipelineRun(
            phase_a=phase_a,
            phase_b=phase_b,
            phase_c=phase_c,
            result=result,
            issues=tuple(self.issues[issue_count_before:]),
        )

    def persist(self, sample: PipelineInput, analysis: PipelineRun) -> None:
        persist_pipeline_run(self.output_dir, sample, analysis)

    def write_issue_log(self, path: Path | str | None = None) -> Path:
        return write_pipeline_issue_log(self.output_dir, self.issues, path)

    def record_issue(
        self, sample_id: str, phase: str, error: Exception
    ) -> PipelineIssue:
        issue = PipelineIssue.from_error(sample_id, phase, error)
        self.issues.append(issue)
        if self.issue_reporter is not None:
            self.issue_reporter(issue)
        return issue

    def _run_phase_resilient(
        self, sample: PipelineInput, phase: str, **values: str
    ) -> dict[str, Any]:
        try:
            return self._run_phase(phase, **values)
        except Exception as error:
            issue = self.record_issue(sample.sample_id, phase, error)
            return _phase_placeholder(phase, sample, issue)

    def _run_phase(self, phase: str, **values: str) -> dict[str, Any]:
        prompt = PROMPTS[f"phase_{phase.lower()}"]
        model_output = self.model.complete_json(
            prompt["system"], prompt["user"].format(**values), phase
        )
        output = _normalize_phase_output(phase, model_output, values)
        try:
            return validate_phase_output(phase, output)
        except Exception as error:
            raise PhaseOutputValidationError(phase, model_output, error) from error

    def _write_phase(self, folder: str, sample_id: str, value: dict[str, Any]) -> None:
        _write_phase_json(self.output_dir, folder, sample_id, value)


def persist_pipeline_run(
    output_dir: Path | str,
    sample: PipelineInput,
    analysis: PipelineRun,
    *,
    write_final_csv: bool = True,
) -> None:
    destination = Path(output_dir)
    _write_phase_json(destination, "phase_a", sample.sample_id, analysis.phase_a)
    _write_phase_json(destination, "phase_b", sample.sample_id, analysis.phase_b)
    _write_phase_json(destination, "phase_c", sample.sample_id, analysis.phase_c)
    _write_phase_json(destination, "combined", sample.sample_id, analysis.result)
    if write_final_csv:
        write_final_record(destination / "final_results.csv", analysis.result)


def write_pipeline_issue_log(
    output_dir: Path | str,
    issues: list[PipelineIssue] | tuple[PipelineIssue, ...],
    path: Path | str | None = None,
) -> Path:
    destination = (
        Path(path) if path is not None else Path(output_dir) / "pipeline_errors.jsonl"
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = "".join(
        json.dumps(issue.to_dict(), ensure_ascii=False) + "\n" for issue in issues
    )
    _write_text_atomic(destination, payload)
    return destination


def _write_phase_json(
    output_dir: Path, folder: str, sample_id: str, value: dict[str, Any]
) -> None:
    filename = _safe_filename(sample_id) + ".json"
    destination = output_dir / folder / filename
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    _write_text_atomic(destination, payload)


def _write_text_atomic(destination: Path, payload: str) -> None:
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=destination.parent, delete=False
        ) as handle:
            handle.write(payload)
            temporary = Path(handle.name)
        os.replace(temporary, destination)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def _safe_error_message(error: Exception) -> str:
    message = " ".join(str(error).split()) or "no error message"
    message = re.sub(r"(?i)(bearer\s+)[^\s]+", r"\1[REDACTED]", message)
    message = re.sub(r"\bsk-[A-Za-z0-9_-]+", "sk-[REDACTED]", message)
    return message[:1000]


def _error_details(error: Exception) -> dict[str, Any]:
    details: dict[str, Any] = {}
    attempts = getattr(error, "attempts", None)
    if attempts:
        details["attempts"] = [dict(item) for item in attempts]
    model_output = getattr(error, "model_output", None)
    if model_output is not None:
        details["model_output"] = _redact_detail(model_output)

    cause_chain = []
    current = error.__cause__ or error.__context__
    seen = {id(error)}
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        cause_chain.append(
            {
                "error_type": type(current).__name__,
                "message": _safe_error_message(current),
            }
        )
        current = current.__cause__ or current.__context__
    if cause_chain:
        details["cause_chain"] = cause_chain
    return details


def _redact_detail(value: Any, key: str = "") -> Any:
    if re.search(r"(?i)(api[_-]?key|access[_-]?token|authorization|secret)", key):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): _redact_detail(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact_detail(item) for item in value]
    if isinstance(value, str):
        text = re.sub(r"(?i)(bearer\s+)[^\s,;]+", r"\1[REDACTED]", value)
        return re.sub(r"\bsk-[A-Za-z0-9_-]+", "sk-[REDACTED]", text)[:4000]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)[:4000]


def _phase_placeholder(
    phase: str, sample: PipelineInput, issue: PipelineIssue
) -> dict[str, Any]:
    metadata = {
        "pipeline_placeholder": True,
        "pipeline_error_type": issue.error_type,
        "pipeline_error": issue.message,
    }
    if phase == "A":
        return {
            "non_standard_external_calls": [],
            "data_flow_path": "[PHASE_A_ERROR]",
            "vulnerability_node": {
                "variable_name": "[PHASE_A_ERROR]",
                "step_location": "[PHASE_A_ERROR]",
                "issue_description": "阶段 A 执行失败，已使用占位结果。",
            },
            "confidence": 0,
            "additional_context_needed": issue.message,
            **metadata,
        }
    if phase == "B":
        return {
            "data_flow_path": "[PHASE_B_ERROR]",
            "vulnerability_node": {
                "variable_name": "[PHASE_B_ERROR]",
                "step_location": "[PHASE_B_ERROR]",
                "issue_description": "阶段 B 执行失败，已使用占位结果。",
            },
            "cwe_type": sample.cwe or "[PHASE_B_ERROR]",
            "depends_on_caller": False,
            "caller_constraint": issue.message,
            **metadata,
        }
    if phase == "C":
        return {
            "variable_match_score": 0.0,
            "step_position_score": 0.0,
            "dataflow_path_score": 0.0,
            "overall_consistency": "[PHASE_C_ERROR]",
            "comment": "阶段 C 执行失败，已使用占位结果。",
            **metadata,
        }
    raise ValueError(f"unknown phase {phase!r}")


def _safe_filename(sample_id: str) -> str:
    original = sample_id.strip()
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", original).strip("._")
    if not safe:
        raise ValueError("sample_id does not contain filename-safe characters")
    if safe != original or len(safe) > 120:
        digest = hashlib.sha256(original.encode("utf-8")).hexdigest()[:10]
        safe = f"{safe[:105]}__{digest}"
    return safe


def _normalize_phase_output(
    phase: str, output: dict[str, Any], prompt_values: dict[str, str]
) -> dict[str, Any]:
    """Preserve valid core analysis when a model omits non-core metadata."""
    result = dict(output)

    if phase == "A":
        result.setdefault("confidence", 0)
        result.setdefault("additional_context_needed", "模型未提供该字段")
    elif phase == "B":
        result.setdefault("cwe_type", prompt_values.get("cwe_id", "").strip() or "无法确定")
        result.setdefault("caller_constraint", None)
        result.setdefault(
            "depends_on_caller",
            isinstance(result["caller_constraint"], str)
            and bool(result["caller_constraint"].strip()),
        )
        cwe_type = result["cwe_type"]
        if isinstance(cwe_type, list) and cwe_type and all(
            isinstance(item, str) and item.strip() for item in cwe_type
        ):
            result["cwe_type"] = ", ".join(item.strip() for item in cwe_type)

    node = result.get("vulnerability_node")
    if phase in {"A", "B"} and isinstance(node, dict):
        normalized_node = dict(node)
        for field in ("variable_name", "step_location", "issue_description"):
            if field in normalized_node and (
                not isinstance(normalized_node[field], str)
                or not normalized_node[field].strip()
            ):
                normalized_node[field] = "无法确定"
        result["vulnerability_node"] = normalized_node

    return result


def _combined_result(
    sample: PipelineInput,
    phase_a: dict[str, Any],
    phase_b: dict[str, Any],
    phase_c: dict[str, Any],
) -> dict[str, Any]:
    return {
        "sample_id": sample.sample_id,
        "commit_id": sample.commit_id,
        "project": sample.project,
        "cwe": sample.cwe,
        "phase_a_non_standard_external_calls": phase_a["non_standard_external_calls"],
        "phase_a_data_flow_path": phase_a["data_flow_path"],
        "phase_a_vulnerability_variable": phase_a["vulnerability_node"]["variable_name"],
        "phase_a_vulnerability_step_location": phase_a["vulnerability_node"]["step_location"],
        "phase_a_vulnerability_issue_description": phase_a["vulnerability_node"]["issue_description"],
        "phase_a_confidence": phase_a["confidence"],
        "phase_a_additional_context_needed": phase_a["additional_context_needed"],
        "phase_a_raw": json.dumps(phase_a, ensure_ascii=False),
        "phase_b_data_flow_path": phase_b["data_flow_path"],
        "phase_b_vulnerability_variable": phase_b["vulnerability_node"]["variable_name"],
        "phase_b_vulnerability_step_location": phase_b["vulnerability_node"]["step_location"],
        "phase_b_vulnerability_issue_description": phase_b["vulnerability_node"]["issue_description"],
        "phase_b_cwe_type": phase_b["cwe_type"],
        "phase_b_depends_on_caller": phase_b["depends_on_caller"],
        "phase_b_caller_constraint": phase_b["caller_constraint"],
        "phase_b_raw": json.dumps(phase_b, ensure_ascii=False),
        "phase_c_variable_match_score": float(phase_c["variable_match_score"]),
        "phase_c_step_position_score": float(phase_c["step_position_score"]),
        "phase_c_dataflow_path_score": float(phase_c["dataflow_path_score"]),
        "phase_c_overall_consistency": phase_c["overall_consistency"],
        "phase_c_comment": phase_c["comment"],
        "phase_c_raw": json.dumps(phase_c, ensure_ascii=False),
    }
