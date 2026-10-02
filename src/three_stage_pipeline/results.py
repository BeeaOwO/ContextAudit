from __future__ import annotations

import csv
import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any


FINAL_CSV_COLUMNS = (
    "sample_id",
    "commit_id",
    "project",
    "cwe",
    "phase_a_non_standard_external_calls",
    "phase_a_data_flow_path",
    "phase_a_vulnerability_variable",
    "phase_a_vulnerability_step_location",
    "phase_a_vulnerability_issue_description",
    "phase_a_confidence",
    "phase_a_additional_context_needed",
    "phase_a_raw",
    "phase_b_data_flow_path",
    "phase_b_vulnerability_variable",
    "phase_b_vulnerability_step_location",
    "phase_b_vulnerability_issue_description",
    "phase_b_cwe_type",
    "phase_b_depends_on_caller",
    "phase_b_caller_constraint",
    "phase_b_raw",
    "phase_c_variable_match_score",
    "phase_c_step_position_score",
    "phase_c_dataflow_path_score",
    "phase_c_overall_consistency",
    "phase_c_comment",
    "phase_c_raw",
)
MAX_COMBINED_JSON_BYTES = 20 * 1024 * 1024


class FinalResultsStore:
    """Load once, apply many sample-id upserts, and flush atomically."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.rows: list[dict[str, str]] = []
        self.row_indexes: dict[str, int] = {}
        if self.path.exists():
            with self.path.open("r", encoding="utf-8-sig", newline="") as handle:
                reader = csv.DictReader(handle)
                if tuple(reader.fieldnames or ()) != FINAL_CSV_COLUMNS:
                    raise ValueError("existing final CSV header does not match current schema")
                for row in reader:
                    sample_id = row["sample_id"]
                    if sample_id in self.row_indexes:
                        raise ValueError(f"existing final CSV has duplicate sample_id: {sample_id}")
                    self.row_indexes[sample_id] = len(self.rows)
                    self.rows.append(row)

    def upsert(self, record: dict[str, Any]) -> None:
        _validate_record_columns(record)
        encoded = {key: _csv_cell(record[key]) for key in FINAL_CSV_COLUMNS}
        sample_id = encoded["sample_id"]
        index = self.row_indexes.get(sample_id)
        if index is None:
            self.row_indexes[sample_id] = len(self.rows)
            self.rows.append(encoded)
        else:
            self.rows[index] = encoded

    def flush(self) -> None:
        _write_rows_atomic(self.path, self.rows)


def write_final_record(path: Path, record: dict[str, Any]) -> None:
    """Atomically insert or replace a result row, keyed by sample_id."""
    store = FinalResultsStore(path)
    store.upsert(record)
    store.flush()


def rebuild_final_csv_from_combined(
    combined_dir: Path | str, output_path: Path | str
) -> int:
    """Replace a final CSV with all valid combined JSON records."""
    source = Path(combined_dir)
    destination = Path(output_path)
    if not source.is_dir():
        raise ValueError(f"combined directory does not exist: {source}")
    json_paths = list(source.glob("*.json"))
    if not json_paths:
        raise ValueError(f"combined directory contains no JSON files: {source}")
    json_paths.sort(key=_combined_sequence)

    sequences = [_combined_sequence(path) for path in json_paths]
    if len(sequences) != len(set(sequences)):
        raise ValueError("combined JSON filenames contain duplicate sample numbers")

    rows: list[dict[str, str]] = []
    seen_ids: set[str] = set()
    for json_path in json_paths:
        record = _read_combined_record(json_path)
        _validate_record_columns(record)
        sample_id = record["sample_id"]
        if not isinstance(sample_id, str) or not sample_id.strip():
            raise ValueError(f"{json_path.name}: sample_id must be a non-empty string")
        if sample_id in seen_ids:
            raise ValueError(f"duplicate sample_id in combined JSON: {sample_id}")
        seen_ids.add(sample_id)
        rows.append({key: _csv_cell(record[key]) for key in FINAL_CSV_COLUMNS})

    _write_rows_atomic(destination, rows)
    return len(rows)


def _combined_sequence(path: Path) -> int:
    match = re.search(r"_(\d+)\.json\Z", path.name)
    if match is None:
        raise ValueError(
            f"{path.name}: filename must end with a trailing sample number such as _349.json"
        )
    return int(match.group(1))


def _read_combined_record(path: Path) -> dict[str, Any]:
    if path.stat().st_size > MAX_COMBINED_JSON_BYTES:
        raise ValueError(f"{path.name}: JSON exceeds {MAX_COMBINED_JSON_BYTES} bytes")
    try:
        decoded = json.loads(
            path.read_text(encoding="utf-8"),
            parse_constant=_reject_json_constant,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError(f"{path.name}: invalid combined JSON: {error}") from error
    if not isinstance(decoded, dict):
        raise ValueError(f"{path.name}: combined JSON must be an object")
    return decoded


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")


def _validate_record_columns(record: dict[str, Any]) -> None:
    unexpected = set(record) - set(FINAL_CSV_COLUMNS)
    missing = set(FINAL_CSV_COLUMNS) - set(record)
    if unexpected or missing:
        raise ValueError(
            f"final CSV record columns differ; missing={sorted(missing)}, "
            f"unexpected={sorted(unexpected)}"
        )


def _write_rows_atomic(path: Path, rows: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8-sig", newline="", dir=path.parent, delete=False
        ) as handle:
            writer = csv.DictWriter(handle, fieldnames=FINAL_CSV_COLUMNS)
            writer.writeheader()
            writer.writerows(rows)
            temporary = Path(handle.name)
        os.replace(temporary, path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def initialize_final_csv(path: Path) -> None:
    """Create an empty final results file with the current header."""
    if path.exists():
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        csv.writer(handle).writerow(FINAL_CSV_COLUMNS)


def _csv_cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, dict)):
        text = json.dumps(value, ensure_ascii=False, allow_nan=False)
    else:
        text = str(value)
    text = text.replace("\x00", r"\0")
    if text.startswith(("=", "+", "-", "@")):
        return "'" + text
    return text
