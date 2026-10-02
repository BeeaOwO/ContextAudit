from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .pipeline import PipelineInput


MAX_JSON_INPUT_BYTES = 20 * 1024 * 1024
MAX_CSV_INPUT_BYTES = 4 * 1024 * 1024 * 1024
MAX_PARQUET_INPUT_BYTES = 1024 * 1024 * 1024
PREFERRED_CSV = "diversevul_paired_anonymized.csv"
PREFERRED_PARQUET = "diversevul_paired_anonymized.parquet"
SUPPORTED_SUFFIXES = {".csv", ".json", ".jsonl", ".parquet"}
INPUT_FIELDS = {
    "sample_id",
    "func_before",
    "func_after",
    "commit_msg",
    "bug_description",
    "commit_id",
    "project",
    "cwe",
}


def load_inputs(
    path: Path, *, start: int = 1, end: int | None = None
) -> list[PipelineInput]:
    """Load a 1-based inclusive sample range from a file or input directory."""
    _validate_range(start, end)
    source = _resolve_source(path)
    suffix = source.suffix.lower()
    if suffix == ".csv":
        samples = _load_csv(source, start, end)
    elif suffix == ".parquet":
        samples = _load_parquet(source, start, end)
    else:
        records = _load_json_records(source)
        samples = _records_to_inputs(records[start - 1 : end])
    if not samples:
        raise ValueError(f"selected range {start}..{end or 'end'} contains no samples")
    return samples


def load_inputs_by_sample_ids(
    path: Path,
    sample_ids: list[str] | tuple[str, ...],
    *,
    csv_chunk_size: int = 1000,
) -> list[PipelineInput]:
    """Load selected samples without reading a large CSV into memory at once."""
    requested = list(dict.fromkeys(sample_ids))
    if not requested or any(
        not isinstance(sample_id, str) or not sample_id.strip()
        for sample_id in requested
    ):
        raise ValueError("sample_ids must contain at least one non-empty string")
    if (
        isinstance(csv_chunk_size, bool)
        or not isinstance(csv_chunk_size, int)
        or csv_chunk_size < 1
    ):
        raise ValueError("csv_chunk_size must be a positive integer")

    source = _resolve_source(path)
    if source.suffix.lower() != ".csv":
        return _select_samples(load_inputs(source, start=1, end=None), requested)
    if source.stat().st_size > MAX_CSV_INPUT_BYTES:
        raise ValueError(f"CSV input exceeds {MAX_CSV_INPUT_BYTES} bytes")

    try:
        import pandas as pd
    except ImportError as error:
        raise ValueError("CSV input requires the pandas package") from error

    found: dict[str, PipelineInput] = {}
    requested_set = set(requested)
    reader = pd.read_csv(
        source,
        chunksize=csv_chunk_size,
        keep_default_na=True,
        dtype={"sample_id": "string"},
    )
    try:
        for frame in reader:
            if "sample_id" not in frame.columns:
                raise ValueError("input CSV is missing required column: sample_id")
            matching_rows = frame[frame["sample_id"].isin(requested_set)]
            for sample in _frame_to_inputs(matching_rows):
                if sample.sample_id in found:
                    raise ValueError(f"duplicate sample_id in input: {sample.sample_id}")
                found[sample.sample_id] = sample
            if len(found) == len(requested):
                break
    finally:
        reader.close()
    return _select_samples(list(found.values()), requested)


def _select_samples(
    samples: list[PipelineInput], requested: list[str]
) -> list[PipelineInput]:
    by_id = {sample.sample_id: sample for sample in samples}
    missing = [sample_id for sample_id in requested if sample_id not in by_id]
    if missing:
        raise ValueError(f"error sample IDs not found in input: {missing}")
    return [by_id[sample_id] for sample_id in requested]


def _resolve_source(path: Path) -> Path:
    if path.is_file():
        if path.suffix.lower() not in SUPPORTED_SUFFIXES:
            raise ValueError(f"unsupported input format: {path.suffix}")
        return path
    if not path.is_dir():
        raise ValueError(f"input path does not exist: {path}")

    for preferred_name in (PREFERRED_CSV, PREFERRED_PARQUET):
        preferred = path / preferred_name
        if preferred.is_file():
            return preferred
    candidates = sorted(
        item for item in path.iterdir() if item.is_file() and item.suffix.lower() in SUPPORTED_SUFFIXES
    )
    if not candidates:
        raise ValueError(f"input directory contains no CSV, JSON, JSONL, or Parquet files: {path}")
    if len(candidates) > 1:
        names = ", ".join(item.name for item in candidates)
        raise ValueError(f"input directory is ambiguous; pass one file explicitly: {names}")
    return candidates[0]


def _load_json_records(path: Path) -> list[dict[str, Any]]:
    if path.stat().st_size > MAX_JSON_INPUT_BYTES:
        raise ValueError(f"JSON input exceeds {MAX_JSON_INPUT_BYTES} bytes")
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".jsonl":
        records = [
            json.loads(line, parse_constant=_reject_constant)
            for line in text.splitlines()
            if line.strip()
        ]
    else:
        decoded = json.loads(text, parse_constant=_reject_constant)
        records = decoded if isinstance(decoded, list) else [decoded]
    return records


def _load_parquet(path: Path, start: int, end: int | None) -> list[PipelineInput]:
    if path.stat().st_size > MAX_PARQUET_INPUT_BYTES:
        raise ValueError(f"Parquet input exceeds {MAX_PARQUET_INPUT_BYTES} bytes")
    try:
        import pandas as pd

        frame = pd.read_parquet(path)
    except ImportError as error:
        raise ValueError("Parquet input requires the pandas and pyarrow packages") from error

    return _frame_to_inputs(frame.iloc[start - 1 : end])


def _load_csv(path: Path, start: int, end: int | None) -> list[PipelineInput]:
    if path.stat().st_size > MAX_CSV_INPUT_BYTES:
        raise ValueError(f"CSV input exceeds {MAX_CSV_INPUT_BYTES} bytes")
    try:
        import pandas as pd
    except ImportError as error:
        raise ValueError("CSV input requires the pandas package") from error

    row_count = None if end is None else end - start + 1
    frame = pd.read_csv(
        path,
        skiprows=range(1, start),
        nrows=row_count,
        keep_default_na=True,
    )
    return _frame_to_inputs(frame)


def _frame_to_inputs(frame: Any) -> list[PipelineInput]:
    samples = []
    for _, row in frame.iterrows():
        commit_msg = _row_text(row, "commit_msg_anonymized", "") or _row_text(
            row, "commit_msg", "No commit message"
        )
        bug_description = _row_text(row, "bug_description_anonymized", "") or _row_text(
            row, "bug_description", "No description"
        )
        samples.append(
            PipelineInput(
                sample_id=_row_text(row, "sample_id", ""),
                func_before=_row_text(row, "func_before", ""),
                func_after=_row_text(row, "func_after", ""),
                commit_msg=commit_msg,
                bug_description=bug_description,
                commit_id=_row_text(row, "commit_id", ""),
                project=_row_text(row, "project", ""),
                cwe=_row_text(row, "cwe", ""),
            )
        )
    return samples


def _row_text(row: Any, key: str, default: str) -> str:
    value = row.get(key, default)
    try:
        import pandas as pd

        if value is None or pd.isna(value):
            return default
    except (ImportError, TypeError, ValueError):
        if value is None:
            return default
    text = str(value)
    return text if text.strip() else default


def _records_to_inputs(records: list[Any]) -> list[PipelineInput]:
    samples: list[PipelineInput] = []
    seen_ids: set[str] = set()
    for position, record in enumerate(records, start=1):
        if not isinstance(record, dict):
            raise ValueError(f"input item {position} must be a JSON object")
        unknown = set(record) - INPUT_FIELDS
        if unknown:
            raise ValueError(f"input item {position} has unknown fields: {sorted(unknown)}")
        try:
            sample = PipelineInput(**record)
        except TypeError as error:
            raise ValueError(f"input item {position} has invalid fields: {error}") from error
        if sample.sample_id in seen_ids:
            raise ValueError(f"duplicate sample_id: {sample.sample_id}")
        seen_ids.add(sample.sample_id)
        samples.append(sample)
    return samples


def _validate_range(start: int, end: int | None) -> None:
    if isinstance(start, bool) or not isinstance(start, int) or start < 1:
        raise ValueError("start must be an integer greater than or equal to 1")
    if end is not None:
        if isinstance(end, bool) or not isinstance(end, int) or end < start:
            raise ValueError("end must be an integer greater than or equal to start")


def _reject_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")
