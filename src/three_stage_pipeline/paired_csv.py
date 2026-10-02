from __future__ import annotations

import csv
import difflib
import hashlib
import json
import os
import re
import tempfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

from .reposvul import DIVERSEVUL_COLUMNS


@dataclass(frozen=True)
class PairedCsvConversionStats:
    read: int = 0
    written: int = 0
    invalid: int = 0
    unchanged: int = 0
    duplicates: int = 0


@dataclass(frozen=True)
class PrimeVulConversionStats:
    read_pairs: int = 0
    written: int = 0
    invalid: int = 0
    metadata_mismatches: int = 0


@dataclass(frozen=True)
class DeduplicationStats:
    read: int = 0
    written: int = 0
    within_dataset_duplicates: int = 0
    cross_dataset_duplicates: int = 0


def _clean(value: object) -> str:
    return str(value).replace("\0", "").strip() if value is not None else ""


def _commit_id(url: str) -> str:
    matches = re.findall(r"(?<![0-9a-fA-F])[0-9a-fA-F]{7,64}(?![0-9a-fA-F])", url)
    return matches[-1] if matches else ""


def _project(url: str) -> str:
    parts = [part for part in urlparse(url).path.split("/") if part]
    marker = next(
        (index for index, part in enumerate(parts) if part in {"commit", "commits"}),
        None,
    )
    if marker is None:
        return ""
    project_parts = [part for part in parts[:marker] if part != "-"]
    if len(project_parts) < 2:
        return ""
    return "/".join(project_parts)


def _cwe_values(raw: str) -> list[str]:
    matches = re.findall(
        r"(?:NVD-)?CWE-(?:\d+|[A-Za-z][A-Za-z0-9_-]*)",
        raw,
        flags=re.IGNORECASE,
    )
    values: list[str] = []
    for match in matches:
        prefix = "NVD-CWE-" if match.lower().startswith("nvd-cwe-") else "CWE-"
        suffix = match[len(prefix) :]
        if suffix.isdigit():
            normalized = f"CWE-{int(suffix)}"
        elif suffix.lower() == "noinfo":
            normalized = f"{prefix}noinfo"
        elif suffix.lower() == "other":
            normalized = f"{prefix}Other"
        else:
            normalized = f"{prefix}{suffix}"
        if normalized not in values:
            values.append(normalized)
    return values


def _diff(before: str, after: str) -> str:
    return "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile="before (vulnerable)",
            tofile="after (fixed)",
        )
    )


def _source_fields(row: dict[str, str], dataset: str) -> tuple[str, str, str, str]:
    if dataset == "titanvul":
        url = _clean(row.get("commit_link"))
        return url, _clean(row.get("commit_message")), "", _clean(row.get("cwe_id"))
    if dataset == "benchvul":
        url = _clean(row.get("commit_link"))
        return (
            url,
            _clean(row.get("commit_msg")),
            _clean(row.get("repo_name")),
            _clean(row.get("cwe_id")),
        )
    if dataset == "vulnerability_score":
        url = _clean(row.get("commit_url"))
        return url, _clean(row.get("commit_msg")), "", _clean(row.get("cwe_id"))
    raise ValueError(f"unsupported dataset: {dataset}")


def convert_paired_csv(
    source: Path,
    destination: Path,
    *,
    dataset: str,
    error_path: Path | None = None,
) -> PairedCsvConversionStats:
    source = Path(source)
    destination = Path(destination)
    if not source.is_file():
        raise ValueError(f"source file does not exist: {source}")
    if source.resolve() == destination.resolve():
        raise ValueError("destination must differ from source")
    if dataset not in {"titanvul", "benchvul", "vulnerability_score"}:
        raise ValueError(f"unsupported dataset: {dataset}")
    error_path = Path(error_path) if error_path else destination.with_suffix(".skipped.jsonl")
    destination.parent.mkdir(parents=True, exist_ok=True)
    error_path.parent.mkdir(parents=True, exist_ok=True)

    output_fd, output_name = tempfile.mkstemp(dir=destination.parent, suffix=".csv.tmp")
    error_fd, error_name = tempfile.mkstemp(dir=error_path.parent, suffix=".jsonl.tmp")
    os.close(output_fd)
    os.close(error_fd)
    output_tmp = Path(output_name)
    error_tmp = Path(error_name)
    read = written = invalid = unchanged = duplicates = 0
    seen: set[str] = set()
    csv.field_size_limit(2_147_483_647)

    try:
        with (
            source.open("r", encoding="utf-8-sig", errors="replace", newline="") as input_handle,
            output_tmp.open("w", encoding="utf-8-sig", newline="") as output_handle,
            error_tmp.open("w", encoding="utf-8", newline="\n") as errors_handle,
        ):
            reader = csv.DictReader(input_handle)
            required = {"func_before", "func_after"}
            missing = required - set(reader.fieldnames or [])
            if missing:
                raise ValueError(f"input CSV is missing required columns: {sorted(missing)}")
            writer = csv.DictWriter(output_handle, fieldnames=DIVERSEVUL_COLUMNS, lineterminator="\n")
            writer.writeheader()

            for row_number, row in enumerate(reader, start=1):
                read += 1
                before = _clean(row.get("func_before"))
                after = _clean(row.get("func_after"))
                reason = ""
                if not before or not after:
                    invalid += 1
                    reason = "missing_function"
                elif before == after:
                    unchanged += 1
                    reason = "unchanged_pair"
                else:
                    pair_key = hashlib.sha256(
                        (before + "\0" + after).encode("utf-8", errors="replace")
                    ).hexdigest()
                    if pair_key in seen:
                        duplicates += 1
                        reason = "duplicate_pair"
                    else:
                        seen.add(pair_key)

                if reason:
                    errors_handle.write(
                        json.dumps({"row": row_number, "reason": reason}, ensure_ascii=False) + "\n"
                    )
                    continue

                url, commit_message, explicit_project, raw_cwe = _source_fields(row, dataset)
                commit_id = _commit_id(url)
                project = explicit_project or _project(url)
                sample_prefix = commit_id[:8] or dataset.replace("vulnerability_score", "vscore")
                diff = _diff(before, after)
                writer.writerow(
                    {
                        "sample_id": f"{sample_prefix}_{row_number}",
                        "commit_id": commit_id,
                        "commit_short": commit_id[:8],
                        "project": project,
                        "func_before": before,
                        "func_after": after,
                        "diff": diff,
                        "diff_length": len(diff),
                        "commit_msg": commit_message,
                        "cwe": json.dumps(_cwe_values(raw_cwe), ensure_ascii=False),
                        "commit_msg_anonymized": "",
                    }
                )
                written += 1
        os.replace(output_tmp, destination)
        os.replace(error_tmp, error_path)
    finally:
        output_tmp.unlink(missing_ok=True)
        error_tmp.unlink(missing_ok=True)

    return PairedCsvConversionStats(read, written, invalid, unchanged, duplicates)


def convert_primevul_jsonl(
    sources: Iterable[Path],
    destination: Path,
    *,
    error_path: Path | None = None,
) -> PrimeVulConversionStats:
    source_paths = [Path(source) for source in sources]
    if not source_paths or any(not source.is_file() for source in source_paths):
        raise ValueError("all PrimeVul sources must be existing JSONL files")
    destination = Path(destination)
    error_path = Path(error_path) if error_path else destination.with_suffix(".skipped.jsonl")
    destination.parent.mkdir(parents=True, exist_ok=True)
    error_path.parent.mkdir(parents=True, exist_ok=True)
    output_fd, output_name = tempfile.mkstemp(dir=destination.parent, suffix=".csv.tmp")
    error_fd, error_name = tempfile.mkstemp(dir=error_path.parent, suffix=".jsonl.tmp")
    os.close(output_fd)
    os.close(error_fd)
    output_tmp = Path(output_name)
    error_tmp = Path(error_name)
    read_pairs = written = invalid = metadata_mismatches = 0

    try:
        with (
            output_tmp.open("w", encoding="utf-8-sig", newline="") as output_handle,
            error_tmp.open("w", encoding="utf-8", newline="\n") as errors_handle,
        ):
            writer = csv.DictWriter(output_handle, fieldnames=DIVERSEVUL_COLUMNS, lineterminator="\n")
            writer.writeheader()
            for source in source_paths:
                pending: dict[str, object] | None = None
                with source.open("r", encoding="utf-8-sig", errors="replace") as input_handle:
                    for line_number, line in enumerate(input_handle, start=1):
                        if not line.strip():
                            continue
                        try:
                            record = json.loads(line)
                        except json.JSONDecodeError as error:
                            invalid += 1
                            pending = None
                            errors_handle.write(
                                json.dumps(
                                    {
                                        "source": source.name,
                                        "line": line_number,
                                        "reason": "invalid_json",
                                        "message": str(error),
                                    },
                                    ensure_ascii=False,
                                )
                                + "\n"
                            )
                            continue
                        if not isinstance(record, dict):
                            invalid += 1
                            pending = None
                            continue
                        if pending is None:
                            pending = record
                            continue
                        before_record, after_record = pending, record
                        pending = None
                        read_pairs += 1
                        reason = ""
                        if before_record.get("target") != 1 or after_record.get("target") != 0:
                            invalid += 1
                            reason = "invalid_target_order"
                        elif (
                            before_record.get("commit_id") != after_record.get("commit_id")
                            or before_record.get("cve") != after_record.get("cve")
                        ):
                            metadata_mismatches += 1
                            reason = "metadata_mismatch"
                        before = _clean(before_record.get("func"))
                        after = _clean(after_record.get("func"))
                        if not reason and (not before or not after):
                            invalid += 1
                            reason = "missing_function"
                        if not reason and before == after:
                            invalid += 1
                            reason = "unchanged_pair"
                        if reason:
                            errors_handle.write(
                                json.dumps(
                                    {
                                        "source": source.name,
                                        "pair": read_pairs,
                                        "reason": reason,
                                    },
                                    ensure_ascii=False,
                                )
                                + "\n"
                            )
                            continue
                        commit_id = _clean(before_record.get("commit_id"))
                        diff = _diff(before, after)
                        writer.writerow(
                            {
                                "sample_id": f"{commit_id[:8] or 'primevul'}_{read_pairs}",
                                "commit_id": commit_id,
                                "commit_short": commit_id[:8],
                                "project": _clean(before_record.get("project")),
                                "func_before": before,
                                "func_after": after,
                                "diff": diff,
                                "diff_length": len(diff),
                                "commit_msg": _clean(before_record.get("commit_message")),
                                "cwe": json.dumps(
                                    _cwe_values(str(before_record.get("cwe", ""))),
                                    ensure_ascii=False,
                                ),
                                "commit_msg_anonymized": "",
                            }
                        )
                        written += 1
                if pending is not None:
                    invalid += 1
                    errors_handle.write(
                        json.dumps(
                            {"source": source.name, "reason": "unpaired_final_record"},
                            ensure_ascii=False,
                        )
                        + "\n"
                    )
        os.replace(output_tmp, destination)
        os.replace(error_tmp, error_path)
    finally:
        output_tmp.unlink(missing_ok=True)
        error_tmp.unlink(missing_ok=True)
    return PrimeVulConversionStats(read_pairs, written, invalid, metadata_mismatches)


def _pipeline_rows(path: Path):
    csv.field_size_limit(2_147_483_647)
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        missing = set(DIVERSEVUL_COLUMNS) - set(reader.fieldnames or [])
        if missing:
            raise ValueError(f"pipeline CSV is missing columns {sorted(missing)}: {path}")
        yield from reader


def _pair_key(row: dict[str, str]) -> str:
    before = _clean(row.get("func_before"))
    after = _clean(row.get("func_after"))
    return hashlib.sha256((before + "\0" + after).encode("utf-8", errors="replace")).hexdigest()


def deduplicate_pipeline_csvs(
    datasets: Iterable[tuple[str, Path, Path]],
) -> dict[str, DeduplicationStats]:
    items = [(name, Path(source), Path(destination)) for name, source, destination in datasets]
    if not items or len({name for name, _, _ in items}) != len(items):
        raise ValueError("dataset names must be non-empty and unique")
    owners: dict[str, int] = {}
    metadata: dict[str, dict[str, object]] = {}
    counters: dict[str, Counter[str]] = {name: Counter() for name, _, _ in items}

    for dataset_index, (name, source, _) in enumerate(items):
        seen_here: set[str] = set()
        for row in _pipeline_rows(source):
            counters[name]["read"] += 1
            key = _pair_key(row)
            if key in seen_here:
                counters[name]["within"] += 1
            else:
                seen_here.add(key)
                if key not in owners:
                    owners[key] = dataset_index
                elif owners[key] != dataset_index:
                    counters[name]["cross"] += 1
            values = metadata.setdefault(
                key,
                {"commit_id": "", "commit_short": "", "project": "", "commit_msg": "", "cwes": []},
            )
            for field in ("commit_id", "commit_short", "project", "commit_msg"):
                if not values[field] and _clean(row.get(field)):
                    values[field] = _clean(row.get(field))
            cwes = values["cwes"]
            assert isinstance(cwes, list)
            for cwe in _cwe_values(_clean(row.get("cwe"))):
                if cwe not in cwes:
                    cwes.append(cwe)

    temporary_outputs: list[tuple[Path, Path]] = []
    try:
        for dataset_index, (name, source, destination) in enumerate(items):
            destination.parent.mkdir(parents=True, exist_ok=True)
            output_fd, output_name = tempfile.mkstemp(dir=destination.parent, suffix=".csv.tmp")
            os.close(output_fd)
            output_tmp = Path(output_name)
            temporary_outputs.append((output_tmp, destination))
            emitted: set[str] = set()
            with output_tmp.open("w", encoding="utf-8-sig", newline="") as output_handle:
                writer = csv.DictWriter(
                    output_handle,
                    fieldnames=DIVERSEVUL_COLUMNS,
                    lineterminator="\n",
                )
                writer.writeheader()
                for row in _pipeline_rows(source):
                    key = _pair_key(row)
                    if owners[key] != dataset_index or key in emitted:
                        continue
                    emitted.add(key)
                    merged = metadata[key]
                    before = _clean(row.get("func_before"))
                    after = _clean(row.get("func_after"))
                    diff = _diff(before, after)
                    for field in ("commit_id", "commit_short", "project", "commit_msg"):
                        row[field] = str(merged[field])
                    row["func_before"] = before
                    row["func_after"] = after
                    row["diff"] = diff
                    row["diff_length"] = str(len(diff))
                    row["cwe"] = json.dumps(merged["cwes"], ensure_ascii=False)
                    writer.writerow({field: row.get(field, "") for field in DIVERSEVUL_COLUMNS})
                    counters[name]["written"] += 1
        for output_tmp, destination in temporary_outputs:
            os.replace(output_tmp, destination)
    finally:
        for output_tmp, _ in temporary_outputs:
            output_tmp.unlink(missing_ok=True)

    return {
        name: DeduplicationStats(
            read=counts["read"],
            written=counts["written"],
            within_dataset_duplicates=counts["within"],
            cross_dataset_duplicates=counts["cross"],
        )
        for name, counts in counters.items()
    }
