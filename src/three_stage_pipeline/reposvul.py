from __future__ import annotations

import csv
import difflib
import json
import os
import re
import tempfile
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib.parse import quote
from urllib.error import URLError
from urllib.request import Request, urlopen


DIVERSEVUL_COLUMNS = (
    "sample_id",
    "commit_id",
    "commit_short",
    "project",
    "func_before",
    "func_after",
    "diff",
    "diff_length",
    "commit_msg",
    "cwe",
    "commit_msg_anonymized",
)
MAX_CSV_FIELD_LENGTH = 131_072


class OversizedCsvFieldError(ValueError):
    pass


@dataclass(frozen=True)
class ConversionStats:
    read: int = 0
    candidates: int = 0
    written: int = 0
    skipped: int = 0
    duplicates: int = 0


@dataclass(frozen=True)
class MergeStats:
    sources: int = 0
    records: int = 0
    bytes_written: int = 0


def merge_reposvul_jsonl(sources: Iterable[Path], destination: Path) -> MergeStats:
    """Concatenate ReposVul JSONL splits atomically in the supplied order."""
    source_paths = [Path(source) for source in sources]
    if not source_paths:
        raise ValueError("at least one ReposVul JSONL source is required")
    for source in source_paths:
        if not source.is_file():
            raise ValueError(f"source file does not exist: {source}")
        if source.resolve() == destination.resolve():
            raise ValueError("merged destination must differ from every source")

    destination.parent.mkdir(parents=True, exist_ok=True)
    output_fd, output_name = tempfile.mkstemp(
        dir=destination.parent, suffix=".jsonl.tmp"
    )
    os.close(output_fd)
    output_tmp = Path(output_name)
    records = bytes_written = 0
    try:
        with output_tmp.open("wb") as output_handle:
            for source in source_paths:
                last_byte = b""
                with source.open("rb") as input_handle:
                    while chunk := input_handle.read(1024 * 1024):
                        output_handle.write(chunk)
                        records += chunk.count(b"\n")
                        bytes_written += len(chunk)
                        last_byte = chunk[-1:]
                if last_byte and last_byte != b"\n":
                    output_handle.write(b"\n")
                    records += 1
                    bytes_written += 1
        os.replace(output_tmp, destination)
    finally:
        output_tmp.unlink(missing_ok=True)
    return MergeStats(len(source_paths), records, bytes_written)


def _union_cwe_ids(existing: dict[str, Any], duplicate: dict[str, Any]) -> None:
    values: list[str] = []
    for record in (existing, duplicate):
        raw = record.get("cwe_id", [])
        items = raw if isinstance(raw, list) else [raw]
        for item in items:
            text = str(item).strip()
            if text and text not in values:
                values.append(text)
    existing["cwe_id"] = values


def _default_fetch_text(url: str, timeout: float) -> str:
    request = Request(url, headers={"User-Agent": "reposvul-pair-converter/1.0"})
    last_error: Exception | None = None
    for attempt in range(3):
        try:
            with urlopen(request, timeout=timeout) as response:
                return response.read().decode("utf-8", errors="replace")
        except (URLError, TimeoutError) as error:
            last_error = error
            if attempt < 2:
                time.sleep(2**attempt)
    assert last_error is not None
    raise last_error


def _function_key(function: str) -> str:
    header = function.split("{", 1)[0]
    names = re.findall(r"([A-Za-z_$][\w$]*)\s*\(", header)
    if not names:
        raise ValueError("cannot identify function name or declaration macro")
    return names[-1]


def _find_closing_brace(source: str, opening: int) -> int | None:
    depth = 0
    state = "code"
    escaped = False
    index = opening
    while index < len(source):
        char = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if state == "line_comment":
            if char == "\n":
                state = "code"
        elif state == "block_comment":
            if char == "*" and following == "/":
                state = "code"
                index += 1
        elif state in {"string", "char"}:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif (state == "string" and char == '"') or (
                state == "char" and char == "'"
            ):
                state = "code"
        elif char == "/" and following == "/":
            state = "line_comment"
            index += 1
        elif char == "/" and following == "*":
            state = "block_comment"
            index += 1
        elif char == '"':
            state = "string"
        elif char == "'":
            state = "char"
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index + 1
        index += 1
    return None


def find_matching_function(source: str, reference: str) -> str:
    """Extract the parent-version function matching a ReposVul function."""
    reference = reference.strip()
    if not reference:
        raise ValueError("reference function is empty")
    key = _function_key(reference)
    first_line = next(line.strip() for line in reference.splitlines() if line.strip())
    source_lines = source.splitlines(keepends=True)
    offsets: list[int] = []
    offset = 0
    for line in source_lines:
        stripped = line.strip()
        if stripped == first_line or re.search(rf"\b{re.escape(key)}\s*\(", line):
            offsets.append(offset + len(line) - len(line.lstrip()))
        offset += len(line)

    candidates: list[str] = []
    for start in dict.fromkeys(offsets):
        opening = source.find("{", start)
        if opening < 0:
            continue
        declaration = source[start:opening]
        if ";" in declaration or not re.search(
            rf"\b{re.escape(key)}\s*\(", declaration
        ):
            continue
        closing = _find_closing_brace(source, opening)
        if closing is not None:
            candidates.append(source[start:closing].strip())
    if not candidates:
        raise ValueError(f"matching function not found in parent file: {key}")
    return max(
        candidates,
        key=lambda item: difflib.SequenceMatcher(None, reference, item).ratio(),
    )


def _fixed_raw_url(record: dict[str, Any]) -> str:
    project = str(record.get("project", "")).strip().strip("/")
    file_name = str(record.get("file_name", "")).strip().replace("\\", "/")
    commit_id = str(record.get("commit_id", "")).strip()
    if not project or not file_name or not commit_id:
        raise ValueError("missing project, commit_id, or file_name")
    revision = quote(commit_id, safe="")
    return (
        f"https://raw.githubusercontent.com/{project}/{revision}/"
        f"{quote(file_name, safe='/')}"
    )


def _sample_id(record: dict[str, Any]) -> str:
    commit_id = str(record.get("commit_id", "")).strip()
    function_id = str(record.get("function_id", "")).strip()
    suffix = function_id.rsplit("_", 1)[-1] if "_" in function_id else function_id
    if not commit_id or not suffix:
        raise ValueError("missing commit_id or function_id")
    return f"{commit_id[:8]}_{suffix}"


def _make_diff(before: str, after: str) -> str:
    return "".join(
        difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile="before (vulnerable)",
            tofile="after (fixed)",
        )
    )


def convert_reposvul_jsonl(
    source: Path,
    destination: Path,
    *,
    error_path: Path,
    fetch_text: Callable[[str, float], str] = _default_fetch_text,
    timeout: float = 30.0,
    include_outdated: bool = False,
    progress_every: int = 50,
    workers: int = 8,
) -> ConversionStats:
    """Convert flattened ReposVul records into paired DiverseVul-style CSV."""
    if not source.is_file():
        raise ValueError(f"source file does not exist: {source}")
    if isinstance(workers, bool) or not isinstance(workers, int) or workers < 1:
        raise ValueError("workers must be a positive integer")
    destination.parent.mkdir(parents=True, exist_ok=True)
    error_path.parent.mkdir(parents=True, exist_ok=True)
    output_fd, output_name = tempfile.mkstemp(
        dir=destination.parent, suffix=".csv.tmp"
    )
    errors_fd, errors_name = tempfile.mkstemp(
        dir=error_path.parent, suffix=".jsonl.tmp"
    )
    os.close(output_fd)
    os.close(errors_fd)
    output_tmp = Path(output_name)
    errors_tmp = Path(errors_name)
    read = candidates = written = skipped = duplicates = 0
    cache: OrderedDict[str, str] = OrderedDict()
    try:
        with (
            source.open("r", encoding="utf-8-sig") as input_handle,
            output_tmp.open("w", encoding="utf-8", newline="") as output_handle,
            errors_tmp.open("w", encoding="utf-8", newline="\n") as error_handle,
        ):
            writer = csv.DictWriter(
                output_handle,
                fieldnames=DIVERSEVUL_COLUMNS,
                lineterminator="\n",
            )
            writer.writeheader()
            candidate_records: OrderedDict[str, tuple[int, dict[str, Any]]] = OrderedDict()
            for line_number, line in enumerate(input_handle, start=1):
                if not line.strip():
                    continue
                read += 1
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as error:
                    skipped += 1
                    error_handle.write(
                        json.dumps(
                            {
                                "line": line_number,
                                "sample_id": f"line-{line_number}",
                                "reason": type(error).__name__,
                                "message": str(error),
                            },
                            ensure_ascii=False,
                        )
                        + "\n"
                    )
                    continue
                if not isinstance(record, dict):
                    skipped += 1
                    error_handle.write(
                        json.dumps(
                            {
                                "line": line_number,
                                "sample_id": f"line-{line_number}",
                                "reason": "invalid_record",
                                "message": "JSONL item must be an object",
                            },
                            ensure_ascii=False,
                        )
                        + "\n"
                    )
                    continue
                if record.get("target") != 1:
                    continue
                sample = str(record.get("function_id", f"line-{line_number}"))
                if record.get("outdated") and not include_outdated:
                    skipped += 1
                    error_handle.write(
                        json.dumps(
                            {"line": line_number, "sample_id": sample, "reason": "outdated"}
                        )
                        + "\n"
                    )
                    continue
                function_id = str(record.get("function_id", "")).strip()
                if not function_id:
                    skipped += 1
                    error_handle.write(
                        json.dumps(
                            {
                                "line": line_number,
                                "sample_id": sample,
                                "reason": "missing_function_id",
                            },
                            ensure_ascii=False,
                        )
                        + "\n"
                    )
                    continue
                existing = candidate_records.get(function_id)
                if existing is not None:
                    duplicates += 1
                    _union_cwe_ids(existing[1], record)
                    continue
                candidate_records[function_id] = (line_number, record)

            candidate_items = list(candidate_records.values())
            candidates = len(candidate_items)
            batch_size = max(32, workers * 8)
            with ThreadPoolExecutor(max_workers=workers) as executor:
                for batch_start in range(0, candidates, batch_size):
                    batch = candidate_items[batch_start : batch_start + batch_size]
                    urls_by_function: dict[str, str] = {}
                    setup_errors: dict[str, Exception] = {}
                    for line_number, record in batch:
                        function_id = str(record.get("function_id", ""))
                        try:
                            urls_by_function[function_id] = _fixed_raw_url(record)
                        except Exception as error:
                            setup_errors[function_id] = error

                    missing_urls = list(
                        dict.fromkeys(
                            url
                            for url in urls_by_function.values()
                            if url not in cache
                        )
                    )
                    futures = {
                        url: executor.submit(fetch_text, url, timeout)
                        for url in missing_urls
                    }
                    fetch_errors: dict[str, Exception] = {}
                    for url, future in futures.items():
                        try:
                            cache[url] = future.result()
                        except Exception as error:
                            fetch_errors[url] = error

                    for batch_offset, (line_number, record) in enumerate(batch, start=1):
                        processed = batch_start + batch_offset
                        function_id = str(record.get("function_id", ""))
                        sample = function_id or f"line-{line_number}"
                        try:
                            if function_id in setup_errors:
                                raise setup_errors[function_id]
                            fixed_url = urls_by_function[function_id]
                            if fixed_url in fetch_errors:
                                raise fetch_errors[fixed_url]
                            cache.move_to_end(fixed_url)
                            before = str(record.get("function", "")).strip()
                            if not before:
                                raise ValueError("vulnerable function is empty")
                            after = find_matching_function(cache[fixed_url], before)
                            if before == after:
                                raise ValueError("unchanged")
                            diff = _make_diff(before, after)
                            commit_id = str(record.get("commit_id", "")).strip()
                            row = {
                                    "sample_id": _sample_id(record),
                                    "commit_id": commit_id,
                                    "commit_short": commit_id[:8],
                                    "project": str(record.get("project", "")),
                                    "func_before": before,
                                    "func_after": after,
                                    "diff": diff,
                                    "diff_length": len(diff),
                                    "commit_msg": str(record.get("commit_message", "")),
                                    "cwe": repr(record.get("cwe_id", [])),
                                    "commit_msg_anonymized": "",
                                }
                            oversized = {
                                key: len(str(value))
                                for key, value in row.items()
                                if len(str(value)) > MAX_CSV_FIELD_LENGTH
                            }
                            if oversized:
                                details = ", ".join(
                                    f"{key}={length}"
                                    for key, length in oversized.items()
                                )
                                raise OversizedCsvFieldError(details)
                            writer.writerow(row)
                            written += 1
                        except Exception as error:
                            skipped += 1
                            if str(error) == "unchanged":
                                reason = "unchanged"
                            elif isinstance(error, OversizedCsvFieldError):
                                reason = "oversized_csv_field"
                            else:
                                reason = type(error).__name__
                            error_handle.write(
                                json.dumps(
                                    {
                                        "line": line_number,
                                        "sample_id": sample,
                                        "reason": reason,
                                        "message": str(error),
                                    },
                                    ensure_ascii=False,
                                )
                                + "\n"
                            )
                        if progress_every and processed % progress_every == 0:
                            print(
                                f"processed candidates={processed}/{candidates} "
                                f"written={written} skipped={skipped}",
                                flush=True,
                            )
                    while len(cache) > 32:
                        cache.popitem(last=False)
        os.replace(output_tmp, destination)
        os.replace(errors_tmp, error_path)
    finally:
        output_tmp.unlink(missing_ok=True)
        errors_tmp.unlink(missing_ok=True)
    return ConversionStats(read, candidates, written, skipped, duplicates)
