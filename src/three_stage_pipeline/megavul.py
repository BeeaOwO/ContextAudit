from __future__ import annotations

import csv
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from .reposvul import DIVERSEVUL_COLUMNS


@dataclass(frozen=True)
class MegaVulConversionStats:
    read: int = 0
    candidates: int = 0
    written: int = 0
    filtered: int = 0
    invalid: int = 0


def _nonempty_text(record: dict[str, Any], field: str) -> str | None:
    value = record.get(field)
    if not isinstance(value, str) or not value.strip():
        return None
    return value


def _line_count(text: str) -> int:
    return len(text.splitlines())


def _iter_json_array(source: Path, *, chunk_size: int = 1024 * 1024) -> Iterator[Any]:
    """Yield items from a top-level JSON array without loading the whole file."""
    decoder = json.JSONDecoder()
    with source.open("r", encoding="utf-8-sig") as handle:
        buffer = ""
        position = 0
        eof = False

        def read_more() -> None:
            nonlocal buffer, position, eof
            buffer = buffer[position:]
            position = 0
            chunk = handle.read(chunk_size)
            if chunk:
                buffer += chunk
            else:
                eof = True

        def skip_whitespace() -> None:
            nonlocal position
            while True:
                while position < len(buffer) and buffer[position].isspace():
                    position += 1
                if position < len(buffer) or eof:
                    return
                read_more()

        read_more()
        skip_whitespace()
        if position >= len(buffer) or buffer[position] != "[":
            raise ValueError("MegaVul input must be a JSON array")
        position += 1
        first = True

        while True:
            skip_whitespace()
            if position >= len(buffer):
                raise ValueError("unterminated MegaVul JSON array")
            if buffer[position] == "]":
                position += 1
                break
            if not first:
                if buffer[position] != ",":
                    raise ValueError("expected ',' between MegaVul JSON records")
                position += 1
                skip_whitespace()

            while True:
                try:
                    item, end = decoder.raw_decode(buffer, position)
                    position = end
                    break
                except json.JSONDecodeError as error:
                    if eof:
                        raise ValueError("invalid or truncated MegaVul JSON") from error
                    read_more()
            yield item
            first = False

        trailing = buffer[position:] + handle.read()
        if trailing.strip():
            raise ValueError("unexpected content after MegaVul JSON array")


def convert_megavul_json(
    source: Path,
    destination: Path,
    *,
    max_diff_chars: int = 1500,
    max_function_chars: int = 5000,
    max_function_lines: int = 500,
) -> MegaVulConversionStats:
    """Convert filtered vulnerable MegaVul pairs to DiverseVul-compatible CSV."""
    source = Path(source)
    destination = Path(destination)
    if not source.is_file():
        raise ValueError(f"source file does not exist: {source}")
    if source.resolve() == destination.resolve():
        raise ValueError("destination must differ from source")
    for name, limit in (
        ("max_diff_chars", max_diff_chars),
        ("max_function_chars", max_function_chars),
        ("max_function_lines", max_function_lines),
    ):
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError(f"{name} must be a positive integer")

    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".tmp")
    read = candidates = written = filtered = invalid = 0
    try:
        with temporary.open("w", encoding="utf-8", newline="") as output_handle:
            writer = csv.DictWriter(
                output_handle, fieldnames=DIVERSEVUL_COLUMNS, lineterminator="\n"
            )
            writer.writeheader()
            for record_index, record in enumerate(_iter_json_array(source)):
                read += 1
                if not isinstance(record, dict):
                    invalid += 1
                    continue
                if record.get("is_vul") is not True:
                    continue
                candidates += 1
                before = _nonempty_text(record, "func_before")
                after = _nonempty_text(record, "func")
                diff = _nonempty_text(record, "diff_func")
                if before is None or after is None or diff is None:
                    invalid += 1
                    continue
                if (
                    len(diff) > max_diff_chars
                    or len(before) > max_function_chars
                    or len(after) > max_function_chars
                    or _line_count(before) > max_function_lines
                    or _line_count(after) > max_function_lines
                ):
                    filtered += 1
                    continue

                commit_id = str(record.get("commit_hash", "")).strip()
                commit_short = commit_id[:8]
                sample_prefix = commit_short or "megavul"
                cwe_ids = record.get("cwe_ids")
                if not isinstance(cwe_ids, list):
                    cwe_ids = []
                writer.writerow(
                    {
                        "sample_id": f"{sample_prefix}_{record_index}",
                        "commit_id": commit_id,
                        "commit_short": commit_short,
                        "project": str(record.get("repo_name", "")),
                        "func_before": before,
                        "func_after": after,
                        "diff": diff,
                        "diff_length": len(diff),
                        "commit_msg": str(record.get("commit_msg", "")),
                        "cwe": json.dumps(cwe_ids, ensure_ascii=False),
                        "commit_msg_anonymized": "",
                    }
                )
                written += 1
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)

    return MegaVulConversionStats(
        read=read,
        candidates=candidates,
        written=written,
        filtered=filtered,
        invalid=invalid,
    )
