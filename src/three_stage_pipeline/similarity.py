from __future__ import annotations

import codecs
import csv
import json
import os
import tempfile
from collections import Counter
from dataclasses import asdict, dataclass
from decimal import Decimal, InvalidOperation, ROUND_CEILING, ROUND_HALF_UP
from pathlib import Path
from statistics import median
from typing import Any




SCORE_COLUMNS = (
    "phase_c_variable_match_score",
    "phase_c_step_position_score",
    "phase_c_dataflow_path_score",
)
PHASE_RAW_COLUMNS = ("phase_a_raw", "phase_b_raw", "phase_c_raw")


@dataclass(frozen=True)
class SimilaritySummary:
    input_path: Path
    input_encoding: str
    output_path: Path
    distribution_path: Path
    row_count: int
    skipped_row_count: int
    distinct_similarity_count: int
    mean: str
    median: str
    minimum: str
    maximum: str

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        for field in ("input_path", "output_path", "distribution_path"):
            result[field] = str(result[field])
        return result


def analyze_similarity_csv(
    input_path: Path | str,
    output_path: Path | str | None = None,
    distribution_path: Path | str | None = None,
    *,
    round_digits: int = 6,
    encoding: str = "auto",
) -> SimilaritySummary:
    """Calculate composite report similarity and write a 0.1-wide distribution.

    Sim = 0.5 * (((E + L + F) / 3) + min(E, L, F)).
    """
    source = Path(input_path)
    if not source.is_file():
        raise ValueError(f"input CSV does not exist: {source}")
    if source.suffix.lower() != ".csv":
        raise ValueError(f"input file must be CSV: {source}")
    if (
        isinstance(round_digits, bool)
        or not isinstance(round_digits, int)
        or not 0 <= round_digits <= 15
    ):
        raise ValueError("round_digits must be an integer from 0 to 15")
    input_encoding = _resolve_input_encoding(source, encoding)

    enriched = Path(output_path) if output_path is not None else source.with_name(
        f"{source.stem}_with_similarity.csv"
    )
    distribution = (
        Path(distribution_path)
        if distribution_path is not None
        else source.with_name(f"{source.stem}_similarity_distribution.csv")
    )
    resolved = {source.resolve(), enriched.resolve(), distribution.resolve()}
    if len(resolved) != 3:
        raise ValueError(
            "input, enriched output, and distribution output must be different files"
        )

    with source.open("r", encoding=input_encoding, newline="") as handle:
        reader = csv.DictReader(line.replace("\0", "") for line in handle)
        fieldnames = reader.fieldnames
        if not fieldnames:
            raise ValueError("input CSV has no header")
        if len(fieldnames) != len(set(fieldnames)):
            raise ValueError("input CSV contains duplicate column names")
        missing = [column for column in SCORE_COLUMNS if column not in fieldnames]
        if missing:
            raise ValueError(f"input CSV is missing required columns: {missing}")

        rows: list[dict[str, str]] = []
        similarities: list[Decimal] = []
        skipped_row_count = 0
        quantum = Decimal(1).scaleb(-round_digits)
        for row_number, row in enumerate(reader, start=2):
            if None in row:
                skipped_row_count += 1
                continue
            if _row_has_pipeline_error(row, fieldnames):
                skipped_row_count += 1
                continue
            try:
                scores = [
                    _parse_score(row[column], column, row_number)
                    for column in SCORE_COLUMNS
                ]
            except ValueError:
                skipped_row_count += 1
                continue
            score_mean = sum(scores, Decimal(0)) / Decimal(3)
            similarity = ((score_mean + min(scores)) / Decimal(2)).quantize(
                quantum, rounding=ROUND_HALF_UP
            )
            row["similarity"] = _decimal_text(similarity)
            rows.append(row)
            similarities.append(similarity)

    if not rows:
        raise ValueError(
            f"input CSV contains no valid data rows; skipped {skipped_row_count}"
        )

    output_fields = list(fieldnames)
    if "similarity" not in output_fields:
        output_fields.append("similarity")
    _write_csv_atomic(enriched, output_fields, rows)

    counts = Counter(similarities)
    distribution_rows = _build_distribution_rows(similarities)
    _write_csv_atomic(
        distribution,
        ["similarity_range", "count", "percentage"],
        distribution_rows,
    )

    mean_value = (sum(similarities, Decimal(0)) / Decimal(len(similarities))).quantize(
        quantum, rounding=ROUND_HALF_UP
    )
    return SimilaritySummary(
        input_path=source.resolve(),
        input_encoding=input_encoding,
        output_path=enriched.resolve(),
        distribution_path=distribution.resolve(),
        row_count=len(rows),
        skipped_row_count=skipped_row_count,
        distinct_similarity_count=len(counts),
        mean=_decimal_text(mean_value),
        median=_decimal_text(Decimal(median(similarities))),
        minimum=_decimal_text(min(similarities)),
        maximum=_decimal_text(max(similarities)),
    )


def _resolve_input_encoding(source: Path, requested: str) -> str:
    if not isinstance(requested, str) or not requested.strip():
        raise ValueError("encoding must be a non-empty codec name or 'auto'")
    requested = requested.strip()
    if requested.lower() != "auto":
        try:
            return codecs.lookup(requested).name
        except LookupError as error:
            raise ValueError(f"unknown input encoding: {requested}") from error

    data = source.read_bytes()
    if data.startswith((codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE)):
        return "utf-32"
    if data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return "utf-16"
    if data.startswith(codecs.BOM_UTF8):
        return "utf-8-sig"
    for candidate in ("utf-8-sig", "gb18030"):
        try:
            data.decode(candidate)
            return candidate
        except UnicodeDecodeError:
            continue
    raise ValueError(
        "unable to detect CSV encoding; retry with --encoding <codec-name>"
    )


def _parse_score(value: str | None, column: str, row_number: int) -> Decimal:
    text = "" if value is None else value.strip()
    try:
        number = Decimal(text)
    except InvalidOperation as error:
        raise ValueError(
            f"CSV row {row_number} column {column} must be numeric; got {value!r}"
        ) from error
    if not number.is_finite():
        raise ValueError(
            f"CSV row {row_number} column {column} must be finite; got {value!r}"
        )
    return number


def _row_has_pipeline_error(
    row: dict[str | None, str | list[str] | None], fieldnames: list[str]
) -> bool:
    for column in PHASE_RAW_COLUMNS:
        if column not in fieldnames:
            continue
        raw = row.get(column)
        if not isinstance(raw, str) or not raw.strip():
            return True
        stripped = raw.strip()
        if not stripped.startswith("{") or not stripped.endswith("}"):
            return True
        if "pipeline_placeholder" not in raw and "pipeline_error" not in raw:
            continue
        try:
            decoded = json.loads(raw)
        except (json.JSONDecodeError, ValueError, TypeError):
            return True
        if not isinstance(decoded, dict):
            return True
        if decoded.get("pipeline_placeholder") or decoded.get("pipeline_error"):
            return True

    return any(
        isinstance(value, str) and value.startswith("[PHASE_") and "_ERROR]" in value
        for value in row.values()
    )


def _build_distribution_rows(similarities: list[Decimal]) -> list[dict[str, str]]:
    width = Decimal("0.1")
    bin_counts = [0] * 10
    below_zero = 0
    above_one = 0
    for value in similarities:
        if value < 0:
            below_zero += 1
        elif value > 1:
            above_one += 1
        elif value == 0:
            bin_counts[0] += 1
        else:
            index = int((value / width).to_integral_value(rounding=ROUND_CEILING)) - 1
            bin_counts[min(index, 9)] += 1

    rows: list[dict[str, str]] = []
    if below_zero:
        rows.append(_distribution_row("< 0.0", below_zero, len(similarities)))
    for index, count in enumerate(bin_counts):
        start = Decimal(index) * width
        end = start + width
        left = "[" if index == 0 else "("
        label = f"{left}{start:.1f}, {end:.1f}]"
        rows.append(_distribution_row(label, count, len(similarities)))
    if above_one:
        rows.append(_distribution_row("> 1.0", above_one, len(similarities)))
    return rows


def _distribution_row(label: str, count: int, total: int) -> dict[str, str]:
    percentage = (Decimal(count) * Decimal(100) / Decimal(total)).quantize(
        Decimal("0.000001"), rounding=ROUND_HALF_UP
    )
    return {
        "similarity_range": label,
        "count": str(count),
        "percentage": _decimal_text(percentage),
    }


def _write_csv_atomic(
    path: Path, fieldnames: list[str], rows: list[dict[str, str]]
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8-sig", newline="", dir=path.parent, delete=False
        ) as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(rows)
            temporary = Path(handle.name)
        os.replace(temporary, path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def _decimal_text(value: Decimal) -> str:
    text = format(value, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text or "0"
