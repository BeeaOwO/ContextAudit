from __future__ import annotations

import csv
from collections import Counter
from dataclasses import asdict, dataclass
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path
from statistics import median
from typing import Any

from .similarity import (
    SCORE_COLUMNS,
    _build_distribution_rows,
    _decimal_text,
    _parse_score,
    _resolve_input_encoding,
    _row_has_pipeline_error,
    _write_csv_atomic,
)


@dataclass(frozen=True)
class CdsSummary:
    input_path: Path
    input_encoding: str
    output_path: Path
    distribution_path: Path
    row_count: int
    skipped_row_count: int
    distinct_cds_count: int
    mean: str
    median: str
    minimum: str
    maximum: str

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        for field in ("input_path", "output_path", "distribution_path"):
            result[field] = str(result[field])
        return result


def analyze_cds_csv(
    input_path: Path | str,
    output_path: Path | str | None = None,
    distribution_path: Path | str | None = None,
    *,
    round_digits: int = 6,
    encoding: str = "auto",
) -> CdsSummary:
    """Calculate composite similarity and CDS, then summarize CDS.

    similarity = 0.5 * (((E + L + F) / 3) + min(E, L, F))
    CDS = 1 - similarity
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
        f"{source.stem}_with_cds.csv"
    )
    distribution = (
        Path(distribution_path)
        if distribution_path is not None
        else source.with_name(f"{source.stem}_cds_distribution.csv")
    )
    if len({source.resolve(), enriched.resolve(), distribution.resolve()}) != 3:
        raise ValueError(
            "input, enriched output, and distribution output must be different files"
        )

    quantum = Decimal(1).scaleb(-round_digits)
    rows: list[dict[str, str]] = []
    cds_values: list[Decimal] = []
    skipped_row_count = 0

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

        for row_number, row in enumerate(reader, start=2):
            if None in row or _row_has_pipeline_error(row, fieldnames):
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
            cds_score = (Decimal(1) - similarity).quantize(
                quantum, rounding=ROUND_HALF_UP
            )
            row["similarity"] = _decimal_text(similarity)
            row["cds_score"] = _decimal_text(cds_score)
            row["cds_band"] = _cds_band(cds_score)
            rows.append(row)
            cds_values.append(cds_score)

    if not rows:
        raise ValueError(
            f"input CSV contains no valid data rows; skipped {skipped_row_count}"
        )

    output_fields = [
        field for field in fieldnames if field not in {"similarity", "cds_score", "cds_band"}
    ]
    output_fields.extend(("similarity", "cds_score", "cds_band"))
    _write_csv_atomic(enriched, output_fields, rows)

    distribution_rows = _build_distribution_rows(cds_values)
    for row in distribution_rows:
        row["cds_range"] = row.pop("similarity_range")
    _write_csv_atomic(
        distribution,
        ["cds_range", "count", "percentage"],
        distribution_rows,
    )

    mean_value = (sum(cds_values, Decimal(0)) / Decimal(len(cds_values))).quantize(
        quantum, rounding=ROUND_HALF_UP
    )
    return CdsSummary(
        input_path=source.resolve(),
        input_encoding=input_encoding,
        output_path=enriched.resolve(),
        distribution_path=distribution.resolve(),
        row_count=len(rows),
        skipped_row_count=skipped_row_count,
        distinct_cds_count=len(Counter(cds_values)),
        mean=_decimal_text(mean_value),
        median=_decimal_text(Decimal(median(cds_values))),
        minimum=_decimal_text(min(cds_values)),
        maximum=_decimal_text(max(cds_values)),
    )


def _cds_band(value: Decimal) -> str:
    if value <= Decimal("0.25"):
        return "low"
    if value >= Decimal("0.75"):
        return "high"
    return "middle"
