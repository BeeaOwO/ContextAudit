from __future__ import annotations

import csv
import json
import os
import re
import tempfile
from collections import Counter
from decimal import Decimal, ROUND_CEILING, ROUND_HALF_UP
from pathlib import Path
from statistics import median


ROOT = Path(__file__).resolve().parents[2]
FINAL = ROOT / "final3"
COMMON = FINAL / "common_all_models.csv"
OUTPUT = FINAL / "score_difference_distribution.csv"
SUMMARY = FINAL / "summary.json"
MODELS = ("chatgpt", "claude", "deepseek")
PAIRS = (
    ("chatgpt", "claude"),
    ("chatgpt", "deepseek"),
    ("claude", "deepseek"),
)


def decimal_text(value: Decimal) -> str:
    text = format(value, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text or "0"


def pct(count: int, total: int) -> str:
    value = (Decimal(count) * Decimal(100) / Decimal(total)).quantize(
        Decimal("0.000001"), rounding=ROUND_HALF_UP
    )
    return decimal_text(value)


def bin_index(value: Decimal) -> int:
    if value < 0:
        return -1
    if value > 1:
        return 10
    if value == 0:
        return 0
    return min(
        int((value / Decimal("0.1")).to_integral_value(rounding=ROUND_CEILING)) - 1,
        9,
    )


def bin_label(index: int) -> str:
    if index == -1:
        return "< 0.0"
    if index == 10:
        return "> 1.0"
    left = "[" if index == 0 else "("
    return f"{left}{index / 10:.1f}, {(index + 1) / 10:.1f}]"


def write_csv_atomic(rows: list[dict[str, object]]) -> None:
    fields = (
        "comparison",
        "difference_range",
        "count",
        "percentage",
        "cumulative_count",
        "cumulative_percentage",
        "total_common",
    )
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8-sig", newline="", dir=FINAL, delete=False
        ) as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)
            temporary = Path(handle.name)
        os.replace(temporary, OUTPUT)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def main() -> None:
    by_sample: dict[str, dict[str, Decimal]] = {}
    record_start = re.compile(r"^([^,\r\n]+),(chatgpt|claude|deepseek),")
    record_end = re.compile(r",(-?\d+(?:\.\d+)?),(?:low|middle|high)\r?\n?$")
    current: tuple[str, str] | None = None
    parsed_records = 0
    text = COMMON.read_text(encoding="utf-8-sig")
    for line in text.splitlines(keepends=True)[1:]:
        start = record_start.match(line)
        if start:
            current = (start.group(1), start.group(2))
        end = record_end.search(line)
        if end and current is not None:
            sample_id, model = current
            by_sample.setdefault(sample_id, {})[model] = Decimal(end.group(1))
            parsed_records += 1
            current = None
    if parsed_records != 11793:
        raise ValueError(f"expected 11793 common records, parsed {parsed_records}")
    if not by_sample or any(set(values) != set(MODELS) for values in by_sample.values()):
        raise ValueError("common_all_models.csv does not contain complete model triplets")

    output_rows: list[dict[str, object]] = []
    summaries: dict[str, dict[str, object]] = {}
    for first, second in PAIRS:
        comparison = f"{first}_vs_{second}"
        differences = [
            abs(values[first] - values[second]) for values in by_sample.values()
        ]
        counts = Counter(bin_index(value) for value in differences)
        indexes = ([-1] if counts[-1] else []) + list(range(10)) + ([10] if counts[10] else [])
        cumulative = 0
        for index in indexes:
            count = counts[index]
            cumulative += count
            output_rows.append(
                {
                    "comparison": comparison,
                    "difference_range": bin_label(index),
                    "count": count,
                    "percentage": pct(count, len(differences)),
                    "cumulative_count": cumulative,
                    "cumulative_percentage": pct(cumulative, len(differences)),
                    "total_common": len(differences),
                }
            )
        mean_value = sum(differences, Decimal(0)) / Decimal(len(differences))
        summaries[comparison] = {
            "sample_count": len(differences),
            "mean_absolute_difference": decimal_text(
                mean_value.quantize(Decimal("0.000001"), rounding=ROUND_HALF_UP)
            ),
            "median_absolute_difference": decimal_text(Decimal(median(differences))),
            "minimum_absolute_difference": decimal_text(min(differences)),
            "maximum_absolute_difference": decimal_text(max(differences)),
        }

    write_csv_atomic(output_rows)
    summary = json.loads(SUMMARY.read_text(encoding="utf-8"))
    summary["score_difference"] = {
        "definition": "absolute difference between two models' similarity scores",
        "scope": "three-model common valid samples",
        "bin_width": "0.1",
        "comparisons": summaries,
    }
    outputs = summary.setdefault("outputs", [])
    if OUTPUT.name not in outputs:
        outputs.append(OUTPUT.name)
    SUMMARY.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summaries, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
