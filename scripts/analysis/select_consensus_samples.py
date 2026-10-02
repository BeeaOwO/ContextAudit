from __future__ import annotations

import csv
from decimal import Decimal, ROUND_HALF_UP
from pathlib import Path

from three_stage_pipeline.similarity import SCORE_COLUMNS, _resolve_input_encoding


ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "output" / "consensus_selected_74.csv"
HIGH = Decimal("0.75")
LOW = Decimal("0.25")
csv.field_size_limit(10_000_000)


def load(path: str) -> dict[str, dict[str, str]]:
    source = ROOT / path
    encoding = _resolve_input_encoding(source, "auto")
    with source.open("r", encoding=encoding, newline="") as handle:
        rows = list(csv.DictReader(handle))
    return {
        row["sample_id"]: {**row, "__source_file": path}
        for row in rows
    }


def similarity(row: dict[str, str]) -> Decimal:
    existing = row.get("similarity", "").strip()
    if existing:
        return Decimal(existing)
    scores = [Decimal(row[column]) for column in SCORE_COLUMNS]
    return ((sum(scores, Decimal()) / Decimal(3) + min(scores)) / Decimal(2))


def text(value: Decimal) -> str:
    rounded = value.quantize(Decimal("0.000001"), rounding=ROUND_HALF_UP)
    return format(rounded, "f").rstrip("0").rstrip(".") or "0"


def sample_index(sample_id: str) -> int:
    return int(sample_id.rsplit("_", 1)[1])


def model_fields(prefix: str, row: dict[str, str]) -> dict[str, str]:
    result = {
        f"{prefix}_source_file": row["__source_file"],
        f"{prefix}_similarity": text(similarity(row)),
    }
    for column in SCORE_COLUMNS:
        result[f"{prefix}_{column.removeprefix('phase_c_')}"] = row[column]
    for column in ("phase_c_overall_consistency", "phase_c_comment"):
        result[f"{prefix}_{column.removeprefix('phase_c_')}"] = row.get(column, "")
    return result


def main() -> None:
    original = load("input/diversevul_paired_anonymized.csv")
    gpt = {
        **load("output/final_results-chatgpt-1-200.csv"),
        **load("output/final_results_with_similarity.csv"),
    }
    claude = {
        **load("output2/final_results-claude_with_similarity.csv"),
        **load("output2/final_results_with_similarity.csv"),
    }
    qwen = load("output/final_results-qwen-1-500.csv")
    common = set(original) & set(gpt) & set(claude) & set(qwen)

    high = [
        sample_id
        for sample_id in common
        if similarity(gpt[sample_id]) > HIGH and similarity(claude[sample_id]) > HIGH
    ]
    low = [
        sample_id
        for sample_id in common
        if similarity(gpt[sample_id]) < LOW and similarity(claude[sample_id]) < LOW
    ]
    high.sort(
        key=lambda sample_id: (
            similarity(qwen[sample_id]) <= HIGH,
            -similarity(qwen[sample_id]),
            -min(similarity(gpt[sample_id]), similarity(claude[sample_id])),
            abs(similarity(gpt[sample_id]) - similarity(claude[sample_id])),
            sample_index(sample_id),
        )
    )
    low.sort(
        key=lambda sample_id: (
            similarity(qwen[sample_id]) >= LOW,
            similarity(qwen[sample_id]),
            max(similarity(gpt[sample_id]), similarity(claude[sample_id])),
            abs(similarity(gpt[sample_id]) - similarity(claude[sample_id])),
            sample_index(sample_id),
        )
    )
    selected = [("high", sample_id) for sample_id in high]
    selected += [("low", sample_id) for sample_id in low[:50]]
    if len(high) != 24 or len(selected) != 74:
        raise RuntimeError(
            f"unexpected candidate counts: high={len(high)}, low={len(low)}, selected={len(selected)}"
        )

    rows: list[dict[str, str]] = []
    ranks = {"high": 0, "low": 0}
    for group, sample_id in selected:
        ranks[group] += 1
        qwen_same = (
            similarity(qwen[sample_id]) > HIGH
            if group == "high"
            else similarity(qwen[sample_id]) < LOW
        )
        row = {
            "selection_group": group,
            "selection_rank": str(ranks[group]),
            "qwen_same_direction": str(qwen_same).lower(),
            "sample_numeric_index": str(sample_index(sample_id)),
            **{key: value for key, value in original[sample_id].items() if key != "__source_file"},
            **model_fields("gpt", gpt[sample_id]),
            **model_fields("claude", claude[sample_id]),
            **model_fields("qwen", qwen[sample_id]),
        }
        rows.append(row)

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    print(OUTPUT)


if __name__ == "__main__":
    main()
