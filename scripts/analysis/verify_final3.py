from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from decimal import Decimal
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "final3"
MODELS = ("chatgpt", "claude", "deepseek")
SCORES = (
    "phase_c_variable_match_score",
    "phase_c_step_position_score",
    "phase_c_dataflow_path_score",
)
EXPECTED_FILES = {
    "result-chatgpt.csv",
    "result-claude.csv",
    "result-deepseek.csv",
    "full_distribution_3_bands.csv",
    "full_distribution_0.1_bins.csv",
    "common_all_models.csv",
    "common_distribution_3_bands.csv",
    "common_distribution_0.1_bins.csv",
    "model_agreement.csv",
    "model_agreement_combinations.csv",
    "excluded_errors.csv",
    "summary.json",
}


def read_csv(name: str) -> list[dict[str, str]]:
    path = OUT / name
    assert b"\0" not in path.read_bytes(), f"NUL found in {name}"
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def index_of(sample_id: str) -> int:
    return int(sample_id.rsplit("_", 1)[1])


def band(value: Decimal) -> str:
    if value <= Decimal("0.25"):
        return "low"
    if value < Decimal("0.75"):
        return "middle"
    return "high"


def main() -> None:
    actual_files = {path.name for path in OUT.iterdir() if path.is_file()}
    assert actual_files == EXPECTED_FILES, (actual_files - EXPECTED_FILES, EXPECTED_FILES - actual_files)
    summary = json.loads((OUT / "summary.json").read_text(encoding="utf-8"))
    assert set(summary["outputs"]) == EXPECTED_FILES

    result_maps: dict[str, dict[str, dict[str, str]]] = {}
    verification: dict[str, object] = {"files": len(actual_files), "models": {}}
    for model in MODELS:
        rows = read_csv(f"result-{model}.csv")
        ids = [row["sample_id"] for row in rows]
        indexes = [index_of(sample_id) for sample_id in ids]
        assert indexes == sorted(indexes)
        assert len(ids) == len(set(ids)) == summary["models"][model]["valid_row_count"]
        for row in rows:
            scores = [Decimal(row[column]) for column in SCORES]
            calculated = ((sum(scores) / Decimal(3)) + min(scores)) / Decimal(2)
            assert abs(calculated - Decimal(row["similarity"])) <= Decimal("0.0000005")
            assert row["score_band"] == band(calculated)
        result_maps[model] = {row["sample_id"]: row for row in rows}
        verification["models"][model] = {
            "rows": len(rows),
            "first_index": indexes[0],
            "last_index": indexes[-1],
        }

    excluded = read_csv("excluded_errors.csv")
    assert len(excluded) == sum(
        summary["models"][model]["excluded_row_count"] for model in MODELS
    )
    assert all(row["reason"] for row in excluded)
    assert sum(summary["models"][model]["source_row_count"] for model in MODELS) == (
        sum(len(result_maps[model]) for model in MODELS) + len(excluded)
    )

    for name in ("full_distribution_3_bands.csv", "common_distribution_3_bands.csv"):
        rows = read_csv(name)
        grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
        for row in rows:
            grouped[row["model"]].append(row)
        assert set(grouped) == set(MODELS)
        for model, group in grouped.items():
            assert {row["band"] for row in group} == {"low", "middle", "high"}
            assert sum(int(row["count"]) for row in group) == int(group[0]["total_valid"])
            assert abs(sum(Decimal(row["percentage"]) for row in group) - Decimal(100)) <= Decimal("0.000002")

    for name in ("full_distribution_0.1_bins.csv", "common_distribution_0.1_bins.csv"):
        rows = read_csv(name)
        grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
        for row in rows:
            grouped[row["model"]].append(row)
        assert set(grouped) == set(MODELS)
        for group in grouped.values():
            assert sum(int(row["count"]) for row in group) == int(group[0]["total_valid"])
            assert abs(sum(Decimal(row["percentage"]) for row in group) - Decimal(100)) <= Decimal("0.000005")

    common = read_csv("common_all_models.csv")
    common_count = summary["three_model_common_valid_sample_count"]
    assert len(common) == common_count * 3 == summary["common_all_models_row_count"]
    common_ids: list[str] = []
    for offset in range(0, len(common), 3):
        group = common[offset : offset + 3]
        base_ids = {row["base_sample_id"] for row in group}
        assert len(base_ids) == 1
        base_id = group[0]["base_sample_id"]
        common_ids.append(base_id)
        assert [row["model"] for row in group] == list(MODELS)
        for row, model in zip(group, MODELS):
            assert row["sample_id"] == f"{base_id}_{model}"
            assert row["similarity"] == result_maps[model][base_id]["similarity"]
            assert row["score_band"] == result_maps[model][base_id]["score_band"]
    assert [index_of(sample_id) for sample_id in common_ids] == sorted(index_of(sample_id) for sample_id in common_ids)
    assert set(common_ids) == set.intersection(*(set(result_maps[model]) for model in MODELS))

    agreement = {row["comparison"]: row for row in read_csv("model_agreement.csv")}
    pair_specs = {
        "chatgpt_vs_claude": ("chatgpt", "claude"),
        "chatgpt_vs_deepseek": ("chatgpt", "deepseek"),
        "claude_vs_deepseek": ("claude", "deepseek"),
    }
    for label, (first, second) in pair_specs.items():
        count = sum(
            result_maps[first][sample_id]["score_band"]
            == result_maps[second][sample_id]["score_band"]
            for sample_id in common_ids
        )
        assert int(agreement[label]["agree_count"]) == count
    all_same = sum(
        len({result_maps[model][sample_id]["score_band"] for model in MODELS}) == 1
        for sample_id in common_ids
    )
    assert int(agreement["all_three"]["agree_count"]) == all_same

    combinations = read_csv("model_agreement_combinations.csv")
    assert len(combinations) == 27
    assert sum(int(row["count"]) for row in combinations) == common_count
    assert sum(int(row["count"]) for row in combinations if row["all_same"] == "true") == all_same
    verification["excluded_rows"] = len(excluded)
    verification["common_samples"] = common_count
    verification["common_rows"] = len(common)
    verification["agreement"] = {
        label: agreement[label]["agreement_percentage"] for label in agreement
    }
    print(json.dumps(verification, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
