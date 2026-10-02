from __future__ import annotations

import csv
import json
from collections import Counter
from decimal import Decimal
from pathlib import Path

from build_final4 import bin_index, bin_label


ROOT = Path(__file__).resolve().parents[2]
FINAL4 = ROOT / "final4"
MODELS = ("chatgpt", "claude", "deepseek")
EXPECTED_ROWS = {"chatgpt": 3998, "claude": 9924, "deepseek": 4959}
EXPECTED_FILES = {
    "result-chatgpt.csv", "result-claude.csv", "result-deepseek.csv",
    "full_cds_distribution_3_bands.csv", "full_cds_distribution_0.1_bins.csv",
    "common_all_models.csv", "common_cds_distribution_3_bands.csv",
    "common_cds_distribution_0.1_bins.csv", "model_cds_agreement.csv",
    "model_cds_agreement_combinations.csv", "cds_difference_distribution.csv",
    "excluded_errors.csv", "summary.json", "README.md",
}


def band(value: Decimal) -> str:
    if value <= Decimal("0.25"):
        return "low"
    if value >= Decimal("0.75"):
        return "high"
    return "middle"


actual_files = {path.name for path in FINAL4.iterdir() if path.is_file()}
assert actual_files == EXPECTED_FILES, (actual_files - EXPECTED_FILES, EXPECTED_FILES - actual_files)

maps = {}
for model in MODELS:
    path = FINAL4 / f"result-{model}.csv"
    current = {}
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        assert reader.fieldnames
        assert "similarity" in reader.fieldnames
        assert "cds_score" in reader.fieldnames
        assert "cds_band" in reader.fieldnames
        assert "score_band" not in reader.fieldnames
        for row in reader:
            similarity = Decimal(row["similarity"])
            cds = Decimal(row["cds_score"])
            assert cds == Decimal(1) - similarity
            assert row["cds_band"] == band(cds)
            assert row["sample_id"] not in current
            current[row["sample_id"]] = (cds, row["cds_band"])
    assert len(current) == EXPECTED_ROWS[model]
    maps[model] = current

common_ids = set.intersection(*(set(maps[model]) for model in MODELS))
assert len(common_ids) == 3931
with (FINAL4 / "common_all_models.csv").open("r", encoding="utf-8-sig", newline="") as handle:
    rows = list(csv.DictReader(handle))
assert len(rows) == 11793
for offset in range(0, len(rows), 3):
    triple = rows[offset:offset + 3]
    assert [row["model"] for row in triple] == list(MODELS)
    assert len({row["base_sample_id"] for row in triple}) == 1
    assert all(Decimal(row["cds_score"]) == 1 - Decimal(row["similarity"]) for row in triple)

with (FINAL4 / "full_cds_distribution_3_bands.csv").open("r", encoding="utf-8-sig", newline="") as handle:
    full_bands = list(csv.DictReader(handle))
for model in MODELS:
    listed = {row["band"]: int(row["count"]) for row in full_bands if row["model"] == model}
    actual = Counter(value[1] for value in maps[model].values())
    assert listed == dict(actual)
    assert sum(listed.values()) == EXPECTED_ROWS[model]

with (FINAL4 / "model_cds_agreement.csv").open("r", encoding="utf-8-sig", newline="") as handle:
    agreement = {row["comparison"]: int(row["agree_count"]) for row in csv.DictReader(handle)}
assert agreement == {
    "chatgpt_vs_claude": 2271,
    "chatgpt_vs_deepseek": 2224,
    "claude_vs_deepseek": 2291,
    "all_three": 1545,
}

with (FINAL4 / "cds_difference_distribution.csv").open("r", encoding="utf-8-sig", newline="") as handle:
    new_diffs = list(csv.DictReader(handle))
for first, second in (
    ("chatgpt", "claude"),
    ("chatgpt", "deepseek"),
    ("claude", "deepseek"),
):
    comparison = f"{first}_vs_{second}"
    expected = Counter(
        bin_index(abs(maps[first][sample_id][0] - maps[second][sample_id][0]))
        for sample_id in common_ids
    )
    listed = {
        row["absolute_cds_difference_range"]: int(row["count"])
        for row in new_diffs
        if row["comparison"] == comparison
    }
    assert listed == {bin_label(index): expected[index] for index in range(10)}

with (FINAL4 / "excluded_errors.csv").open("r", encoding="utf-8-sig", newline="") as handle:
    assert sum(1 for _ in csv.DictReader(handle)) == 1119

summary = json.loads((FINAL4 / "summary.json").read_text(encoding="utf-8"))
assert summary["cds_formula"] == "1 - similarity"
assert summary["three_model_common_valid_sample_count"] == 3931
assert "CDS = 1 - similarity" in (FINAL4 / "README.md").read_text(encoding="utf-8")
print("final4 verification passed")
