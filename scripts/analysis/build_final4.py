from __future__ import annotations

import csv
import itertools
import json
import os
import tempfile
from collections import Counter
from decimal import Decimal, ROUND_CEILING, ROUND_HALF_UP
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCE_DIR = ROOT / "final3"
OUTPUT_DIR = ROOT / "final4"
MODELS = ("chatgpt", "claude", "deepseek")
BANDS = ("low", "middle", "high")
SCORES = (
    "phase_c_variable_match_score",
    "phase_c_step_position_score",
    "phase_c_dataflow_path_score",
)
BAND_DEFINITIONS = {
    "low": "(-inf, 0.25]",
    "middle": "(0.25, 0.75)",
    "high": "[0.75, +inf)",
}
QUANTUM = Decimal("0.000001")


def decimal_text(value: Decimal) -> str:
    text = format(value, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text or "0"


def percentage(count: int, total: int) -> str:
    if not total:
        return "0"
    value = (Decimal(count) * 100 / Decimal(total)).quantize(
        QUANTUM, rounding=ROUND_HALF_UP
    )
    return decimal_text(value)


def calculate_scores(row: dict[str, str]) -> tuple[Decimal, Decimal, str]:
    values = [Decimal(row[column]) for column in SCORES]
    similarity = (
        ((sum(values, Decimal(0)) / 3) + min(values)) / 2
    ).quantize(QUANTUM, rounding=ROUND_HALF_UP)
    cds = (Decimal(1) - similarity).quantize(QUANTUM, rounding=ROUND_HALF_UP)
    return similarity, cds, cds_band(cds)


def cds_band(value: Decimal) -> str:
    if value <= Decimal("0.25"):
        return "low"
    if value >= Decimal("0.75"):
        return "high"
    return "middle"


def output_fields(fields: list[str]) -> list[str]:
    result = [
        field
        for field in fields
        if field not in {"similarity", "score_band", "cds_score", "cds_band"}
    ]
    result.extend(("similarity", "cds_score", "cds_band"))
    return result


def atomic_csv_writer(path: Path, fields: list[str]):
    path.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        "w", encoding="utf-8-sig", newline="", dir=path.parent, delete=False
    )
    writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    return handle, writer, Path(handle.name)


def finish_atomic(handle, temporary: Path, path: Path) -> None:
    handle.close()
    os.replace(temporary, path)


def write_small_csv(path: Path, fields: list[str], rows: list[dict[str, object]]) -> None:
    handle, writer, temporary = atomic_csv_writer(path, fields)
    try:
        writer.writerows(rows)
        finish_atomic(handle, temporary, path)
    finally:
        if not handle.closed:
            handle.close()
        if temporary.exists():
            temporary.unlink()


def transform_results(model: str):
    source = SOURCE_DIR / f"result-{model}.csv"
    target = OUTPUT_DIR / source.name
    score_map: dict[str, tuple[Decimal, str]] = {}
    cds_values: list[Decimal] = []
    with source.open("r", encoding="utf-8-sig", newline="") as input_handle:
        reader = csv.DictReader(line.replace("\0", "") for line in input_handle)
        if not reader.fieldnames:
            raise ValueError(f"missing header: {source}")
        fields = output_fields(list(reader.fieldnames))
        handle, writer, temporary = atomic_csv_writer(target, fields)
        try:
            for index, row in enumerate(reader, start=1):
                similarity, cds, band = calculate_scores(row)
                old_similarity = row.get("similarity", "").strip()
                if old_similarity and Decimal(old_similarity) != similarity:
                    raise ValueError(
                        f"similarity mismatch model={model} sample={row.get('sample_id')}"
                    )
                row["similarity"] = decimal_text(similarity)
                row["cds_score"] = decimal_text(cds)
                row["cds_band"] = band
                writer.writerow(row)
                sample_id = row["sample_id"]
                if sample_id in score_map:
                    raise ValueError(f"duplicate sample_id model={model}: {sample_id}")
                score_map[sample_id] = (cds, band)
                cds_values.append(cds)
                if index % 1000 == 0:
                    print(f"writing {target.name}: {index}", flush=True)
            finish_atomic(handle, temporary, target)
        finally:
            if not handle.closed:
                handle.close()
            if temporary.exists():
                temporary.unlink()
    return score_map, cds_values, fields


def transform_common(expected_common: set[str]) -> tuple[int, dict[str, dict[str, tuple[Decimal, str]]]]:
    source = SOURCE_DIR / "common_all_models.csv"
    target = OUTPUT_DIR / source.name
    common: dict[str, dict[str, tuple[Decimal, str]]] = {}
    with source.open("r", encoding="utf-8-sig", newline="") as input_handle:
        reader = csv.DictReader(line.replace("\0", "") for line in input_handle)
        if not reader.fieldnames:
            raise ValueError(f"missing header: {source}")
        fields = output_fields(list(reader.fieldnames))
        handle, writer, temporary = atomic_csv_writer(target, fields)
        try:
            count = 0
            for count, row in enumerate(reader, start=1):
                similarity, cds, band = calculate_scores(row)
                base_id = row["base_sample_id"]
                model = row["model"]
                if base_id not in expected_common:
                    raise ValueError(f"unexpected common sample: {base_id}")
                row["similarity"] = decimal_text(similarity)
                row["cds_score"] = decimal_text(cds)
                row["cds_band"] = band
                writer.writerow(row)
                common.setdefault(base_id, {})[model] = (cds, band)
                if count % 1000 == 0:
                    print(f"writing {target.name}: {count}", flush=True)
            finish_atomic(handle, temporary, target)
        finally:
            if not handle.closed:
                handle.close()
            if temporary.exists():
                temporary.unlink()
    if set(common) != expected_common:
        raise ValueError("common_all_models.csv does not match the model intersection")
    if any(set(values) != set(MODELS) for values in common.values()):
        raise ValueError("one or more common samples do not have all three models")
    return count, common


def three_band_rows(scope: str, values_by_model: dict[str, list[Decimal]]):
    rows = []
    for model in MODELS:
        counts = Counter(cds_band(value) for value in values_by_model[model])
        total = len(values_by_model[model])
        for band in BANDS:
            rows.append(
                {
                    "scope": scope,
                    "model": model,
                    "band": band,
                    "band_definition": BAND_DEFINITIONS[band],
                    "count": counts[band],
                    "percentage": percentage(counts[band], total),
                    "total_valid": total,
                }
            )
    return rows


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
    if index < 0:
        return "< 0.0"
    if index > 9:
        return "> 1.0"
    left = "[" if index == 0 else "("
    return f"{left}{index / 10:.1f}, {(index + 1) / 10:.1f}]"


def point_one_rows(scope: str, values_by_model: dict[str, list[Decimal]]):
    rows = []
    for model in MODELS:
        counts = Counter(bin_index(value) for value in values_by_model[model])
        total = len(values_by_model[model])
        indexes = ([-1] if counts[-1] else []) + list(range(10)) + ([10] if counts[10] else [])
        for index in indexes:
            rows.append(
                {
                    "scope": scope,
                    "model": model,
                    "cds_range": bin_label(index),
                    "count": counts[index],
                    "percentage": percentage(counts[index], total),
                    "total_valid": total,
                }
            )
    return rows


def agreement_outputs(common: dict[str, dict[str, tuple[Decimal, str]]]):
    total = len(common)
    pairs = (("chatgpt", "claude"), ("chatgpt", "deepseek"), ("claude", "deepseek"))
    agreement = []
    for first, second in pairs:
        agreed = sum(values[first][1] == values[second][1] for values in common.values())
        agreement.append(
            {
                "comparison": f"{first}_vs_{second}",
                "common_valid": total,
                "agree_count": agreed,
                "disagree_count": total - agreed,
                "agreement_percentage": percentage(agreed, total),
            }
        )
    all_three = sum(
        len({values[model][1] for model in MODELS}) == 1 for values in common.values()
    )
    agreement.append(
        {
            "comparison": "all_three",
            "common_valid": total,
            "agree_count": all_three,
            "disagree_count": total - all_three,
            "agreement_percentage": percentage(all_three, total),
        }
    )

    counts = Counter(
        tuple(values[model][1] for model in MODELS) for values in common.values()
    )
    combinations = []
    for bands in itertools.product(BANDS, repeat=3):
        count = counts[bands]
        combinations.append(
            {
                "chatgpt_cds_band": bands[0],
                "claude_cds_band": bands[1],
                "deepseek_cds_band": bands[2],
                "all_same": str(len(set(bands)) == 1).lower(),
                "count": count,
                "percentage": percentage(count, total),
                "common_valid": total,
            }
        )
    return agreement, combinations


def difference_rows(common: dict[str, dict[str, tuple[Decimal, str]]]):
    rows = []
    total = len(common)
    for first, second in (("chatgpt", "claude"), ("chatgpt", "deepseek"), ("claude", "deepseek")):
        counts = Counter(
            bin_index(abs(values[first][0] - values[second][0]))
            for values in common.values()
        )
        cumulative = 0
        for index in range(10):
            count = counts[index]
            cumulative += count
            rows.append(
                {
                    "comparison": f"{first}_vs_{second}",
                    "absolute_cds_difference_range": bin_label(index),
                    "count": count,
                    "percentage": percentage(count, total),
                    "cumulative_count": cumulative,
                    "cumulative_percentage": percentage(cumulative, total),
                    "total_common": total,
                }
            )
    return rows


def copy_excluded() -> int:
    source = SOURCE_DIR / "excluded_errors.csv"
    target = OUTPUT_DIR / source.name
    with source.open("r", encoding="utf-8-sig", newline="") as input_handle:
        reader = csv.DictReader(input_handle)
        if not reader.fieldnames:
            raise ValueError(f"missing header: {source}")
        rows = list(reader)
    write_small_csv(target, list(reader.fieldnames), rows)
    return len(rows)


def write_readme(model_meta, common_count: int, agreement) -> None:
    claude = model_meta["claude"]
    lines = [
        "# final4：按 CDS 修正后的实验统计",
        "",
        "## 1. 本次修正",
        "",
        "此前 `final3` 的复合分数计算本身正确，但统计口径错误：程序直接把该分数当成 CDS 分档。原始实验定义明确区分二者：",
        "",
        "- `similarity = 0.5 * (((E + L + F) / 3) + min(E, L, F))`；",
        "- `CDS = 1 - similarity`。",
        "",
        "因此 `final4` 的所有判定、三档分布、一致率和分数差统计均使用 `cds_score`。结果 CSV 同时保留 `similarity`，用于审计换算关系。",
        "",
        "## 2. 实验定位",
        "",
        f"主实验仍是 Claude 的 10,000 条原始样本；排除 {claude['excluded_row_count']} 条错误记录后，有效样本为 {claude['valid_row_count']} 条。",
        "Claude、DeepSeek 与 ChatGPT 的模型替换消融使用三模型共同有效样本，严格交集为 " + f"{common_count} 条。",
        "",
        "## 3. CDS 分档",
        "",
        "| 分档 | 条件 | 含义 |",
        "|---|---|---|",
        "| 低 CDS | `CDS <= 0.25` | Phase A 与 Phase B 一致性高 |",
        "| 中 CDS | `0.25 < CDS < 0.75` | 一致性居中 |",
        "| 高 CDS | `CDS >= 0.75` | Phase A 与 Phase B 一致性低、差异大 |",
        "",
        "端点不属于中间档。错误占位、阶段错误、缺失/非法评分及重复样本继续排除。",
        "",
        "## 4. 文件说明",
        "",
        "| 文件 | 含义 |",
        "|---|---|",
        "| `result-claude.csv` | Claude 主实验有效结果，新增 `similarity`、`cds_score`、`cds_band` |",
        "| `result-chatgpt.csv` / `result-deepseek.csv` | 两个消融模型的有效结果 |",
        "| `full_cds_distribution_3_bands.csv` | 各模型完整有效数据的 CDS 三档分布 |",
        "| `full_cds_distribution_0.1_bins.csv` | 各模型完整有效数据的 CDS 每 0.1 分布 |",
        "| `common_all_models.csv` | 三模型共同有效样本；每个样本连续三行 |",
        "| `common_cds_distribution_3_bands.csv` | 共同样本上的 CDS 三档分布 |",
        "| `common_cds_distribution_0.1_bins.csv` | 共同样本上的 CDS 每 0.1 分布 |",
        "| `model_cds_agreement.csv` | 两两及三模型 CDS 分档一致率 |",
        "| `model_cds_agreement_combinations.csv` | 27 种三模型 CDS 档位组合 |",
        "| `cds_difference_distribution.csv` | 两两绝对 CDS 分数差的每 0.1 分布 |",
        "| `excluded_errors.csv` | 被排除记录及原因 |",
        "| `summary.json` | 机器可读的口径、规模和一致率摘要 |",
        "",
        "## 5. 解释注意事项",
        "",
        "CDS 越高表示两份报告差异越大，因此不能再把高 CDS 写成高一致性。由于 `CDS = 1 - similarity` 是镜像变换，低/高档数量会相互交换；中档数量不变。对称阈值下，同档一致率数值不变，但 low/high 的组合标签会交换。两模型的绝对分数差也不变，因为 `|(1-s1)-(1-s2)| = |s1-s2|`。",
        "",
        "当前三模型共同样本的一致率为：",
        "",
    ]
    for row in agreement:
        lines.append(
            f"- `{row['comparison']}`：{row['agree_count']}/{row['common_valid']}（{row['agreement_percentage']}%）"
        )
    lines.extend(
        [
            "",
            "论文正文的总体分布应使用 Claude 的完整有效结果；三模型公平比较应使用共同样本统计表。",
            "",
        ]
    )
    (OUTPUT_DIR / "README.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    with (SOURCE_DIR / "summary.json").open("r", encoding="utf-8") as handle:
        old_summary = json.load(handle)

    score_maps = {}
    full_values = {}
    for model in MODELS:
        score_maps[model], full_values[model], _ = transform_results(model)

    expected_common = set.intersection(*(set(score_maps[model]) for model in MODELS))
    common_row_count, common = transform_common(expected_common)
    common_values = {
        model: [values[model][0] for values in common.values()] for model in MODELS
    }

    full_bands = three_band_rows("full", full_values)
    full_bins = point_one_rows("full", full_values)
    common_bands = three_band_rows("three_model_common", common_values)
    common_bins = point_one_rows("three_model_common", common_values)
    agreement, combinations = agreement_outputs(common)
    differences = difference_rows(common)

    write_small_csv(
        OUTPUT_DIR / "full_cds_distribution_3_bands.csv",
        ["scope", "model", "band", "band_definition", "count", "percentage", "total_valid"],
        full_bands,
    )
    write_small_csv(
        OUTPUT_DIR / "full_cds_distribution_0.1_bins.csv",
        ["scope", "model", "cds_range", "count", "percentage", "total_valid"],
        full_bins,
    )
    write_small_csv(
        OUTPUT_DIR / "common_cds_distribution_3_bands.csv",
        ["scope", "model", "band", "band_definition", "count", "percentage", "total_valid"],
        common_bands,
    )
    write_small_csv(
        OUTPUT_DIR / "common_cds_distribution_0.1_bins.csv",
        ["scope", "model", "cds_range", "count", "percentage", "total_valid"],
        common_bins,
    )
    write_small_csv(
        OUTPUT_DIR / "model_cds_agreement.csv",
        ["comparison", "common_valid", "agree_count", "disagree_count", "agreement_percentage"],
        agreement,
    )
    write_small_csv(
        OUTPUT_DIR / "model_cds_agreement_combinations.csv",
        ["chatgpt_cds_band", "claude_cds_band", "deepseek_cds_band", "all_same", "count", "percentage", "common_valid"],
        combinations,
    )
    write_small_csv(
        OUTPUT_DIR / "cds_difference_distribution.csv",
        ["comparison", "absolute_cds_difference_range", "count", "percentage", "cumulative_count", "cumulative_percentage", "total_common"],
        differences,
    )
    excluded_count = copy_excluded()

    summary = {
        "correction": "Previous tables classified composite similarity directly. final4 derives CDS = 1 - similarity and classifies on CDS.",
        "similarity_formula": "0.5 * (((E + L + F) / 3) + min(E, L, F))",
        "cds_formula": "1 - similarity",
        "score_columns": list(SCORES),
        "cds_bands": BAND_DEFINITIONS,
        "models": old_summary["models"],
        "three_model_common_valid_sample_count": len(common),
        "common_all_models_row_count": common_row_count,
        "excluded_error_row_count": excluded_count,
        "full_cds_distribution_3_bands": full_bands,
        "common_cds_distribution_3_bands": common_bands,
        "agreement": agreement,
        "absolute_difference_invariance": "abs((1-s1)-(1-s2)) == abs(s1-s2)",
        "outputs": [
            "result-chatgpt.csv", "result-claude.csv", "result-deepseek.csv",
            "full_cds_distribution_3_bands.csv", "full_cds_distribution_0.1_bins.csv",
            "common_all_models.csv", "common_cds_distribution_3_bands.csv",
            "common_cds_distribution_0.1_bins.csv", "model_cds_agreement.csv",
            "model_cds_agreement_combinations.csv", "cds_difference_distribution.csv",
            "excluded_errors.csv", "summary.json", "README.md",
        ],
    }
    (OUTPUT_DIR / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    write_readme(old_summary["models"], len(common), agreement)
    print(json.dumps(summary, ensure_ascii=False, indent=2), flush=True)


if __name__ == "__main__":
    main()
