from __future__ import annotations

import codecs
import csv
import itertools
import json
import os
import tempfile
from collections import Counter
from decimal import Decimal, InvalidOperation, ROUND_CEILING, ROUND_HALF_UP
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
OUTPUT_DIR = ROOT / "final3"
SCORE_COLUMNS = (
    "phase_c_variable_match_score",
    "phase_c_step_position_score",
    "phase_c_dataflow_path_score",
)
RAW_COLUMNS = ("phase_a_raw", "phase_b_raw", "phase_c_raw")
MODEL_FILES = {
    "chatgpt": (
        ROOT / "output" / "final_results-chatgpt-1-200.csv",
        ROOT / "output" / "final_results201-1000.csv",
        ROOT / "output" / "final_results.csv",
    ),
    "claude": (
        ROOT / "output2" / "final_results-claude.csv",
        ROOT / "output2" / "final_results201-500.csv",
        ROOT / "output2" / "final_results501-5000.csv",
        ROOT / "output2" / "final_results5001-6000.csv",
        ROOT / "output2" / "final_results6001-7000.csv",
        ROOT / "output2" / "final_results.csv",
    ),
    "deepseek": (
        ROOT / "output3" / "final_results1-500.csv",
        ROOT / "output3" / "final_results.csv",
    ),
}
MODEL_ORDER = ("chatgpt", "claude", "deepseek")
BAND_ORDER = ("low", "middle", "high")
BAND_LABELS = {
    "low": "(-inf, 0.25]",
    "middle": "(0.25, 0.75)",
    "high": "[0.75, +inf)",
}


def detect_encoding(path: Path) -> str:
    data = path.read_bytes()
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
    raise ValueError(f"cannot detect CSV encoding: {path}")


def sample_sort_key(sample_id: str) -> tuple[int, str]:
    try:
        return int(sample_id.rsplit("_", 1)[1]), sample_id
    except (IndexError, ValueError):
        return 2**63 - 1, sample_id


def error_reasons(row: dict[str, str]) -> list[str]:
    reasons: list[str] = []
    sample_id = (row.get("sample_id") or "").strip()
    try:
        int(sample_id.rsplit("_", 1)[1])
    except (IndexError, ValueError):
        reasons.append("invalid_sample_id_suffix")

    for column in RAW_COLUMNS:
        if column not in row:
            reasons.append(f"missing_column:{column}")
            continue
        raw = (row.get(column) or "").strip()
        if not raw:
            reasons.append(f"empty:{column}")
            continue
        if not raw.startswith("{") or not raw.endswith("}"):
            reasons.append(f"invalid_json:{column}")
            continue
        if "pipeline_placeholder" not in raw and "pipeline_error" not in raw:
            continue
        try:
            decoded = json.loads(raw)
        except (json.JSONDecodeError, TypeError, ValueError):
            reasons.append(f"invalid_json:{column}")
            continue
        if not isinstance(decoded, dict):
            reasons.append(f"non_object:{column}")
        elif decoded.get("pipeline_placeholder") or decoded.get("pipeline_error"):
            reasons.append(f"pipeline_error:{column}")

    for value in row.values():
        if isinstance(value, str) and value.startswith("[PHASE_") and "_ERROR]" in value:
            reasons.append("phase_error_marker")
            break

    scores: list[Decimal] = []
    for column in SCORE_COLUMNS:
        if column not in row:
            reasons.append(f"missing_column:{column}")
            continue
        value = (row.get(column) or "").strip()
        try:
            score = Decimal(value)
        except InvalidOperation:
            reasons.append(f"invalid_score:{column}")
            continue
        if not score.is_finite():
            reasons.append(f"non_finite_score:{column}")
        else:
            scores.append(score)
    if len(scores) == len(SCORE_COLUMNS):
        similarity = ((sum(scores, Decimal(0)) / Decimal(3)) + min(scores)) / Decimal(2)
        row["similarity"] = decimal_text(
            similarity.quantize(Decimal("0.000001"), rounding=ROUND_HALF_UP)
        )
        row["score_band"] = score_band(similarity)
    return reasons


def score_band(value: Decimal) -> str:
    if value <= Decimal("0.25"):
        return "low"
    if value < Decimal("0.75"):
        return "middle"
    return "high"


def decimal_text(value: Decimal) -> str:
    text = format(value, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text or "0"


def union_fields(field_groups: list[list[str]], extra: tuple[str, ...] = ()) -> list[str]:
    result: list[str] = []
    for fields in field_groups:
        for field in fields:
            if field not in result:
                result.append(field)
    for field in extra:
        if field not in result:
            result.append(field)
    return result


def load_model(model: str, paths: tuple[Path, ...]):
    rows_by_id: dict[str, dict[str, str]] = {}
    field_groups: list[list[str]] = []
    excluded: list[dict[str, str]] = []
    source_rows = 0
    encodings: dict[str, str] = {}
    for path in paths:
        print(f"loading model={model} file={path.name}", flush=True)
        if not path.is_file():
            raise FileNotFoundError(path)
        encoding = detect_encoding(path)
        encodings[str(path.resolve())] = encoding
        with path.open("r", encoding=encoding, newline="") as handle:
            reader = csv.DictReader(line.replace("\0", "") for line in handle)
            if not reader.fieldnames:
                raise ValueError(f"CSV has no header: {path}")
            field_groups.append(list(reader.fieldnames))
            for source_row_number, row in enumerate(reader, start=2):
                source_rows += 1
                clean = {str(key): "" if value is None else str(value) for key, value in row.items() if key is not None}
                sample_id = clean.get("sample_id", "").strip()
                reasons = error_reasons(clean)
                if sample_id in rows_by_id:
                    reasons.append("duplicate_sample_id")
                if reasons:
                    excluded.append(
                        {
                            "model": model,
                            "sample_id": sample_id,
                            "sample_index": str(sample_sort_key(sample_id)[0]),
                            "source_file": str(path.resolve()),
                            "source_row_number": str(source_row_number),
                            "reason": ";".join(dict.fromkeys(reasons)),
                        }
                    )
                    continue
                clean["sample_id"] = sample_id
                rows_by_id[sample_id] = clean
        print(
            f"loaded model={model} file={path.name} cumulative_rows={source_rows}",
            flush=True,
        )
    fields = union_fields(field_groups, ("similarity", "score_band"))
    rows = sorted(rows_by_id.values(), key=lambda row: sample_sort_key(row["sample_id"]))
    return rows, rows_by_id, fields, excluded, {
        "source_files": [str(path.resolve()) for path in paths],
        "source_encodings": encodings,
        "source_row_count": source_rows,
        "excluded_row_count": len(excluded),
        "valid_row_count": len(rows),
    }


def atomic_write_csv(path: Path, fields: list[str], rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8-sig", newline="", dir=path.parent, delete=False
        ) as handle:
            writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            for index, row in enumerate(rows, start=1):
                writer.writerow(row)
                if index % 1000 == 0:
                    print(f"writing file={path.name} rows={index}/{len(rows)}", flush=True)
            temporary = Path(handle.name)
        os.replace(temporary, path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def distribution_3_bands(model: str, rows: list[dict[str, str]], scope: str):
    counts = Counter(row["score_band"] for row in rows)
    total = len(rows)
    return [
        {
            "scope": scope,
            "model": model,
            "band": band,
            "band_definition": BAND_LABELS[band],
            "count": counts[band],
            "percentage": percentage(counts[band], total),
            "total_valid": total,
        }
        for band in BAND_ORDER
    ]


def bin_label(index: int) -> str:
    if index < 0:
        return "< 0.0"
    if index > 9:
        return "> 1.0"
    left = "[" if index == 0 else "("
    return f"{left}{index / 10:.1f}, {(index + 1) / 10:.1f}]"


def distribution_01(model: str, rows: list[dict[str, str]], scope: str):
    counts: Counter[int] = Counter()
    for row in rows:
        value = Decimal(row["similarity"])
        if value < 0:
            index = -1
        elif value > 1:
            index = 10
        elif value == 0:
            index = 0
        else:
            index = min(
                int((value / Decimal("0.1")).to_integral_value(rounding=ROUND_CEILING)) - 1,
                9,
            )
        counts[index] += 1
    indexes = ([-1] if counts[-1] else []) + list(range(10)) + ([10] if counts[10] else [])
    total = len(rows)
    return [
        {
            "scope": scope,
            "model": model,
            "similarity_range": bin_label(index),
            "count": counts[index],
            "percentage": percentage(counts[index], total),
            "total_valid": total,
        }
        for index in indexes
    ]


def percentage(count: int, total: int) -> str:
    if not total:
        return "0"
    value = (Decimal(count) * Decimal(100) / Decimal(total)).quantize(
        Decimal("0.000001"), rounding=ROUND_HALF_UP
    )
    return decimal_text(value)


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    model_rows: dict[str, list[dict[str, str]]] = {}
    model_maps: dict[str, dict[str, dict[str, str]]] = {}
    model_fields: dict[str, list[str]] = {}
    model_summary: dict[str, dict[str, object]] = {}
    all_excluded: list[dict[str, str]] = []

    for model in MODEL_ORDER:
        rows, row_map, fields, excluded, summary = load_model(model, MODEL_FILES[model])
        model_rows[model] = rows
        model_maps[model] = row_map
        model_fields[model] = fields
        model_summary[model] = summary
        all_excluded.extend(excluded)
        atomic_write_csv(OUTPUT_DIR / f"result-{model}.csv", fields, rows)

    all_excluded.sort(
        key=lambda row: (MODEL_ORDER.index(row["model"]), int(row["sample_index"]), row["source_file"])
    )
    atomic_write_csv(
        OUTPUT_DIR / "excluded_errors.csv",
        ["model", "sample_id", "sample_index", "source_file", "source_row_number", "reason"],
        all_excluded,
    )

    full_band_rows: list[dict[str, object]] = []
    full_bin_rows: list[dict[str, object]] = []
    for model in MODEL_ORDER:
        full_band_rows.extend(distribution_3_bands(model, model_rows[model], "full"))
        full_bin_rows.extend(distribution_01(model, model_rows[model], "full"))
    atomic_write_csv(
        OUTPUT_DIR / "full_distribution_3_bands.csv",
        ["scope", "model", "band", "band_definition", "count", "percentage", "total_valid"],
        full_band_rows,
    )
    atomic_write_csv(
        OUTPUT_DIR / "full_distribution_0.1_bins.csv",
        ["scope", "model", "similarity_range", "count", "percentage", "total_valid"],
        full_bin_rows,
    )

    common_ids = sorted(
        set.intersection(*(set(model_maps[model]) for model in MODEL_ORDER)),
        key=sample_sort_key,
    )
    common_fields = union_fields(
        [model_fields[model] for model in MODEL_ORDER],
        ("similarity", "score_band"),
    )
    common_output_fields = ["base_sample_id", "model"] + common_fields
    common_rows: list[dict[str, str]] = []
    common_by_model: dict[str, list[dict[str, str]]] = {model: [] for model in MODEL_ORDER}
    for sample_id in common_ids:
        for model in MODEL_ORDER:
            source_row = model_maps[model][sample_id]
            common_by_model[model].append(source_row)
            common_row = dict(source_row)
            common_row["base_sample_id"] = sample_id
            common_row["model"] = model
            common_row["sample_id"] = f"{sample_id}_{model}"
            common_rows.append(common_row)
    atomic_write_csv(OUTPUT_DIR / "common_all_models.csv", common_output_fields, common_rows)

    common_band_rows: list[dict[str, object]] = []
    common_bin_rows: list[dict[str, object]] = []
    for model in MODEL_ORDER:
        common_band_rows.extend(
            distribution_3_bands(model, common_by_model[model], "three_model_common")
        )
        common_bin_rows.extend(
            distribution_01(model, common_by_model[model], "three_model_common")
        )
    atomic_write_csv(
        OUTPUT_DIR / "common_distribution_3_bands.csv",
        ["scope", "model", "band", "band_definition", "count", "percentage", "total_valid"],
        common_band_rows,
    )
    atomic_write_csv(
        OUTPUT_DIR / "common_distribution_0.1_bins.csv",
        ["scope", "model", "similarity_range", "count", "percentage", "total_valid"],
        common_bin_rows,
    )

    agreement_rows: list[dict[str, object]] = []
    pairs = (("chatgpt", "claude"), ("chatgpt", "deepseek"), ("claude", "deepseek"))
    for first, second in pairs:
        agree = sum(
            model_maps[first][sample_id]["score_band"]
            == model_maps[second][sample_id]["score_band"]
            for sample_id in common_ids
        )
        agreement_rows.append(
            {
                "comparison": f"{first}_vs_{second}",
                "common_valid": len(common_ids),
                "agree_count": agree,
                "disagree_count": len(common_ids) - agree,
                "agreement_percentage": percentage(agree, len(common_ids)),
            }
        )
    all_same = sum(
        len({model_maps[model][sample_id]["score_band"] for model in MODEL_ORDER}) == 1
        for sample_id in common_ids
    )
    agreement_rows.append(
        {
            "comparison": "all_three",
            "common_valid": len(common_ids),
            "agree_count": all_same,
            "disagree_count": len(common_ids) - all_same,
            "agreement_percentage": percentage(all_same, len(common_ids)),
        }
    )
    atomic_write_csv(
        OUTPUT_DIR / "model_agreement.csv",
        ["comparison", "common_valid", "agree_count", "disagree_count", "agreement_percentage"],
        agreement_rows,
    )

    combinations = Counter(
        tuple(model_maps[model][sample_id]["score_band"] for model in MODEL_ORDER)
        for sample_id in common_ids
    )
    combination_rows = []
    for bands in itertools.product(BAND_ORDER, repeat=3):
        count = combinations[bands]
        combination_rows.append(
            {
                "chatgpt_band": bands[0],
                "claude_band": bands[1],
                "deepseek_band": bands[2],
                "all_same": str(len(set(bands)) == 1).lower(),
                "count": count,
                "percentage": percentage(count, len(common_ids)),
                "common_valid": len(common_ids),
            }
        )
    atomic_write_csv(
        OUTPUT_DIR / "model_agreement_combinations.csv",
        [
            "chatgpt_band",
            "claude_band",
            "deepseek_band",
            "all_same",
            "count",
            "percentage",
            "common_valid",
        ],
        combination_rows,
    )

    summary = {
        "similarity_formula": "0.5 * (((E + L + F) / 3) + min(E, L, F))",
        "score_columns": list(SCORE_COLUMNS),
        "bands": BAND_LABELS,
        "models": model_summary,
        "three_model_common_valid_sample_count": len(common_ids),
        "common_all_models_row_count": len(common_rows),
        "agreement": agreement_rows,
        "outputs": [
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
        ],
    }
    (OUTPUT_DIR / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
