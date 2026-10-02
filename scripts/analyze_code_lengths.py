from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd


CHAR_BINS = [-1, 500, 1000, 2000, 5000, 10000, 20000, 50000, 100000, float("inf")]
CHAR_LABELS = [
    "<=500",
    "501-1000",
    "1001-2000",
    "2001-5000",
    "5001-10000",
    "10001-20000",
    "20001-50000",
    "50001-100000",
    ">100000",
]
LINE_BINS = [-1, 10, 20, 50, 100, 200, 500, float("inf")]
LINE_LABELS = ["<=10", "11-20", "21-50", "51-100", "101-200", "201-500", ">500"]
PERCENTILES = [0, 0.1, 0.25, 0.5, 0.75, 0.9, 0.95, 0.99, 1]


def summarize(series: pd.Series, bins: list[float], labels: list[str]) -> dict:
    quantiles = series.quantile(PERCENTILES)
    counts = pd.cut(series, bins=bins, labels=labels).value_counts(sort=False)
    total = len(series)
    return {
        "mean": round(float(series.mean()), 2),
        "std": round(float(series.std()), 2),
        "quantiles": {
            str(int(percentile * 100)): round(float(quantiles.loc[percentile]), 2)
            for percentile in PERCENTILES
        },
        "bins": {
            label: {
                "count": int(counts[label]),
                "percentage": round(float(counts[label] / total * 100), 2),
            }
            for label in labels
        },
    }


def analyze(path: Path) -> dict:
    frame = pd.read_csv(path, encoding="utf-8")
    required = {"func_before", "func_after", "diff"}
    missing = sorted(required - set(frame.columns))
    if missing:
        raise ValueError(f"missing required columns: {missing}")
    metrics = {
        "diff_characters": frame["diff"].str.len(),
        "diff_lines": frame["diff"].str.count("\n") + 1,
        "func_before_characters": frame["func_before"].str.len(),
        "func_after_characters": frame["func_after"].str.len(),
        "func_before_lines": frame["func_before"].str.count("\n") + 1,
        "func_after_lines": frame["func_after"].str.count("\n") + 1,
    }
    return {
        "input": str(path.resolve()),
        "sample_count": len(frame),
        **{
            name: summarize(
                series,
                LINE_BINS if name.endswith("_lines") else CHAR_BINS,
                LINE_LABELS if name.endswith("_lines") else CHAR_LABELS,
            )
            for name, series in metrics.items()
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze function and diff lengths.")
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = analyze(args.input)
    text = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + "\n", encoding="utf-8")
        print(f"output={args.output.resolve()}")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
