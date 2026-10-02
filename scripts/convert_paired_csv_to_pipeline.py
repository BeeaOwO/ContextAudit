from __future__ import annotations

import argparse
from pathlib import Path

from three_stage_pipeline.paired_csv import convert_paired_csv


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Convert TitanVul, BenchVul, or vulnerability_score CSV into pipeline input CSV."
    )
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument(
        "--dataset",
        required=True,
        choices=("titanvul", "benchvul", "vulnerability_score"),
    )
    parser.add_argument("--errors", type=Path)
    args = parser.parse_args()

    stats = convert_paired_csv(
        args.source,
        args.destination,
        dataset=args.dataset,
        error_path=args.errors,
    )
    print(
        "conversion complete: "
        f"read={stats.read} written={stats.written} invalid={stats.invalid} "
        f"unchanged={stats.unchanged} duplicates={stats.duplicates}"
    )
    print(f"csv={args.destination.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
