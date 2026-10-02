from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from three_stage_pipeline.cds import analyze_cds_csv


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Calculate composite similarity, derive CDS = 1 - similarity, "
            "and write the CDS distribution in 0.1-wide bins."
        )
    )
    parser.add_argument("input", type=Path, help="source CSV file")
    parser.add_argument(
        "--output",
        type=Path,
        help="enriched CSV path (default: <input>_with_cds.csv)",
    )
    parser.add_argument(
        "--distribution-output",
        type=Path,
        help="distribution CSV path (default: <input>_cds_distribution.csv)",
    )
    parser.add_argument(
        "--round-digits",
        type=int,
        default=6,
        help="decimal places used for similarity, CDS, and grouping (default: 6)",
    )
    parser.add_argument(
        "--encoding",
        default="auto",
        help=(
            "input CSV encoding; default auto detects UTF-8, UTF-16, and "
            "GB18030 (for example: --encoding cp1252)"
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    summary = analyze_cds_csv(
        args.input,
        args.output,
        args.distribution_output,
        round_digits=args.round_digits,
        encoding=args.encoding,
    )
    print(json.dumps(summary.to_dict(), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
