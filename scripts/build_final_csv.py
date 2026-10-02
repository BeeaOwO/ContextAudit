from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from three_stage_pipeline.results import rebuild_final_csv_from_combined


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Rebuild a final 26-column CSV from combined JSON files."
    )
    parser.add_argument(
        "combined_dir",
        nargs="?",
        type=Path,
        default=Path("output/combined"),
        help="combined JSON directory (default: output/combined)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("output/final_results_from_combined.csv"),
        help="output CSV path (default: output/final_results_from_combined.csv)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    row_count = rebuild_final_csv_from_combined(args.combined_dir, args.output)
    print(
        json.dumps(
            {
                "event": "final_csv_rebuilt",
                "combined_dir": str(args.combined_dir.resolve()),
                "output_path": str(args.output.resolve()),
                "row_count": row_count,
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
