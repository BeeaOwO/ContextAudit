from __future__ import annotations

import argparse
from pathlib import Path

from three_stage_pipeline.megavul import convert_megavul_json


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Filter MegaVul vulnerable function pairs and write DiverseVul-compatible CSV."
    )
    parser.add_argument("source", type=Path, help="MegaVul JSON array")
    parser.add_argument("destination", type=Path, help="output CSV")
    parser.add_argument("--max-diff-chars", type=int, default=1500)
    parser.add_argument("--max-function-chars", type=int, default=5000)
    parser.add_argument("--max-function-lines", type=int, default=500)
    args = parser.parse_args()

    stats = convert_megavul_json(
        args.source,
        args.destination,
        max_diff_chars=args.max_diff_chars,
        max_function_chars=args.max_function_chars,
        max_function_lines=args.max_function_lines,
    )
    print(
        "conversion complete: "
        f"read={stats.read} candidates={stats.candidates} written={stats.written} "
        f"filtered={stats.filtered} invalid={stats.invalid}"
    )
    print(f"csv={args.destination.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
