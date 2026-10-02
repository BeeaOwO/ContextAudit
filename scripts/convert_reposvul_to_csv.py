from __future__ import annotations

import argparse
from pathlib import Path

from three_stage_pipeline.reposvul import (
    convert_reposvul_jsonl,
    merge_reposvul_jsonl,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Reconstruct vulnerable/fixed function pairs from a flattened ReposVul "
            "JSONL file and write a DiverseVul-compatible CSV."
        )
    )
    parser.add_argument("source", type=Path, help="ReposVul repository2 JSONL file")
    parser.add_argument("destination", type=Path, help="output paired CSV file")
    parser.add_argument(
        "--merge-source",
        action="append",
        default=[],
        type=Path,
        help="additional JSONL split to merge before conversion; may be repeated",
    )
    parser.add_argument(
        "--merged-output",
        type=Path,
        help="path for the combined ReposVul JSONL (required with --merge-source)",
    )
    parser.add_argument(
        "--errors",
        type=Path,
        help="JSONL skip/error log (default: <destination>.skipped.jsonl)",
    )
    parser.add_argument(
        "--include-outdated",
        action="store_true",
        help="include records marked outdated (excluded by default)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="timeout in seconds for each parent source file request (default: 30)",
    )
    parser.add_argument(
        "--progress-every",
        type=int,
        default=50,
        help="print progress after this many candidate records; 0 disables it",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=8,
        help="number of concurrent source-file downloads (default: 8)",
    )
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero")
    if args.progress_every < 0:
        parser.error("--progress-every must be zero or greater")
    if args.workers < 1:
        parser.error("--workers must be greater than zero")
    if args.merge_source and args.merged_output is None:
        parser.error("--merged-output is required when --merge-source is used")

    conversion_source = args.source
    if args.merged_output is not None:
        merge_stats = merge_reposvul_jsonl(
            [args.source, *args.merge_source], args.merged_output
        )
        conversion_source = args.merged_output
        print(
            "merge complete: "
            f"sources={merge_stats.sources} records={merge_stats.records} "
            f"bytes={merge_stats.bytes_written}"
        )
        print(f"merged_jsonl={args.merged_output.resolve()}")

    error_path = args.errors or args.destination.with_suffix(
        args.destination.suffix + ".skipped.jsonl"
    )
    stats = convert_reposvul_jsonl(
        conversion_source,
        args.destination,
        error_path=error_path,
        timeout=args.timeout,
        include_outdated=args.include_outdated,
        progress_every=args.progress_every,
        workers=args.workers,
    )
    print(
        "conversion complete: "
        f"read={stats.read} candidates={stats.candidates} "
        f"written={stats.written} skipped={stats.skipped} "
        f"duplicates={stats.duplicates}"
    )
    print(f"csv={args.destination.resolve()}")
    print(f"skip_log={error_path.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
