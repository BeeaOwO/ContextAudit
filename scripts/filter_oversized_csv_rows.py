from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import tempfile
from pathlib import Path


DEFAULT_MAX_FIELD_LENGTH = 131_072
csv.field_size_limit(sys.maxsize)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Remove rows containing CSV fields above a configured length."
    )
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--excluded", type=Path, required=True)
    parser.add_argument(
        "--max-field-length", type=int, default=DEFAULT_MAX_FIELD_LENGTH
    )
    args = parser.parse_args()
    if args.max_field_length < 1:
        parser.error("--max-field-length must be positive")
    if not args.source.is_file():
        parser.error(f"source does not exist: {args.source}")

    args.destination.parent.mkdir(parents=True, exist_ok=True)
    args.excluded.parent.mkdir(parents=True, exist_ok=True)
    output_fd, output_name = tempfile.mkstemp(
        dir=args.destination.parent, suffix=".csv.tmp"
    )
    excluded_fd, excluded_name = tempfile.mkstemp(
        dir=args.excluded.parent, suffix=".jsonl.tmp"
    )
    os.close(output_fd)
    os.close(excluded_fd)
    output_tmp = Path(output_name)
    excluded_tmp = Path(excluded_name)
    written = excluded = 0
    try:
        with (
            args.source.open("r", encoding="utf-8-sig", newline="") as source,
            output_tmp.open("w", encoding="utf-8", newline="") as destination,
            excluded_tmp.open("w", encoding="utf-8", newline="\n") as log,
        ):
            reader = csv.DictReader(source)
            if not reader.fieldnames:
                raise ValueError("input CSV has no header")
            writer = csv.DictWriter(
                destination, fieldnames=reader.fieldnames, lineterminator="\n"
            )
            writer.writeheader()
            for row_number, row in enumerate(reader, start=2):
                oversized = {
                    key: len(value or "")
                    for key, value in row.items()
                    if key is not None and len(value or "") > args.max_field_length
                }
                if oversized:
                    excluded += 1
                    log.write(
                        json.dumps(
                            {
                                "csv_row": row_number,
                                "sample_id": row.get("sample_id", ""),
                                "reason": "oversized_csv_field",
                                "max_field_length": args.max_field_length,
                                "oversized_fields": oversized,
                            },
                            ensure_ascii=False,
                        )
                        + "\n"
                    )
                    continue
                writer.writerow(row)
                written += 1
        os.replace(output_tmp, args.destination)
        os.replace(excluded_tmp, args.excluded)
    finally:
        output_tmp.unlink(missing_ok=True)
        excluded_tmp.unlink(missing_ok=True)
    print(f"filtered written={written} excluded={excluded}")
    print(f"csv={args.destination.resolve()}")
    print(f"excluded_log={args.excluded.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
