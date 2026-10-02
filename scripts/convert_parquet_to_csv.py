from __future__ import annotations

import argparse
import os
from pathlib import Path

import pandas as pd


def convert(source: Path, destination: Path) -> tuple[int, int]:
    """Convert one Parquet table to UTF-8 CSV using an atomic replacement."""
    if not source.is_file():
        raise ValueError(f"source file does not exist: {source}")
    if source.suffix.lower() != ".parquet":
        raise ValueError("source must be a .parquet file")

    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    try:
        frame = pd.read_parquet(source)
        frame.to_csv(temporary, index=False, encoding="utf-8", lineterminator="\n")
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)
    return len(frame), len(frame.columns)


def main() -> int:
    parser = argparse.ArgumentParser(description="Convert a Parquet table to UTF-8 CSV")
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path, nargs="?")
    args = parser.parse_args()
    destination = args.destination or args.source.with_suffix(".csv")
    rows, columns = convert(args.source, destination)
    print(f"converted {rows} rows x {columns} columns -> {destination.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
