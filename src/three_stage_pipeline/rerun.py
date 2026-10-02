from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .cli import run_samples
from .inputs import load_inputs_by_sample_ids
from .pipeline import write_pipeline_issue_log


MAX_ERROR_LOG_BYTES = 100 * 1024 * 1024


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Rerun complete A/B/C pipelines for samples listed in an error log."
    )
    parser.add_argument(
        "errors",
        nargs="?",
        type=Path,
        default=Path("output/pipeline_errors.jsonl"),
        help="source pipeline error JSONL (default: output/pipeline_errors.jsonl)",
    )
    parser.add_argument(
        "input",
        nargs="?",
        type=Path,
        default=Path("input/diversevul_paired_anonymized.csv"),
        help="original input CSV or compatible input file",
    )
    parser.add_argument("--workers", type=_positive_int, default=1)
    parser.add_argument("--output-dir", type=Path, default=Path("output"))
    parser.add_argument(
        "--rerun-log",
        type=Path,
        help="new error log path (default: <output-dir>/pipeline_errors_rerun.jsonl)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    rerun_log = args.rerun_log or args.output_dir / "pipeline_errors_rerun.jsonl"
    if args.errors.resolve() == rerun_log.resolve():
        raise ValueError("source error log and rerun log must differ")

    sample_ids = load_error_sample_ids(args.errors)
    samples = load_inputs_by_sample_ids(args.input, sample_ids)
    print(
        json.dumps(
            {"event": "rerun_started", "sample_count": len(samples)},
            ensure_ascii=False,
        )
    )
    issues = run_samples(samples, args.output_dir, workers=args.workers)
    log_path = write_pipeline_issue_log(args.output_dir, issues, rerun_log)
    failed_sample_ids = list(
        dict.fromkeys(issue.sample_id for issue in issues if issue.sample_id != "[RUN]")
    )
    print(
        json.dumps(
            {
                "event": "rerun_finished",
                "sample_count": len(samples),
                "issue_count": len(issues),
                "failed_sample_count": len(failed_sample_ids),
                "error_log": str(log_path.resolve()),
            },
            ensure_ascii=False,
        )
    )
    return 1 if issues else 0


def load_error_sample_ids(path: Path | str) -> list[str]:
    source = Path(path)
    if not source.is_file():
        raise ValueError(f"error log does not exist: {source}")
    if source.stat().st_size > MAX_ERROR_LOG_BYTES:
        raise ValueError(f"error log exceeds {MAX_ERROR_LOG_BYTES} bytes")

    sample_ids: list[str] = []
    seen: set[str] = set()
    with source.open("r", encoding="utf-8-sig") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            entry = _decode_error_entry(line, line_number)
            sample_id = entry.get("sample_id")
            if not isinstance(sample_id, str) or not sample_id.strip():
                raise ValueError(
                    f"error log line {line_number} has no non-empty sample_id"
                )
            if sample_id == "[RUN]" or sample_id in seen:
                continue
            seen.add(sample_id)
            sample_ids.append(sample_id)
    if not sample_ids:
        raise ValueError("error log contains no sample-level errors to rerun")
    return sample_ids


def _decode_error_entry(line: str, line_number: int) -> dict[str, Any]:
    try:
        entry = json.loads(line, parse_constant=_reject_json_constant)
    except (json.JSONDecodeError, ValueError) as error:
        raise ValueError(f"invalid JSON on error log line {line_number}: {error}") from error
    if not isinstance(entry, dict):
        raise ValueError(f"error log line {line_number} must be a JSON object")
    return entry


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("workers must be greater than or equal to 1")
    return parsed


if __name__ == "__main__":
    raise SystemExit(main())
