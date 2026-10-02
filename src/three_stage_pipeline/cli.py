from __future__ import annotations

import argparse
import json
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

from .client import OpenAIJsonModel
from .inputs import load_inputs
from .pipeline import (
    PipelineInput,
    PipelineIssue,
    PipelineRun,
    ThreeStagePipeline,
    persist_pipeline_run,
    write_pipeline_issue_log,
)
from .results import FinalResultsStore


_WORKER_PIPELINE: ThreeStagePipeline | None = None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the extracted three-stage LLM pipeline")
    parser.add_argument(
        "input",
        nargs="?",
        type=Path,
        default=Path("input"),
        help="input directory or .csv/.json/.jsonl/.parquet file (default: input)",
    )
    parser.add_argument("--start", type=int, default=1, help="first sample, 1-based inclusive")
    parser.add_argument("--end", type=int, default=1, help="last sample, 1-based inclusive")
    parser.add_argument(
        "--workers",
        type=_positive_int,
        default=1,
        help="number of model worker processes (default: 1)",
    )
    parser.add_argument("--output-dir", type=Path, default=Path("output"))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    samples = load_inputs(args.input, start=args.start, end=args.end)
    issues = run_samples(samples, args.output_dir, workers=args.workers)
    log_path = write_pipeline_issue_log(args.output_dir, issues)
    print(f"wrote {len(samples)} sample(s) to {args.output_dir.resolve()}")
    print(f"issues: {len(issues)}; log: {log_path.resolve()}")
    return 0


def run_samples(
    samples: list[PipelineInput], output_dir: Path, *, workers: int = 1
) -> list[PipelineIssue]:
    if isinstance(workers, bool) or not isinstance(workers, int) or workers < 1:
        raise ValueError("workers must be an integer greater than or equal to 1")
    if workers == 1:
        return _run_serial(samples, output_dir)
    return _run_parallel(samples, output_dir, workers)


def _run_serial(samples: list[PipelineInput], output_dir: Path) -> list[PipelineIssue]:
    pipeline = ThreeStagePipeline(
        OpenAIJsonModel.from_env(),
        output_dir,
        issue_reporter=_print_issue,
    )
    for sample in samples:
        issue_count_before = len(pipeline.issues)
        try:
            pipeline.run(sample)
        except Exception as error:
            pipeline.record_issue(sample.sample_id, "PIPELINE", error)
            print(f"continued after unrecoverable sample error: {sample.sample_id}")
            continue
        suffix = " with placeholder(s)" if len(pipeline.issues) > issue_count_before else ""
        print(f"completed {sample.sample_id}{suffix}")
    return pipeline.issues


def _run_parallel(
    samples: list[PipelineInput], output_dir: Path, workers: int
) -> list[PipelineIssue]:
    if not samples:
        return []

    issues: list[PipelineIssue] = []
    worker_count = min(workers, len(samples))
    final_results = FinalResultsStore(output_dir / "final_results.csv")
    print(f"starting {worker_count} worker process(es)")
    with ProcessPoolExecutor(
        max_workers=worker_count, initializer=_initialize_worker
    ) as executor:
        futures = [executor.submit(_analyze_sample_worker, sample) for sample in samples]
        for sample, future in zip(samples, futures):
            try:
                analysis = future.result()
            except Exception as error:
                issue = PipelineIssue.from_error(sample.sample_id, "WORKER", error)
                issues.append(issue)
                _print_issue(issue)
                continue

            issues.extend(analysis.issues)
            for issue in analysis.issues:
                _print_issue(issue)
            try:
                persist_pipeline_run(
                    output_dir, sample, analysis, write_final_csv=False
                )
                final_results.upsert(analysis.result)
            except Exception as error:
                issue = PipelineIssue.from_error(sample.sample_id, "PIPELINE", error)
                issues.append(issue)
                _print_issue(issue)
                continue
            suffix = " with placeholder(s)" if analysis.issues else ""
            print(f"completed {sample.sample_id}{suffix}")
    try:
        final_results.flush()
    except Exception as error:
        issue = PipelineIssue.from_error("[RUN]", "FINAL_CSV", error)
        issues.append(issue)
        _print_issue(issue)
    return issues


def _initialize_worker() -> None:
    global _WORKER_PIPELINE
    _WORKER_PIPELINE = ThreeStagePipeline(OpenAIJsonModel.from_env())


def _analyze_sample_worker(sample: PipelineInput) -> PipelineRun:
    if _WORKER_PIPELINE is None:
        raise RuntimeError("worker process was not initialized")
    return _WORKER_PIPELINE.analyze(sample)


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("workers must be greater than or equal to 1")
    return parsed


def _print_issue(issue: PipelineIssue) -> None:
    print(
        f"WARNING sample={issue.sample_id} phase={issue.phase} "
        f"{issue.error_type}: {issue.message}; placeholder recorded, continuing",
        flush=True,
    )
    for attempt in issue.details.get("attempts", []):
        context = []
        if attempt.get("status_code") is not None:
            context.append(f"status={attempt['status_code']}")
        if attempt.get("request_id"):
            context.append(f"request_id={attempt['request_id']}")
        suffix = f" {' '.join(context)}" if context else ""
        print(
            f"  phase={attempt.get('phase', issue.phase)} "
            f"model={attempt.get('model', '[unknown]')} "
            f"attempt={attempt['attempt']}/{attempt['max_attempts']} "
            f"{attempt['error_type']}: {attempt['message']}{suffix}",
            flush=True,
        )
        if attempt.get("response_body"):
            print(f"    response_body={attempt['response_body']}", flush=True)
        if attempt.get("model_output"):
            print(f"    model_output={attempt['model_output']}", flush=True)
    if issue.details.get("model_output") is not None:
        print(
            "  rejected_model_output="
            + json.dumps(issue.details["model_output"], ensure_ascii=False),
            flush=True,
        )


if __name__ == "__main__":
    raise SystemExit(main())
