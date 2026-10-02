import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from three_stage_pipeline.inputs import load_inputs_by_sample_ids
from three_stage_pipeline.pipeline import PipelineInput, PipelineIssue
from three_stage_pipeline.rerun import (
    load_error_sample_ids,
    main as rerun_main,
)


class RerunErrorSamplesTests(unittest.TestCase):
    def test_loads_only_requested_csv_samples_in_requested_order(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            input_path = Path(directory) / "input.csv"
            input_path.write_text(
                "sample_id,func_before,func_after,commit_msg_anonymized\n"
                "sample-a,before-a,after-a,message-a\n"
                "sample-b,before-b,after-b,message-b\n",
                encoding="utf-8",
            )

            samples = load_inputs_by_sample_ids(
                input_path, ["sample-b", "sample-a"], csv_chunk_size=1
            )

            self.assertEqual(
                [sample.sample_id for sample in samples], ["sample-b", "sample-a"]
            )
            self.assertEqual(samples[0].commit_msg, "message-b")
            with self.assertRaisesRegex(ValueError, "not found.*missing"):
                load_inputs_by_sample_ids(input_path, ["missing"], csv_chunk_size=1)

    def test_loads_unique_sample_ids_and_ignores_run_level_errors(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            errors_path = Path(directory) / "pipeline_errors.jsonl"
            entries = [
                {"sample_id": "sample-b", "phase": "C"},
                {"sample_id": "sample-a", "phase": "A"},
                {"sample_id": "sample-b", "phase": "B"},
                {"sample_id": "[RUN]", "phase": "FINAL_CSV"},
            ]
            errors_path.write_text(
                "".join(json.dumps(entry) + "\n" for entry in entries),
                encoding="utf-8",
            )

            self.assertEqual(
                load_error_sample_ids(errors_path), ["sample-b", "sample-a"]
            )

    def test_cli_reruns_selected_samples_and_writes_a_separate_error_log(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            errors_path = root / "pipeline_errors.jsonl"
            errors_path.write_text(
                json.dumps({"sample_id": "sample-b", "phase": "C"}) + "\n",
                encoding="utf-8",
            )
            output_dir = root / "output"
            samples = [
                PipelineInput("sample-a", "before-a", "after-a"),
                PipelineInput("sample-b", "before-b", "after-b"),
            ]
            remaining_issue = PipelineIssue.from_error(
                "sample-b", "A", RuntimeError("failed again")
            )

            with (
                patch(
                    "three_stage_pipeline.rerun.load_inputs_by_sample_ids",
                    return_value=[samples[1]],
                ),
                patch(
                    "three_stage_pipeline.rerun.run_samples",
                    return_value=[remaining_issue],
                ) as run_samples,
                patch("builtins.print"),
            ):
                exit_code = rerun_main(
                    [
                        str(errors_path),
                        "input.csv",
                        "--workers",
                        "3",
                        "--output-dir",
                        str(output_dir),
                    ]
                )

            self.assertEqual(exit_code, 1)
            selected_samples = run_samples.call_args.args[0]
            self.assertEqual([sample.sample_id for sample in selected_samples], ["sample-b"])
            self.assertEqual(run_samples.call_args.kwargs["workers"], 3)
            self.assertTrue(errors_path.exists())
            rerun_entries = [
                json.loads(line)
                for line in (output_dir / "pipeline_errors_rerun.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
            ]
            self.assertEqual(
                [(entry["sample_id"], entry["phase"]) for entry in rerun_entries],
                [("sample-b", "A")],
            )

    def test_cli_rejects_overwriting_the_source_error_log(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            errors_path = Path(directory) / "pipeline_errors.jsonl"
            errors_path.write_text(
                json.dumps({"sample_id": "sample-a", "phase": "A"}) + "\n",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "must differ"):
                rerun_main(
                    [
                        str(errors_path),
                        "input.csv",
                        "--rerun-log",
                        str(errors_path),
                    ]
                )


if __name__ == "__main__":
    unittest.main()
