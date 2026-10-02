import json
import csv
import os
import runpy
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from three_stage_pipeline.cli import build_parser, load_inputs, main as cli_main
from three_stage_pipeline.client import OpenAIJsonModel
from three_stage_pipeline.contracts import validate_phase_output
from three_stage_pipeline.pipeline import (
    PipelineInput,
    PipelineIssue,
    PipelineRun,
    ThreeStagePipeline,
)
from three_stage_pipeline.results import FinalResultsStore


class FakeModel:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str]] = []
        self.responses = {
            "A": {
                "non_standard_external_calls": ["copy_from_user"],
                "data_flow_path": "length -> copy_from_user -> buffer",
                "vulnerability_node": {
                    "variable_name": "length",
                    "step_location": "copy block",
                    "issue_description": "length is not checked",
                },
                "confidence": 81,
                "additional_context_needed": "caller constraints",
            },
            "B": {
                "data_flow_path": "length -> bounds check -> copy_from_user -> buffer",
                "vulnerability_node": {
                    "variable_name": "length",
                    "step_location": "copy block",
                    "issue_description": "the patch adds a length bound",
                },
                "cwe_type": "CWE-125",
                "depends_on_caller": True,
                "caller_constraint": "caller controls length",
            },
            "C": {
                "variable_match_score": 1.0,
                "step_position_score": 0.7,
                "dataflow_path_score": 0.3,
                "overall_consistency": "部分一致",
                "comment": "变量一致，但位置和数据流只有部分重合",
            },
        }

    def complete_json(self, system_prompt: str, user_prompt: str, phase: str) -> dict:
        self.calls.append((phase, system_prompt, user_prompt))
        return self.responses[phase]


class FailFirstPhaseAModel(FakeModel):
    def __init__(self) -> None:
        super().__init__()
        self.failed = False

    def complete_json(self, system_prompt: str, user_prompt: str, phase: str) -> dict:
        if phase == "A" and not self.failed:
            self.failed = True
            raise RuntimeError("temporary model failure")
        return super().complete_json(system_prompt, user_prompt, phase)


class ThreeStagePipelineTests(unittest.TestCase):
    def test_final_results_store_batches_multiple_upserts_into_one_flush(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "final.csv"
            first = ThreeStagePipeline(FakeModel()).analyze(
                PipelineInput(sample_id="one", func_before="before", func_after="after")
            ).result
            second = ThreeStagePipeline(FakeModel()).analyze(
                PipelineInput(sample_id="two", func_before="before", func_after="after")
            ).result
            store = FinalResultsStore(path)

            store.upsert(first)
            store.upsert(second)
            first["phase_c_comment"] = "updated"
            store.upsert(first)

            self.assertFalse(path.exists())
            store.flush()
            with path.open("r", encoding="utf-8-sig", newline="") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual([row["sample_id"] for row in rows], ["one", "two"])
            self.assertEqual(rows[0]["phase_c_comment"], "updated")

    def test_analysis_can_be_persisted_later_by_a_single_writer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_dir = Path(directory) / "output"
            pipeline = ThreeStagePipeline(model=FakeModel(), output_dir=output_dir)
            sample = PipelineInput(
                sample_id="deferred", func_before="before", func_after="after"
            )

            analysis = pipeline.analyze(sample)

            self.assertIsInstance(analysis, PipelineRun)
            self.assertFalse(output_dir.exists())
            pipeline.persist(sample, analysis)
            self.assertTrue((output_dir / "phase_a" / "deferred.json").exists())
            self.assertTrue((output_dir / "final_results.csv").exists())

    def test_runs_a_b_c_and_writes_matching_json_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            model = FakeModel()
            pipeline = ThreeStagePipeline(model=model, output_dir=Path(directory))
            sample = PipelineInput(
                sample_id="sample/001",
                func_before="void f(int length) { use(length); }",
                func_after="void f(int length) { if (length < 8) use(length); }",
                commit_msg="validate length",
                bug_description="out-of-bounds read",
                cwe="CWE-125",
                commit_id="abc123",
                project="demo",
            )

            result = pipeline.run(sample)

            self.assertEqual([call[0] for call in model.calls], ["A", "B", "C"])
            self.assertIn('"vulnerability_node"', model.calls[2][2])
            self.assertIn("length -> copy_from_user -> buffer", model.calls[2][2])
            self.assertIn("length -> bounds check -> copy_from_user -> buffer", model.calls[2][2])
            self.assertEqual(result["sample_id"], "sample/001")
            self.assertEqual(result["phase_a_vulnerability_variable"], "length")
            self.assertEqual(result["phase_b_vulnerability_variable"], "length")
            self.assertEqual(result["phase_c_variable_match_score"], 1.0)
            self.assertEqual(result["phase_c_step_position_score"], 0.7)
            self.assertEqual(result["phase_c_dataflow_path_score"], 0.3)
            self.assertEqual(result["phase_c_overall_consistency"], "部分一致")
            self.assertNotIn("similarity", result)
            self.assertNotIn("cds_score", result)

            expected = {
                "phase_a": model.responses["A"],
                "phase_b": model.responses["B"],
                "phase_c": model.responses["C"],
            }
            saved_name = None
            for folder, payload in expected.items():
                paths = list((Path(directory) / folder).glob("*.json"))
                self.assertEqual(len(paths), 1)
                path = paths[0]
                saved_name = saved_name or path.name
                self.assertEqual(path.name, saved_name)
                self.assertEqual(json.loads(path.read_text(encoding="utf-8")), payload)

            combined = Path(directory) / "combined" / saved_name
            self.assertEqual(json.loads(combined.read_text(encoding="utf-8")), result)

            final_csv = Path(directory) / "final_results.csv"
            with final_csv.open("r", encoding="utf-8-sig", newline="") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["sample_id"], "sample/001")
            self.assertEqual(rows[0]["cwe"], "CWE-125")
            self.assertEqual(rows[0]["phase_a_vulnerability_variable"], "length")
            self.assertEqual(
                json.loads(rows[0]["phase_a_non_standard_external_calls"]),
                ["copy_from_user"],
            )
            self.assertEqual(rows[0]["phase_b_depends_on_caller"], "true")

    def test_final_csv_upserts_sample_id_instead_of_duplicating_rows(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            model = FakeModel()
            pipeline = ThreeStagePipeline(model=model, output_dir=Path(directory))
            sample = PipelineInput(
                sample_id="same", func_before="before", func_after="after", cwe="CWE-125"
            )

            pipeline.run(sample)
            model.responses["C"]["comment"] = "updated"
            pipeline.run(sample)

            with (Path(directory) / "final_results.csv").open(
                "r", encoding="utf-8-sig", newline=""
            ) as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["phase_c_comment"], "updated")

    def test_uses_placeholder_logs_issue_and_continues_after_phase_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            model = FakeModel()
            model.responses["A"] = {"hypothesis": "missing required fields"}
            warnings = []
            pipeline = ThreeStagePipeline(
                model=model,
                output_dir=Path(directory),
                issue_reporter=warnings.append,
            )
            sample = PipelineInput(
                sample_id="bad",
                func_before="before",
                func_after="after",
            )

            result = pipeline.run(sample)
            log_path = pipeline.write_issue_log()

            self.assertEqual([call[0] for call in model.calls], ["A", "B", "C"])
            phase_a = json.loads(
                (Path(directory) / "phase_a" / "bad.json").read_text(encoding="utf-8")
            )
            self.assertTrue(phase_a["pipeline_placeholder"])
            self.assertEqual(result["phase_a_vulnerability_variable"], "[PHASE_A_ERROR]")
            self.assertFalse(json.loads(result["phase_b_raw"]).get("pipeline_placeholder", False))
            self.assertEqual(len(warnings), 1)
            self.assertEqual(warnings[0].sample_id, "bad")
            self.assertEqual(warnings[0].phase, "A")
            entries = [
                json.loads(line)
                for line in log_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0]["sample_id"], "bad")
            self.assertEqual(entries[0]["phase"], "A")

    def test_every_phase_has_a_schema_compatible_placeholder(self) -> None:
        raw_fields = {"A": "phase_a_raw", "B": "phase_b_raw", "C": "phase_c_raw"}
        for phase in ("A", "B", "C"):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as directory:
                model = FakeModel()
                model.responses[phase] = {}
                pipeline = ThreeStagePipeline(model=model, output_dir=Path(directory))
                sample = PipelineInput(
                    sample_id=f"bad-{phase.lower()}",
                    func_before="before",
                    func_after="after",
                    cwe="CWE-20",
                )

                result = pipeline.run(sample)

                placeholder = json.loads(result[raw_fields[phase]])
                self.assertTrue(placeholder["pipeline_placeholder"])
                self.assertEqual(
                    [(issue.sample_id, issue.phase) for issue in pipeline.issues],
                    [(sample.sample_id, phase)],
                )

    def test_rejects_unsafe_or_empty_sample_ids(self) -> None:
        with self.assertRaises(ValueError):
            PipelineInput(sample_id="   ", func_before="before", func_after="after")

    def test_accepts_arbitrary_numeric_phase_c_scores(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            model = FakeModel()
            model.responses["C"]["variable_match_score"] = 0.86
            model.responses["C"]["step_position_score"] = 0.52
            model.responses["C"]["dataflow_path_score"] = 0.91
            pipeline = ThreeStagePipeline(model=model, output_dir=Path(directory))
            sample = PipelineInput(sample_id="range", func_before="before", func_after="after")

            result = pipeline.run(sample)

            self.assertEqual(result["phase_c_variable_match_score"], 0.86)
            self.assertEqual(result["phase_c_step_position_score"], 0.52)
            self.assertEqual(result["phase_c_dataflow_path_score"], 0.91)

    def test_fills_omitted_phase_metadata_without_discarding_core_analysis(self) -> None:
        model = FakeModel()
        del model.responses["A"]["confidence"]
        del model.responses["A"]["additional_context_needed"]
        del model.responses["B"]["cwe_type"]
        del model.responses["B"]["depends_on_caller"]
        del model.responses["B"]["caller_constraint"]
        pipeline = ThreeStagePipeline(model=model)
        sample = PipelineInput(
            sample_id="missing-metadata",
            func_before="before",
            func_after="after",
            cwe="CWE-125",
        )

        analysis = pipeline.analyze(sample)

        self.assertEqual(analysis.issues, ())
        self.assertEqual(analysis.phase_a["confidence"], 0)
        self.assertEqual(
            analysis.phase_a["additional_context_needed"], "模型未提供该字段"
        )
        self.assertEqual(analysis.phase_b["cwe_type"], "CWE-125")
        self.assertFalse(analysis.phase_b["depends_on_caller"])
        self.assertIsNone(analysis.phase_b["caller_constraint"])
        self.assertEqual(analysis.phase_b["data_flow_path"], model.responses["B"]["data_flow_path"])

    def test_normalizes_unknown_phase_b_locations_and_multiple_cwe_values(self) -> None:
        model = FakeModel()
        model.responses["B"]["vulnerability_node"]["variable_name"] = None
        model.responses["B"]["vulnerability_node"]["step_location"] = ""
        model.responses["B"]["cwe_type"] = ["CWE-190", "CWE-125"]
        pipeline = ThreeStagePipeline(model=model)
        sample = PipelineInput(
            sample_id="normalized-values", func_before="before", func_after="after"
        )

        analysis = pipeline.analyze(sample)

        self.assertEqual(analysis.issues, ())
        self.assertEqual(
            analysis.phase_b["vulnerability_node"]["variable_name"], "无法确定"
        )
        self.assertEqual(
            analysis.phase_b["vulnerability_node"]["step_location"], "无法确定"
        )
        self.assertEqual(analysis.phase_b["cwe_type"], "CWE-190, CWE-125")

    def test_phase_c_comment_object_is_serialized_for_json_and_final_csv(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            comment = {
                "variable_match": {"命中证据": "变量证据", "评分理由": "变量理由"},
                "step_position": {"命中证据": "位置证据", "评分理由": "位置理由"},
                "dataflow_path": {"命中证据": "路径证据", "评分理由": "路径理由"},
            }
            model = FakeModel()
            model.responses["C"]["comment"] = comment
            pipeline = ThreeStagePipeline(model=model, output_dir=Path(directory))
            sample = PipelineInput(
                sample_id="object-comment", func_before="before", func_after="after"
            )

            result = pipeline.run(sample)

            self.assertEqual(pipeline.issues, [])
            phase_c = json.loads(
                (Path(directory) / "phase_c" / "object-comment.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertIsInstance(phase_c["comment"], str)
            self.assertEqual(json.loads(phase_c["comment"]), comment)
            self.assertIsInstance(result["phase_c_comment"], str)
            self.assertEqual(json.loads(result["phase_c_comment"]), comment)
            with (Path(directory) / "final_results.csv").open(
                "r", encoding="utf-8-sig", newline=""
            ) as handle:
                row = next(csv.DictReader(handle))
            self.assertIsInstance(row["phase_c_comment"], str)
            self.assertEqual(json.loads(row["phase_c_comment"]), comment)

    def test_requires_every_phase_c_field_declared_by_prompt(self) -> None:
        model = FakeModel()
        del model.responses["C"]["overall_consistency"]

        with self.assertRaisesRegex(ValueError, "overall_consistency"):
            validate_phase_output("C", model.responses["C"])

    def test_requires_prompt_defined_nested_vulnerability_node(self) -> None:
        model = FakeModel()
        del model.responses["A"]["vulnerability_node"]["variable_name"]

        with self.assertRaisesRegex(ValueError, "variable_name"):
            validate_phase_output("A", model.responses["A"])

    def test_filename_sanitizing_does_not_overwrite_a_different_sample(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pipeline = ThreeStagePipeline(model=FakeModel(), output_dir=Path(directory))

            pipeline.run(PipelineInput(sample_id="a/b", func_before="before", func_after="after"))
            pipeline.run(PipelineInput(sample_id="a_b", func_before="before", func_after="after"))

            files = list((Path(directory) / "combined").glob("*.json"))
            self.assertEqual(len(files), 2)
            saved_ids = {json.loads(path.read_text(encoding="utf-8"))["sample_id"] for path in files}
            self.assertEqual(saved_ids, {"a/b", "a_b"})


class OpenAIJsonModelTests(unittest.TestCase):
    def test_decodes_json_with_trailing_commas_before_object_or_array_end(self) -> None:
        content = (
            '{"data_flow_path":"path",'
            '"vulnerability_node":{"variable_name":"hid->inputs",},'
            '"evidence":["one","two",],'
            '"note":"literal comma before brace: , }",}'
        )
        response = SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(content=content),
                    finish_reason="stop",
                )
            ]
        )
        completions = SimpleNamespace(create=lambda **kwargs: response)
        fake_client = SimpleNamespace(chat=SimpleNamespace(completions=completions))
        model = OpenAIJsonModel(client=fake_client, model="demo", max_attempts=1)

        result = model.complete_json("system", "user", "B")

        self.assertEqual(result["vulnerability_node"]["variable_name"], "hid->inputs")
        self.assertEqual(result["evidence"], ["one", "two"])
        self.assertEqual(result["note"], "literal comma before brace: , }")

    def test_decodes_json_with_only_closing_delimiters_missing_at_eof(self) -> None:
        content = '{"data_flow_path":"path","vulnerability_node":{"variable_name":"x"}'
        response = SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(content=content),
                    finish_reason="stop",
                )
            ]
        )
        completions = SimpleNamespace(create=lambda **kwargs: response)
        fake_client = SimpleNamespace(chat=SimpleNamespace(completions=completions))
        model = OpenAIJsonModel(client=fake_client, model="demo", max_attempts=1)

        result = model.complete_json("system", "user", "B")

        self.assertEqual(result["vulnerability_node"]["variable_name"], "x")

    def test_uses_final_json_object_after_commentary_objects(self) -> None:
        content = (
            '{"commentary":"working"}'
            '{"commentary":"still working"}'
            '{"data_flow_path":"final result"}'
        )
        response = SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(content=content),
                    finish_reason="stop",
                )
            ]
        )
        completions = SimpleNamespace(create=lambda **kwargs: response)
        fake_client = SimpleNamespace(chat=SimpleNamespace(completions=completions))
        model = OpenAIJsonModel(client=fake_client, model="demo", max_attempts=1)

        result = model.complete_json("system", "user", "B")

        self.assertEqual(result, {"data_flow_path": "final result"})

    def test_decodes_json_wrapped_in_a_markdown_code_fence(self) -> None:
        for content in (
            '```json\n{"ok": true}\n```',
            '```JSON\r\n{"ok": true}\r\n```',
            '```\n{"ok": true}\n```',
        ):
            with self.subTest(content=content):
                response = SimpleNamespace(
                    choices=[
                        SimpleNamespace(
                            message=SimpleNamespace(content=content),
                            finish_reason="stop",
                        )
                    ]
                )
                completions = SimpleNamespace(create=lambda **kwargs: response)
                fake_client = SimpleNamespace(
                    chat=SimpleNamespace(completions=completions)
                )
                model = OpenAIJsonModel(
                    client=fake_client, model="claude", max_attempts=1
                )

                self.assertEqual(
                    model.complete_json("system", "user", "B"), {"ok": True}
                )

    def test_decodes_json_and_uses_phase_specific_thinking_config(self) -> None:
        response = SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(
                        content=(
                            '{"variable_match_score":1.0,"step_position_score":0.7,'
                            '"dataflow_path_score":0.3,"overall_consistency":"部分一致",'
                            '"comment":"partial"}'
                        )
                    ),
                    finish_reason="stop",
                )
            ]
        )
        requests = []

        def create(**kwargs):
            requests.append(kwargs)
            return response

        completions = SimpleNamespace(create=create)
        fake_client = SimpleNamespace(chat=SimpleNamespace(completions=completions))
        model = OpenAIJsonModel(client=fake_client, model="demo", max_attempts=1)

        results = [
            model.complete_json("system", "user", phase) for phase in ("A", "B", "C")
        ]

        self.assertTrue(
            all(result["variable_match_score"] == 1.0 for result in results)
        )
        self.assertEqual(
            [request["extra_body"]["thinking"]["type"] for request in requests],
            ["disabled", "disabled", "disabled"],
        )

    def test_from_env_requires_all_connection_settings(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ValueError, "LLM_API_KEY"):
                OpenAIJsonModel.from_env()

    def test_failed_attempts_keep_gateway_details_and_redact_secrets(self) -> None:
        class GatewayResponse:
            status_code = 502
            headers = {"x-request-id": "req-claude-123"}
            text = '{"error":"upstream Claude failed","api_key":"sk-secret"}'

        class GatewayError(Exception):
            status_code = 502
            request_id = "req-claude-123"
            response = GatewayResponse()

        def fail_request(**kwargs):
            raise GatewayError("Bad gateway; Authorization: Bearer sk-secret")

        reports = []
        completions = SimpleNamespace(create=fail_request)
        fake_client = SimpleNamespace(chat=SimpleNamespace(completions=completions))
        model = OpenAIJsonModel(
            client=fake_client,
            model="claude-via-gateway",
            max_attempts=2,
            error_reporter=reports.append,
        )

        with patch("three_stage_pipeline.client.time.sleep"):
            with self.assertRaises(RuntimeError) as raised:
                model.complete_json("system", "user", "A")

        issue = PipelineIssue.from_error("sample-1", "A", raised.exception)
        payload = issue.to_dict()
        self.assertIn("GatewayError", payload["message"])
        self.assertEqual(len(payload["details"]["attempts"]), 2)
        self.assertEqual(payload["details"]["attempts"][0]["status_code"], 502)
        self.assertEqual(
            payload["details"]["attempts"][0]["request_id"],
            "req-claude-123",
        )
        self.assertIn("upstream Claude failed", payload["details"]["attempts"][0]["response_body"])
        self.assertNotIn("sk-secret", json.dumps(payload, ensure_ascii=False))
        self.assertEqual(len(reports), 2)

    def test_invalid_json_error_keeps_the_raw_claude_output(self) -> None:
        response = SimpleNamespace(
            choices=[
                SimpleNamespace(
                    message=SimpleNamespace(content="Claude returned plain text"),
                    finish_reason="stop",
                )
            ]
        )
        completions = SimpleNamespace(create=lambda **kwargs: response)
        fake_client = SimpleNamespace(
            chat=SimpleNamespace(completions=completions),
            base_url="https://user:pass@gateway.example/v1?token=secret",
        )
        model = OpenAIJsonModel(client=fake_client, model="claude", max_attempts=1)

        with self.assertRaises(RuntimeError) as raised:
            model.complete_json("system", "user", "A")

        issue = PipelineIssue.from_error("sample-json", "A", raised.exception)
        attempt = issue.details["attempts"][0]
        self.assertEqual(attempt["phase"], "A")
        self.assertEqual(attempt["model"], "claude")
        self.assertEqual(attempt["model_output"], "Claude returned plain text")
        self.assertEqual(attempt["base_url"], "https://gateway.example/v1")

    def test_schema_error_keeps_the_decoded_model_output(self) -> None:
        model = FakeModel()
        model.responses["B"] = {"data_flow_path": "partial response"}
        sample = PipelineInput(
            sample_id="sample-schema", func_before="before", func_after="after"
        )

        analysis = ThreeStagePipeline(model).analyze(sample)

        issue = next(item for item in analysis.issues if item.phase == "B")
        self.assertEqual(
            issue.details["model_output"], {"data_flow_path": "partial response"}
        )


class InputLoadingTests(unittest.TestCase):
    def test_module_entrypoint_does_not_run_when_imported_by_spawned_process(self) -> None:
        with patch("three_stage_pipeline.cli.main") as main_mock:
            runpy.run_module("three_stage_pipeline.__main__", run_name="spawn_import")

        main_mock.assert_not_called()

    def test_cli_parallel_mode_persists_worker_results_in_input_order(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            samples = [
                PipelineInput(sample_id="one", func_before="before", func_after="after"),
                PipelineInput(sample_id="two", func_before="before", func_after="after"),
            ]
            analyses = [
                ThreeStagePipeline(FailFirstPhaseAModel()).analyze(samples[0]),
                ThreeStagePipeline(FakeModel()).analyze(samples[1]),
            ]
            executor = MagicMock()
            executor.submit.side_effect = [
                SimpleNamespace(result=lambda analysis=analysis: analysis)
                for analysis in analyses
            ]
            executor_context = MagicMock()
            executor_context.__enter__.return_value = executor
            executor_context.__exit__.return_value = False
            output_dir = Path(directory) / "output"

            with (
                patch("three_stage_pipeline.cli.load_inputs", return_value=samples),
                patch(
                    "three_stage_pipeline.cli.ProcessPoolExecutor",
                    return_value=executor_context,
                ) as executor_class,
                patch("three_stage_pipeline.cli.OpenAIJsonModel.from_env") as model_factory,
                patch("builtins.print"),
            ):
                exit_code = cli_main(
                    ["input.csv", "--workers", "2", "--output-dir", str(output_dir)]
                )

            self.assertEqual(exit_code, 0)
            executor_class.assert_called_once()
            self.assertEqual(executor.submit.call_count, 2)
            model_factory.assert_not_called()
            with (output_dir / "final_results.csv").open(
                "r", encoding="utf-8-sig", newline=""
            ) as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual([row["sample_id"] for row in rows], ["one", "two"])
            log_entries = [
                json.loads(line)
                for line in (output_dir / "pipeline_errors.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
                if line.strip()
            ]
            self.assertEqual(
                [(entry["sample_id"], entry["phase"]) for entry in log_entries],
                [("one", "A")],
            )

    def test_cli_parallel_mode_handles_an_empty_input_range(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_dir = Path(directory) / "output"
            with (
                patch("three_stage_pipeline.cli.load_inputs", return_value=[]),
                patch("three_stage_pipeline.cli.ProcessPoolExecutor") as executor_class,
                patch("three_stage_pipeline.cli.OpenAIJsonModel.from_env") as model_factory,
                patch("builtins.print"),
            ):
                exit_code = cli_main(
                    ["input.csv", "--workers", "4", "--output-dir", str(output_dir)]
                )

            self.assertEqual(exit_code, 0)
            executor_class.assert_not_called()
            model_factory.assert_not_called()
            self.assertEqual(
                (output_dir / "pipeline_errors.jsonl").read_text(encoding="utf-8"),
                "",
            )

    def test_cli_finishes_all_samples_and_writes_problem_log(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            samples = [
                PipelineInput(sample_id="bad", func_before="before", func_after="after"),
                PipelineInput(sample_id="good", func_before="before", func_after="after"),
            ]
            model = FailFirstPhaseAModel()
            output_dir = Path(directory) / "output"

            with (
                patch("three_stage_pipeline.cli.load_inputs", return_value=samples),
                patch(
                    "three_stage_pipeline.cli.OpenAIJsonModel.from_env",
                    return_value=model,
                ),
                patch("builtins.print") as print_mock,
            ):
                exit_code = cli_main(["input.csv", "--output-dir", str(output_dir)])

            self.assertEqual(exit_code, 0)
            with (output_dir / "final_results.csv").open(
                "r", encoding="utf-8-sig", newline=""
            ) as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual({row["sample_id"] for row in rows}, {"bad", "good"})
            log_entries = [
                json.loads(line)
                for line in (output_dir / "pipeline_errors.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
                if line.strip()
            ]
            self.assertEqual([(item["sample_id"], item["phase"]) for item in log_entries], [("bad", "A")])
            printed = "\n".join(str(call.args[0]) for call in print_mock.call_args_list)
            self.assertIn("WARNING", printed)
            self.assertIn("pipeline_errors.jsonl", printed)

    def test_cli_defaults_to_input_directory_and_first_sample(self) -> None:
        args = build_parser().parse_args([])

        self.assertEqual(args.input, Path("input"))
        self.assertEqual(args.start, 1)
        self.assertEqual(args.end, 1)
        self.assertEqual(args.workers, 1)

    def test_cli_rejects_non_positive_worker_count(self) -> None:
        with self.assertRaises(SystemExit):
            build_parser().parse_args(["--workers", "0"])

    def test_directory_prefers_anonymized_csv_and_maps_requested_range(self) -> None:
        import pandas as pd

        rows = pd.DataFrame(
            [
                {
                    "sample_id": "sample_1",
                    "commit_id": "commit_1",
                    "project": "demo",
                    "cwe": "CWE-125",
                    "func_before": "before 1",
                    "func_after": "after 1",
                    "commit_msg": "original 1",
                    "commit_msg_anonymized": "anonymous 1",
                },
                {
                    "sample_id": "sample_2",
                    "commit_id": "commit_2",
                    "project": "demo",
                    "cwe": "CWE-787",
                    "func_before": "before 2",
                    "func_after": "after 2",
                    "commit_msg": "original 2",
                    "commit_msg_anonymized": "anonymous 2",
                },
            ]
        )
        with tempfile.TemporaryDirectory() as directory:
            input_dir = Path(directory)
            anonymized_csv = input_dir / "diversevul_paired_anonymized.csv"
            anonymized_csv.write_text("placeholder", encoding="utf-8")
            anonymized = input_dir / "diversevul_paired_anonymized.parquet"
            anonymized.write_bytes(b"placeholder")
            (input_dir / "diversevul_paired.parquet").write_bytes(b"placeholder")

            with patch("pandas.read_csv", return_value=rows.iloc[1:2]) as read_csv:
                samples = load_inputs(input_dir, start=2, end=2)

            self.assertEqual(read_csv.call_args.args[0], anonymized_csv)
            self.assertEqual(read_csv.call_args.kwargs["nrows"], 1)
            self.assertEqual(
                samples,
                [
                    PipelineInput(
                        sample_id="sample_2",
                        commit_id="commit_2",
                        project="demo",
                        cwe="CWE-787",
                        func_before="before 2",
                        func_after="after 2",
                        commit_msg="anonymous 2",
                    )
                ],
            )

    def test_direct_csv_uses_anonymized_text_fallbacks(self) -> None:
        import pandas as pd

        rows = pd.DataFrame(
            [
                {
                    "sample_id": "sample_1",
                    "func_before": "before",
                    "func_after": "after",
                    "commit_msg": "original",
                    "commit_msg_anonymized": "anonymous",
                    "bug_description": "original description",
                    "bug_description_anonymized": "anonymous description",
                }
            ]
        )
        with tempfile.TemporaryDirectory() as directory:
            csv_path = Path(directory) / "diversevul_paired_anonymized.csv"
            csv_path.write_text("placeholder", encoding="utf-8")

            with patch("pandas.read_csv", return_value=rows):
                samples = load_inputs(csv_path, start=1, end=1)

            self.assertEqual(samples[0].commit_msg, "anonymous")
            self.assertEqual(samples[0].bug_description, "anonymous description")

    def test_rejects_invalid_sample_range(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.json"
            path.write_text(
                json.dumps(
                    {
                        "sample_id": "one",
                        "func_before": "before",
                        "func_after": "after",
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "start"):
                load_inputs(path, start=0, end=1)

    def test_loads_json_array_and_jsonl(self) -> None:
        sample = {
            "sample_id": "one",
            "func_before": "before",
            "func_after": "after",
        }
        with tempfile.TemporaryDirectory() as directory:
            json_path = Path(directory) / "samples.json"
            json_path.write_text(json.dumps([sample]), encoding="utf-8")
            jsonl_path = Path(directory) / "samples.jsonl"
            jsonl_path.write_text(json.dumps(sample) + "\n", encoding="utf-8")

            self.assertEqual(load_inputs(json_path), [PipelineInput(**sample)])
            self.assertEqual(load_inputs(jsonl_path), [PipelineInput(**sample)])

    def test_rejects_unknown_input_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.json"
            path.write_text(
                json.dumps(
                    {
                        "sample_id": "one",
                        "func_before": "before",
                        "func_after": "after",
                        "unexpected": "value",
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "unknown fields"):
                load_inputs(path)

    def test_rejects_non_standard_nan_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.json"
            path.write_text(
                '{"sample_id":"one","func_before":"before",'
                '"func_after":"after","commit_id":NaN}',
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "invalid JSON constant"):
                load_inputs(path)


if __name__ == "__main__":
    unittest.main()
