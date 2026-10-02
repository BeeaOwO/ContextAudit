import csv
import json
import tempfile
import unittest
from pathlib import Path

from three_stage_pipeline.results import (
    FINAL_CSV_COLUMNS,
    rebuild_final_csv_from_combined,
)


class RebuildFinalCsvTests(unittest.TestCase):
    def test_rebuilds_csv_from_sorted_combined_json_without_stale_rows(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            combined = root / "combined"
            combined.mkdir()
            output = root / "final.csv"
            output.write_text("sample_id\nstale\n", encoding="utf-8")

            second = _record("sample-2")
            second["phase_a_data_flow_path"] = "before\x00after"
            tenth = _record("sample-10")
            (combined / "commit_10.json").write_text(
                json.dumps(tenth, ensure_ascii=False), encoding="utf-8"
            )
            (combined / "commit_2.json").write_text(
                json.dumps(second, ensure_ascii=False), encoding="utf-8"
            )

            row_count = rebuild_final_csv_from_combined(combined, output)

            self.assertEqual(row_count, 2)
            with output.open("r", encoding="utf-8-sig", newline="") as handle:
                reader = csv.DictReader(handle)
                self.assertEqual(tuple(reader.fieldnames or ()), FINAL_CSV_COLUMNS)
                rows = list(reader)
            self.assertEqual(
                [row["sample_id"] for row in rows], ["sample-2", "sample-10"]
            )
            self.assertEqual(
                json.loads(rows[0]["phase_a_non_standard_external_calls"]),
                ["外部函数"],
            )
            self.assertEqual(rows[0]["phase_b_depends_on_caller"], "false")
            self.assertEqual(rows[0]["phase_a_data_flow_path"], r"before\0after")
            self.assertNotIn(b"\x00", output.read_bytes())

    def test_reports_the_invalid_combined_json_filename(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            combined = Path(directory) / "combined"
            combined.mkdir()
            (combined / "broken_1.json").write_text("[]", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "broken_1.json"):
                rebuild_final_csv_from_combined(combined, Path(directory) / "final.csv")

    def test_rejects_a_filename_without_a_trailing_sample_number(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            combined = Path(directory) / "combined"
            combined.mkdir()
            (combined / "sample.json").write_text(
                json.dumps(_record("sample")), encoding="utf-8"
            )

            with self.assertRaisesRegex(ValueError, "trailing sample number"):
                rebuild_final_csv_from_combined(combined, Path(directory) / "final.csv")


def _record(sample_id: str) -> dict:
    record = {column: f"{column}-{sample_id}" for column in FINAL_CSV_COLUMNS}
    record["sample_id"] = sample_id
    record["phase_a_non_standard_external_calls"] = ["外部函数"]
    record["phase_b_depends_on_caller"] = False
    record["phase_c_variable_match_score"] = 0.5
    record["phase_c_step_position_score"] = 0.75
    record["phase_c_dataflow_path_score"] = 1.0
    return record


if __name__ == "__main__":
    unittest.main()
