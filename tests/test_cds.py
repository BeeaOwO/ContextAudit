from __future__ import annotations

import csv
import tempfile
import unittest
from pathlib import Path

from three_stage_pipeline.cds import analyze_cds_csv


SCORE_COLUMNS = (
    "phase_c_variable_match_score",
    "phase_c_step_position_score",
    "phase_c_dataflow_path_score",
)


class CdsAnalysisTests(unittest.TestCase):
    def test_derives_cds_as_one_minus_composite_similarity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.csv"
            with source.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(
                    handle,
                    fieldnames=("sample_id", *SCORE_COLUMNS, "similarity", "cds_score"),
                )
                writer.writeheader()
                writer.writerow(
                    {
                        "sample_id": "sample-1",
                        SCORE_COLUMNS[0]: "0.2",
                        SCORE_COLUMNS[1]: "0.2",
                        SCORE_COLUMNS[2]: "0.2",
                        "similarity": "stale",
                        "cds_score": "stale",
                    }
                )

            summary = analyze_cds_csv(source)

            with summary.output_path.open(
                "r", encoding="utf-8-sig", newline=""
            ) as handle:
                row = next(csv.DictReader(handle))
            self.assertEqual(row["similarity"], "0.2")
            self.assertEqual(row["cds_score"], "0.8")
            self.assertEqual(row["cds_band"], "high")
            self.assertEqual(summary.mean, "0.8")

            with summary.distribution_path.open(
                "r", encoding="utf-8-sig", newline=""
            ) as handle:
                distribution = list(csv.DictReader(handle))
            self.assertEqual(distribution[7]["cds_range"], "(0.7, 0.8]")
            self.assertEqual(distribution[7]["count"], "1")

    def test_skips_pipeline_error_rows(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.csv"
            with source.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(
                    handle,
                    fieldnames=("sample_id", *SCORE_COLUMNS, "phase_c_raw"),
                )
                writer.writeheader()
                writer.writerow(
                    {
                        "sample_id": "valid",
                        SCORE_COLUMNS[0]: "1",
                        SCORE_COLUMNS[1]: "1",
                        SCORE_COLUMNS[2]: "1",
                        "phase_c_raw": '{"comment":"ok"}',
                    }
                )
                writer.writerow(
                    {
                        "sample_id": "failed",
                        SCORE_COLUMNS[0]: "0",
                        SCORE_COLUMNS[1]: "0",
                        SCORE_COLUMNS[2]: "0",
                        "phase_c_raw": '{"pipeline_placeholder":true}',
                    }
                )

            summary = analyze_cds_csv(source)

            self.assertEqual(summary.row_count, 1)
            self.assertEqual(summary.skipped_row_count, 1)
            with summary.output_path.open(
                "r", encoding="utf-8-sig", newline=""
            ) as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual([row["sample_id"] for row in rows], ["valid"])
            self.assertEqual(rows[0]["cds_score"], "0")
            self.assertEqual(rows[0]["cds_band"], "low")


if __name__ == "__main__":
    unittest.main()
