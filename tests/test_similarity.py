import csv
import tempfile
import unittest
from pathlib import Path

from three_stage_pipeline.similarity import analyze_similarity_csv


SCORE_COLUMNS = (
    "phase_c_variable_match_score",
    "phase_c_step_position_score",
    "phase_c_dataflow_path_score",
)


class SimilarityAnalysisTests(unittest.TestCase):
    def test_skips_pipeline_placeholders_and_invalid_score_rows(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.csv"
            fieldnames = (
                "sample_id",
                *SCORE_COLUMNS,
                "phase_a_raw",
                "phase_b_raw",
                "phase_c_raw",
            )
            valid_raw = '{"pipeline_placeholder":false}'
            error_raw = '{"pipeline_placeholder":true,"pipeline_error":"failed"}'
            with source.open("w", encoding="utf-8-sig", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(
                    [
                        {
                            "sample_id": "valid-zero",
                            SCORE_COLUMNS[0]: "0",
                            SCORE_COLUMNS[1]: "0",
                            SCORE_COLUMNS[2]: "0",
                            "phase_a_raw": valid_raw,
                            "phase_b_raw": valid_raw,
                            "phase_c_raw": valid_raw,
                        },
                        {
                            "sample_id": "placeholder",
                            SCORE_COLUMNS[0]: "0",
                            SCORE_COLUMNS[1]: "0",
                            SCORE_COLUMNS[2]: "0",
                            "phase_a_raw": valid_raw,
                            "phase_b_raw": error_raw,
                            "phase_c_raw": valid_raw,
                        },
                        {
                            "sample_id": "invalid-score",
                            SCORE_COLUMNS[0]: "0.5",
                            SCORE_COLUMNS[1]: "not-a-number",
                            SCORE_COLUMNS[2]: "0.5",
                            "phase_a_raw": valid_raw,
                            "phase_b_raw": valid_raw,
                            "phase_c_raw": valid_raw,
                        },
                    ]
                )

            summary = analyze_similarity_csv(source)

            self.assertEqual(summary.row_count, 1)
            self.assertEqual(summary.skipped_row_count, 2)
            with summary.output_path.open(
                "r", encoding="utf-8-sig", newline=""
            ) as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual([row["sample_id"] for row in rows], ["valid-zero"])
            self.assertEqual(rows[0]["similarity"], "0")

    def test_auto_detects_gb18030_input_and_writes_utf8_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "gb18030.csv"
            source.write_text(
                "sample_id,phase_c_variable_match_score,"
                "phase_c_step_position_score,phase_c_dataflow_path_score,comment\n"
                "中文样本,0.5,0.75,0.75,部分一致\n",
                encoding="gb18030",
            )

            summary = analyze_similarity_csv(source)

            self.assertEqual(summary.input_encoding, "gb18030")
            with summary.output_path.open(
                "r", encoding="utf-8-sig", newline=""
            ) as handle:
                row = next(csv.DictReader(handle))
            self.assertEqual(row["sample_id"], "中文样本")
            self.assertEqual(row["comment"], "部分一致")
            self.assertEqual(row["similarity"], "0.583333")

    def test_calculates_similarity_and_groups_distribution_by_point_one(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.csv"
            enriched = root / "enriched.csv"
            distribution = root / "distribution.csv"
            with source.open("w", encoding="utf-8-sig", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=("sample_id", *SCORE_COLUMNS))
                writer.writeheader()
                writer.writerows(
                    [
                        {
                            "sample_id": "one",
                            SCORE_COLUMNS[0]: "0.3",
                            SCORE_COLUMNS[1]: "0.4",
                            SCORE_COLUMNS[2]: "0.5",
                        },
                        {
                            "sample_id": "two",
                            SCORE_COLUMNS[0]: "0.2",
                            SCORE_COLUMNS[1]: "0.4",
                            SCORE_COLUMNS[2]: "0.6",
                        },
                        {
                            "sample_id": "three",
                            SCORE_COLUMNS[0]: "0.9",
                            SCORE_COLUMNS[1]: "0.8",
                            SCORE_COLUMNS[2]: "0.7",
                        },
                    ]
                )

            summary = analyze_similarity_csv(source, enriched, distribution)

            with enriched.open("r", encoding="utf-8-sig", newline="") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(
                [row["similarity"] for row in rows], ["0.35", "0.3", "0.75"]
            )
            with distribution.open("r", encoding="utf-8-sig", newline="") as handle:
                frequencies = list(csv.DictReader(handle))
            self.assertEqual(len(frequencies), 10)
            self.assertEqual(
                frequencies[2],
                {
                    "similarity_range": "(0.2, 0.3]",
                    "count": "1",
                    "percentage": "33.333333",
                },
            )
            self.assertEqual(
                frequencies[3],
                {
                    "similarity_range": "(0.3, 0.4]",
                    "count": "1",
                    "percentage": "33.333333",
                },
            )
            self.assertEqual(
                frequencies[7],
                {
                    "similarity_range": "(0.7, 0.8]",
                    "count": "1",
                    "percentage": "33.333333",
                },
            )
            self.assertEqual(frequencies[0]["similarity_range"], "[0.0, 0.1]")
            self.assertEqual(frequencies[9]["similarity_range"], "(0.9, 1.0]")
            self.assertEqual(summary.row_count, 3)
            self.assertEqual(summary.mean, "0.466667")
            self.assertEqual(summary.median, "0.35")
            self.assertEqual(summary.minimum, "0.3")
            self.assertEqual(summary.maximum, "0.75")

    def test_replaces_existing_similarity_column(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input.csv"
            with source.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(
                    handle, fieldnames=("sample_id", *SCORE_COLUMNS, "similarity")
                )
                writer.writeheader()
                writer.writerow(
                    {
                        "sample_id": "one",
                        SCORE_COLUMNS[0]: "0.12",
                        SCORE_COLUMNS[1]: "0.34",
                        SCORE_COLUMNS[2]: "0.56",
                        "similarity": "stale",
                    }
                )

            summary = analyze_similarity_csv(source)

            with summary.output_path.open("r", encoding="utf-8-sig", newline="") as handle:
                row = next(csv.DictReader(handle))
            self.assertEqual(row["similarity"], "0.23")
            self.assertTrue(summary.distribution_path.exists())

    def test_rejects_missing_columns_or_a_file_with_no_valid_scores(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            missing = root / "missing.csv"
            missing.write_text("sample_id,phase_c_variable_match_score\none,0.1\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "missing required columns"):
                analyze_similarity_csv(missing)

            invalid = root / "invalid.csv"
            with invalid.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=("sample_id", *SCORE_COLUMNS))
                writer.writeheader()
                writer.writerow(
                    {
                        "sample_id": "bad",
                        SCORE_COLUMNS[0]: "0.1",
                        SCORE_COLUMNS[1]: "not-a-number",
                        SCORE_COLUMNS[2]: "0.3",
                    }
                )

            with self.assertRaisesRegex(ValueError, "no valid data rows; skipped 1"):
                analyze_similarity_csv(invalid)


if __name__ == "__main__":
    unittest.main()
