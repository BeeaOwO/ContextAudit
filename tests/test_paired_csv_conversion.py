from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from three_stage_pipeline.paired_csv import (
    convert_paired_csv,
    convert_primevul_jsonl,
    deduplicate_pipeline_csvs,
)
from three_stage_pipeline.reposvul import DIVERSEVUL_COLUMNS


class PairedCsvConversionTests(unittest.TestCase):
    def test_converts_titanvul_and_records_invalid_or_duplicate_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "TitanVul.csv"
            destination = root / "titanvul_paired.csv"
            errors = root / "titanvul_paired.skipped.jsonl"
            fieldnames = [
                "func_before",
                "func_after",
                "cve_id",
                "cwe_id",
                "cve_description",
                "commit_link",
                "commit_message",
                "file_name",
                "extension",
                "datetime",
            ]
            rows = [
                {
                    "func_before": "int f() { return 0; }",
                    "func_after": "int f() { return 1; }",
                    "cwe_id": "cwe-0190",
                    "commit_link": "https://github.com/acme/demo/commit/abcdef1234567890",
                    "commit_message": "fix overflow",
                },
                {
                    "func_before": "int f() { return 0; }",
                    "func_after": "int f() { return 1; }",
                    "cwe_id": "CWE-190",
                    "commit_link": "https://github.com/acme/demo/commit/abcdef1234567890",
                },
                {
                    "func_before": "same",
                    "func_after": "same",
                    "cwe_id": "CWE-20",
                },
                {"func_before": "", "func_after": "fixed"},
            ]
            with source.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows)

            stats = convert_paired_csv(
                source,
                destination,
                dataset="titanvul",
                error_path=errors,
            )

            self.assertEqual(stats.read, 4)
            self.assertEqual(stats.written, 1)
            self.assertEqual(stats.duplicates, 1)
            self.assertEqual(stats.unchanged, 1)
            self.assertEqual(stats.invalid, 1)
            with destination.open(encoding="utf-8-sig", newline="") as handle:
                output_rows = list(csv.DictReader(handle))
            self.assertEqual(list(output_rows[0]), list(DIVERSEVUL_COLUMNS))
            self.assertEqual(output_rows[0]["sample_id"], "abcdef12_1")
            self.assertEqual(output_rows[0]["commit_id"], "abcdef1234567890")
            self.assertEqual(output_rows[0]["project"], "acme/demo")
            self.assertEqual(json.loads(output_rows[0]["cwe"]), ["CWE-190"])
            self.assertIn("-int f() { return 0; }", output_rows[0]["diff"])
            self.assertIn("+int f() { return 1; }", output_rows[0]["diff"])
            self.assertEqual(int(output_rows[0]["diff_length"]), len(output_rows[0]["diff"]))
            error_rows = [json.loads(line) for line in errors.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(
                [row["reason"] for row in error_rows],
                ["duplicate_pair", "unchanged_pair", "missing_function"],
            )

    def test_maps_benchvul_and_vulnerability_score_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            cases = [
                (
                    "benchvul",
                    {
                        "func_before": "def f():\n    return 0",
                        "func_after": "def f():\n    return 1",
                        "cwe_id": "CWE-79",
                        "commit_link": "https://bitbucket.org/team/repo/commits/1234567890abcdef",
                        "commit_msg": "escape output",
                        "repo_name": "team/repo",
                    },
                    "team/repo",
                    "1234567890abcdef",
                ),
                (
                    "vulnerability_score",
                    {
                        "func_before": "void f() {}",
                        "func_after": "void f() { safe(); }",
                        "cwe_id": "['CWE-787', 'CWE-20']",
                        "commit_url": "https://gitlab.com/team/repo/-/commit/fedcba9876543210",
                        "commit_msg": "bounds check",
                    },
                    "team/repo",
                    "fedcba9876543210",
                ),
            ]
            for dataset, row, expected_project, expected_commit in cases:
                source = root / f"{dataset}.csv"
                destination = root / f"{dataset}_paired.csv"
                with source.open("w", encoding="utf-8", newline="") as handle:
                    writer = csv.DictWriter(handle, fieldnames=list(row))
                    writer.writeheader()
                    writer.writerow(row)
                stats = convert_paired_csv(source, destination, dataset=dataset)
                self.assertEqual(stats.written, 1)
                with destination.open(encoding="utf-8-sig", newline="") as handle:
                    converted = next(csv.DictReader(handle))
                self.assertEqual(converted["project"], expected_project)
                self.assertEqual(converted["commit_id"], expected_commit)

    def test_converts_primevul_adjacent_pairs_and_skips_metadata_mismatches(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "primevul_train_paired.jsonl"
            destination = root / "primevul_paired.csv"
            records = [
                {
                    "idx": 1,
                    "target": 1,
                    "func": "int f() { return 0; }",
                    "commit_id": "abcdef1234567890",
                    "commit_message": "fix",
                    "project": "acme/demo",
                    "cve": "CVE-1",
                    "cwe": ["CWE-190"],
                },
                {
                    "idx": 2,
                    "target": 0,
                    "func": "int f() { return 1; }",
                    "commit_id": "abcdef1234567890",
                    "project": "acme/demo",
                    "cve": "CVE-1",
                },
                {
                    "idx": 3,
                    "target": 1,
                    "func": "bad before",
                    "commit_id": "1111111",
                    "cve": "CVE-2",
                },
                {
                    "idx": 4,
                    "target": 0,
                    "func": "bad after",
                    "commit_id": "2222222",
                    "cve": "CVE-3",
                },
            ]
            source.write_text(
                "".join(json.dumps(record) + "\n" for record in records),
                encoding="utf-8",
            )

            stats = convert_primevul_jsonl([source], destination)

            self.assertEqual(stats.read_pairs, 2)
            self.assertEqual(stats.written, 1)
            self.assertEqual(stats.metadata_mismatches, 1)
            with destination.open(encoding="utf-8-sig", newline="") as handle:
                row = next(csv.DictReader(handle))
            self.assertEqual(row["sample_id"], "abcdef12_1")
            self.assertEqual(row["project"], "acme/demo")
            self.assertEqual(json.loads(row["cwe"]), ["CWE-190"])

    def test_cross_dataset_deduplication_merges_metadata_into_first_owner(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            first = root / "first.csv"
            second = root / "second.csv"
            first_out = root / "first_dedup.csv"
            second_out = root / "second_dedup.csv"
            common = {
                "sample_id": "first_1",
                "commit_id": "",
                "commit_short": "",
                "project": "",
                "func_before": "int f() { return 0; }",
                "func_after": "int f() { return 1; }",
                "diff": "diff",
                "diff_length": "4",
                "commit_msg": "",
                "cwe": "[]",
                "commit_msg_anonymized": "",
            }
            with first.open("w", encoding="utf-8-sig", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=DIVERSEVUL_COLUMNS)
                writer.writeheader()
                writer.writerow(common)
            enriched = dict(common)
            enriched.update(
                {
                    "sample_id": "second_1",
                    "commit_id": "abcdef123456",
                    "commit_short": "abcdef12",
                    "project": "acme/demo",
                    "commit_msg": "fix",
                    "cwe": '["CWE-190"]',
                }
            )
            unique = dict(enriched)
            unique.update(
                {
                    "sample_id": "second_2",
                    "func_before": "int g() { return 0; }",
                    "func_after": "int g() { return 1; }",
                    "cwe": '["CWE-20"]',
                }
            )
            with second.open("w", encoding="utf-8-sig", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=DIVERSEVUL_COLUMNS)
                writer.writeheader()
                writer.writerows([enriched, unique])

            stats = deduplicate_pipeline_csvs(
                [("first", first, first_out), ("second", second, second_out)]
            )

            self.assertEqual(stats["first"].written, 1)
            self.assertEqual(stats["second"].written, 1)
            self.assertEqual(stats["second"].cross_dataset_duplicates, 1)
            with first_out.open(encoding="utf-8-sig", newline="") as handle:
                retained = next(csv.DictReader(handle))
            self.assertEqual(retained["commit_id"], "abcdef123456")
            self.assertEqual(retained["project"], "acme/demo")
            self.assertEqual(json.loads(retained["cwe"]), ["CWE-190"])


if __name__ == "__main__":
    unittest.main()
