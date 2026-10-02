from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path

from three_stage_pipeline.reposvul import (
    DIVERSEVUL_COLUMNS,
    convert_reposvul_jsonl,
    find_matching_function,
    merge_reposvul_jsonl,
)


BEFORE_FUNCTION = """static int parse_size(const char *text)
{
    return atoi(text);
}
"""

AFTER_FUNCTION = """static int parse_size(const char *text)
{
    if (text == NULL)
        return -1;
    return atoi(text);
}
"""


class ReposVulConversionTests(unittest.TestCase):
    def test_merge_reposvul_jsonl_preserves_source_order_and_repairs_newlines(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            train = root / "train.jsonl"
            valid = root / "valid.jsonl"
            test = root / "test.jsonl"
            merged = root / "ReposVul.jsonl"
            train.write_bytes(b'{"split":"train"}\n')
            valid.write_bytes(b'{"split":"valid"}')
            test.write_bytes(b'{"split":"test"}\n')

            stats = merge_reposvul_jsonl([train, valid, test], merged)

            self.assertEqual(
                merged.read_bytes(),
                b'{"split":"train"}\n{"split":"valid"}\n{"split":"test"}\n',
            )
            self.assertEqual(stats.sources, 3)
            self.assertEqual(stats.records, 3)

    def test_find_matching_function_extracts_the_same_function_from_parent_file(self) -> None:
        parent_file = """static void unrelated(void)
{
}

static int parse_size(const char *text)
{
    return atoi(text);
}
"""

        result = find_matching_function(parent_file, AFTER_FUNCTION)

        self.assertEqual(result, BEFORE_FUNCTION.rstrip())

    def test_flattened_reposvul_record_is_written_in_diversevul_format(self) -> None:
        record = {
            "function_id": "abcdef1234567890_7",
            "function": BEFORE_FUNCTION,
            "target": 1,
            "commit_id": "abcdef1234567890",
            "commit_message": "validate the input length",
            "project": "owner/project",
            "file_name": "src/parser.c",
            "cwe_id": ["CWE-20"],
            "parents": [{"commit_id_before": "parent123"}],
            "outdated": 0,
        }
        fixed_url = (
            "https://raw.githubusercontent.com/owner/project/"
            "abcdef1234567890/src/parser.c"
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "reposvul.jsonl"
            output = root / "paired.csv"
            errors = root / "skipped.jsonl"
            source.write_text(json.dumps(record) + "\n", encoding="utf-8")

            stats = convert_reposvul_jsonl(
                source,
                output,
                error_path=errors,
                fetch_text=lambda url, timeout: (
                    AFTER_FUNCTION if url == fixed_url else self.fail(url)
                ),
                workers=2,
            )

            with output.open("r", encoding="utf-8-sig", newline="") as handle:
                reader = csv.DictReader(handle)
                rows = list(reader)
            raw_output = output.read_bytes()

        self.assertEqual(reader.fieldnames, list(DIVERSEVUL_COLUMNS))
        self.assertEqual(stats.written, 1)
        self.assertEqual(stats.skipped, 0)
        self.assertEqual(rows[0]["sample_id"], "abcdef12_7")
        self.assertEqual(rows[0]["func_before"], BEFORE_FUNCTION.rstrip())
        self.assertEqual(rows[0]["func_after"], AFTER_FUNCTION.rstrip())
        self.assertEqual(rows[0]["cwe"], "['CWE-20']")
        self.assertEqual(int(rows[0]["diff_length"]), len(rows[0]["diff"]))
        self.assertEqual(rows[0]["commit_msg_anonymized"], "")
        self.assertFalse(raw_output.startswith(b"\xef\xbb\xbf"))

    def test_oversized_csv_fields_are_skipped(self) -> None:
        record = {
            "function_id": "abcdef1234567890_7",
            "function": BEFORE_FUNCTION,
            "target": 1,
            "commit_id": "abcdef1234567890",
            "commit_message": "message",
            "project": "owner/project",
            "file_name": "src/parser.c",
            "cwe_id": ["CWE-20"],
            "outdated": 0,
        }
        oversized_after = AFTER_FUNCTION.replace(
            "return atoi(text);", 'return atoi(text);\n    /* ' + ("x" * 140_000) + " */"
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "reposvul.jsonl"
            output = root / "paired.csv"
            errors = root / "skipped.jsonl"
            source.write_text(json.dumps(record) + "\n", encoding="utf-8")

            stats = convert_reposvul_jsonl(
                source,
                output,
                error_path=errors,
                fetch_text=lambda url, timeout: oversized_after,
            )
            with output.open("r", encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))
            logged = [json.loads(line) for line in errors.read_text().splitlines()]

        self.assertEqual(stats.written, 0)
        self.assertEqual(stats.skipped, 1)
        self.assertEqual(rows, [])
        self.assertEqual(logged[0]["reason"], "oversized_csv_field")

    def test_non_vulnerable_outdated_and_unchanged_records_are_logged(self) -> None:
        base = {
            "function": BEFORE_FUNCTION,
            "commit_id": "abcdef1234567890",
            "project": "owner/project",
            "file_name": "src/parser.c",
            "cwe_id": ["CWE-20"],
            "parents": [{"commit_id_before": "parent123"}],
            "commit_message": "message",
            "outdated": 0,
        }
        records = [
            {**base, "function_id": "abcdef1234567890_1", "target": 0},
            {
                **base,
                "function_id": "abcdef1234567890_2",
                "target": 1,
                "outdated": 1,
            },
            {**base, "function_id": "abcdef1234567890_3", "target": 1},
        ]

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "reposvul.jsonl"
            output = root / "paired.csv"
            errors = root / "skipped.jsonl"
            source.write_text(
                "".join(json.dumps(item) + "\n" for item in records),
                encoding="utf-8",
            )

            stats = convert_reposvul_jsonl(
                source,
                output,
                error_path=errors,
                fetch_text=lambda url, timeout: BEFORE_FUNCTION,
            )
            logged = [
                json.loads(line)
                for line in errors.read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual(stats.read, 3)
        self.assertEqual(stats.candidates, 1)
        self.assertEqual(stats.written, 0)
        self.assertEqual(stats.skipped, 2)
        self.assertEqual([item["reason"] for item in logged], ["outdated", "unchanged"])

    def test_invalid_json_is_logged_without_stopping_later_records(self) -> None:
        valid = {
            "function_id": "abcdef1234567890_7",
            "function": BEFORE_FUNCTION,
            "target": 1,
            "commit_id": "abcdef1234567890",
            "commit_message": "message",
            "project": "owner/project",
            "file_name": "src/parser.c",
            "cwe_id": ["CWE-20"],
            "parents": [{"commit_id_before": "parent123"}],
            "outdated": 0,
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "reposvul.jsonl"
            output = root / "paired.csv"
            errors = root / "skipped.jsonl"
            source.write_text("{broken json\n" + json.dumps(valid) + "\n", encoding="utf-8")

            stats = convert_reposvul_jsonl(
                source,
                output,
                error_path=errors,
                fetch_text=lambda url, timeout: AFTER_FUNCTION,
            )
            logged = [
                json.loads(line)
                for line in errors.read_text(encoding="utf-8").splitlines()
            ]

        self.assertEqual(stats.read, 2)
        self.assertEqual(stats.written, 1)
        self.assertEqual(stats.skipped, 1)
        self.assertEqual(logged[0]["reason"], "JSONDecodeError")

    def test_duplicate_function_records_are_combined_and_cwe_values_are_unioned(self) -> None:
        first = {
            "function_id": "abcdef1234567890_7",
            "function": BEFORE_FUNCTION,
            "target": 1,
            "commit_id": "abcdef1234567890",
            "commit_message": "validate the input length",
            "project": "owner/project",
            "file_name": "src/parser.c",
            "cwe_id": ["CWE-20"],
            "cve_id": "CVE-1",
            "outdated": 0,
        }
        second = {
            **first,
            "cwe_id": ["CWE-20", "CWE-125"],
            "cve_id": "CVE-2",
        }

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "reposvul.jsonl"
            output = root / "paired.csv"
            errors = root / "skipped.jsonl"
            source.write_text(
                json.dumps(first) + "\n" + json.dumps(second) + "\n",
                encoding="utf-8",
            )

            stats = convert_reposvul_jsonl(
                source,
                output,
                error_path=errors,
                fetch_text=lambda url, timeout: AFTER_FUNCTION,
            )
            with output.open("r", encoding="utf-8-sig", newline="") as handle:
                rows = list(csv.DictReader(handle))

        self.assertEqual(stats.read, 2)
        self.assertEqual(stats.candidates, 1)
        self.assertEqual(stats.duplicates, 1)
        self.assertEqual(stats.written, 1)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["cwe"], "['CWE-20', 'CWE-125']")


if __name__ == "__main__":
    unittest.main()
