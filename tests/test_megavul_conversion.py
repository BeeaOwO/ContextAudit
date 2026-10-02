from __future__ import annotations

import csv
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from three_stage_pipeline.megavul import convert_megavul_json
from three_stage_pipeline.reposvul import DIVERSEVUL_COLUMNS


class MegaVulConversionTests(unittest.TestCase):
    def test_streams_the_top_level_array_without_json_load(self) -> None:
        record = {
            "commit_hash": "abcdef1234567890",
            "repo_name": "owner/project",
            "func_before": "void f() {}",
            "func": "void f() { return; }",
            "diff_func": "-void f() {}\n+void f() { return; }",
            "is_vul": True,
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "megavul.json"
            destination = root / "megavul.csv"
            source.write_text(json.dumps([record]), encoding="utf-8")

            with patch(
                "three_stage_pipeline.megavul.json.load",
                side_effect=AssertionError("json.load must not be used"),
            ):
                stats = convert_megavul_json(source, destination)

        self.assertEqual(stats.read, 1)
        self.assertEqual(stats.written, 1)

    def test_writes_only_vulnerable_pairs_within_all_length_limits(self) -> None:
        accepted = {
            "cve_id": "CVE-2024-0001",
            "cwe_ids": ["CWE-20"],
            "repo_name": "owner/project",
            "commit_hash": "abcdef1234567890",
            "commit_msg": "validate input",
            "func_before": "void f() {\n  bad();\n}\n",
            "func": "void f() {\n  good();\n}\n",
            "diff_func": "@@ -1 +1 @@\n-bad();\n+good();\n",
            "is_vul": True,
        }
        diff_limit = len(accepted["diff_func"])
        too_long_diff = {
            **accepted,
            "commit_hash": "11111111",
            "diff_func": "x" * (diff_limit + 1),
        }
        not_vulnerable = {**accepted, "commit_hash": "22222222", "is_vul": False}

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "megavul.json"
            destination = root / "megavul.csv"
            source.write_text(
                json.dumps([accepted, too_long_diff, not_vulnerable]), encoding="utf-8"
            )

            stats = convert_megavul_json(
                source,
                destination,
                max_diff_chars=diff_limit,
                max_function_chars=100,
                max_function_lines=10,
            )

            with destination.open(encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))

        self.assertEqual(stats.read, 3)
        self.assertEqual(stats.candidates, 2)
        self.assertEqual(stats.written, 1)
        self.assertEqual(stats.filtered, 1)
        self.assertEqual(tuple(rows[0]), DIVERSEVUL_COLUMNS)
        self.assertEqual(rows[0]["sample_id"], "abcdef12_0")
        self.assertEqual(rows[0]["func_after"], accepted["func"])
        self.assertEqual(rows[0]["diff_length"], str(len(accepted["diff_func"])))
        self.assertEqual(json.loads(rows[0]["cwe"]), ["CWE-20"])

    def test_applies_function_limits_to_both_before_and_after(self) -> None:
        base = {
            "cwe_ids": [],
            "repo_name": "project",
            "commit_msg": "fix",
            "diff_func": "short",
            "is_vul": True,
        }
        records = [
            {**base, "commit_hash": "a" * 40, "func_before": "x" * 6, "func": "ok"},
            {**base, "commit_hash": "b" * 40, "func_before": "ok", "func": "x" * 6},
            {**base, "commit_hash": "c" * 40, "func_before": "a\nb\nc", "func": "ok"},
            {**base, "commit_hash": "d" * 40, "func_before": "ok", "func": "a\nb\nc"},
        ]

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "megavul.json"
            destination = root / "megavul.csv"
            source.write_text(json.dumps(records), encoding="utf-8")

            stats = convert_megavul_json(
                source,
                destination,
                max_diff_chars=10,
                max_function_chars=5,
                max_function_lines=2,
            )

        self.assertEqual(stats.written, 0)
        self.assertEqual(stats.filtered, 4)


if __name__ == "__main__":
    unittest.main()
