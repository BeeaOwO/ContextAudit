from __future__ import annotations

import unittest

from three_stage_pipeline.prompts import PROMPTS


class PromptContractTests(unittest.TestCase):
    def test_phase_c_uses_anchored_numeric_scores_and_caps(self) -> None:
        phase_c = PROMPTS["phase_c"]["system"]

        self.assertIn("仅允许 0、0.25、0.5、0.75、1", phase_c)
        self.assertIn("决定性实体", phase_c)
        self.assertIn("决定性操作", phase_c)
        self.assertIn("决定性步骤", phase_c)
        self.assertIn("同一实体但因果角色不完整或不明确", phase_c)
        self.assertIn("实体或因果角色不同", phase_c)
        self.assertIn("操作或分支不同", phase_c)
        self.assertIn("误判决定性步骤", phase_c)
        self.assertNotIn("0.6-0.9", phase_c)
        self.assertNotIn("0.7-0.9", phase_c)

    def test_all_phases_keep_the_existing_output_fields(self) -> None:
        phase_a = PROMPTS["phase_a"]["user"]
        phase_b = PROMPTS["phase_b"]["user"]
        phase_c = PROMPTS["phase_c"]["user"]

        for field in (
            "non_standard_external_calls",
            "data_flow_path",
            "vulnerability_node",
            "confidence",
            "additional_context_needed",
        ):
            self.assertIn(field, phase_a)
        for field in (
            "data_flow_path",
            "vulnerability_node",
            "cwe_type",
            "depends_on_caller",
            "caller_constraint",
        ):
            self.assertIn(field, phase_b)
        for field in (
            "variable_match_score",
            "step_position_score",
            "dataflow_path_score",
            "overall_consistency",
            "comment",
        ):
            self.assertIn(field, phase_c)

    def test_phase_c_json_example_separates_comment_from_score_fields(self) -> None:
        phase_c = PROMPTS["phase_c"]["user"]

        self.assertIn('评分理由",\n  "variable_match_score"', phase_c)

    def test_revised_prompts_do_not_exceed_the_original_lengths(self) -> None:
        original_total_lengths = {
            "phase_a": 1017,
            "phase_b": 1197,
            "phase_c": 1034,
        }

        for phase, maximum in original_total_lengths.items():
            prompt = PROMPTS[phase]
            self.assertLessEqual(len(prompt["system"]) + len(prompt["user"]), maximum)


if __name__ == "__main__":
    unittest.main()
