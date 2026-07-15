#!/usr/bin/env python3
"""Focused source-regression checks for runtime authorization wording."""

from __future__ import annotations

import unittest
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve()
SKILL_ROOT = SCRIPT_PATH.parents[1]
REPO_ROOT = SCRIPT_PATH.parents[3]
SKILL_MD = SKILL_ROOT / "SKILL.md"
RUNTIME_EXCEPTIONS = SKILL_ROOT / "authorizations" / "runtime-exceptions.md"
WAKEUP_PLAN = SKILL_ROOT / "scripts" / "codex_refactor_loop" / "wakeup_plan.py"
CONTROLLER_ACTIONS = SKILL_ROOT / "scripts" / "codex_refactor_loop" / "controller_actions.py"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


class AuthorizationSourceRegressionTests(unittest.TestCase):
    def test_current_pr_adoption_boundary_is_documented_without_new_authority(self) -> None:
        combined = "\n".join((read(SKILL_MD), read(RUNTIME_EXCEPTIONS)))
        for needle in (
            "existing canonical PR is never standalone completion authority",
            "only inside `publish_exact_head`",
            "`PUBLICATION_RECEIPT_FINALIZED`",
            "no public command bus",
            "no generic command fields",
            "no generic lifecycle actor",
        ):
            with self.subTest(needle=needle):
                self.assertIn(needle, combined)

    def test_current_pr_adoption_has_complete_transaction_surfaces(self) -> None:
        wakeup_plan = read(WAKEUP_PLAN)
        controller_actions = read(CONTROLLER_ACTIONS)
        for needle in (
            "_current_implementation_pr_proof",
            "IMPLEMENTATION_PR_HEAD_VISIBILITY_ATTEMPTS",
            "legacy_implementation_pr_evidence_missing_or_ambiguous",
        ):
            with self.subTest(planner=needle):
                self.assertIn(needle, wakeup_plan)
        for needle in (
            ".publish_exact_head(",
            "PublishExactHeadRequest(",
            "return self.dispatch_reviewers",
        ):
            with self.subTest(helper=needle):
                self.assertIn(needle, controller_actions)
        self.assertNotIn("_matching_current_implementation_pr", controller_actions)


if __name__ == "__main__":
    unittest.main()
