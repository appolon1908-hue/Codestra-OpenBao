from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class SavedPlanWorkflowTests(unittest.TestCase):
    def test_saved_plan_apply_never_plans_or_deploys_a_container(self) -> None:
        source = (ROOT / "scripts/apply_saved_plan.sh").read_text(encoding="utf-8")
        self.assertIn("sha256sum -c", source)
        self.assertIn("scripts/preflight.sh", source)
        self.assertIn("scripts/backup.sh", source)
        self.assertIn("scripts/apply.sh", source)
        self.assertIn("scripts/verify.sh", source)
        self.assertNotIn("scripts/plan.sh", source)
        self.assertNotIn("docker compose up", source)

    def test_production_apply_proves_ssh_unchanged(self) -> None:
        source = (ROOT / "scripts/apply_saved_plan.sh").read_text(encoding="utf-8")
        self.assertGreaterEqual(source.count("scripts/capture_ssh_baseline.sh"), 2)
        self.assertIn("verify_ssh_unchanged.py", source)
        self.assertIn("SSH_CHANGED=NO", source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
