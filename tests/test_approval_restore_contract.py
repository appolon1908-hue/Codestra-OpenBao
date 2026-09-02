from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APPROVAL = (ROOT / "scripts/verify_environment_approval.sh").read_text(encoding="utf-8")
RESTORE = (ROOT / "scripts/restore-test.sh").read_text(encoding="utf-8")
WORKFLOW = (ROOT / ".github/workflows/backup-restore-test.yml").read_text(encoding="utf-8")


class ApprovalAndRestoreContractTests(unittest.TestCase):
    def test_environment_approval_iterates_top_level_response_entries(self) -> None:
        self.assertIn('type == "array"', APPROVAL)
        self.assertIn("any(.[];", APPROVAL)
        self.assertNotIn("any(.;", APPROVAL)
        self.assertIn("any(.environments[]?; .name == $environment)", APPROVAL)

    def test_restore_switches_to_credential_from_restored_snapshot(self) -> None:
        restore_operation = RESTORE.index("bao operator raft snapshot restore -force")
        unset_target_token = RESTORE.index("unset BAO_TOKEN", restore_operation)
        read_restored_token = RESTORE.index(
            'restored_probe_token="$(< "$restored_probe_token_file")"',
            unset_target_token,
        )
        export_restored_token = RESTORE.index(
            'export BAO_TOKEN="$restored_probe_token"',
            read_restored_token,
        )
        probe = RESTORE.index("verify_secret_hash.py", export_restored_token)
        unset_restored_token = RESTORE.index(
            "unset BAO_TOKEN restored_probe_token",
            probe,
        )

        self.assertLess(restore_operation, unset_target_token)
        self.assertLess(unset_target_token, read_restored_token)
        self.assertLess(read_restored_token, export_restored_token)
        self.assertLess(export_restored_token, probe)
        self.assertLess(probe, unset_restored_token)
        self.assertIn("OPENBAO_RESTORED_PROBE_TOKEN_FILE", RESTORE)
        self.assertIn("400|600", RESTORE)
        self.assertIn('[[ -f "$restored_probe_token_file" && ! -L "$restored_probe_token_file" ]]', RESTORE)

    def test_restore_workflow_requires_distinct_protected_token_files(self) -> None:
        self.assertIn(
            "OPENBAO_RESTORED_PROBE_TOKEN_FILE: ${{ vars.OPENBAO_RESTORED_PROBE_TOKEN_FILE }}",
            WORKFLOW,
        )
        self.assertIn(
            '[[ "$OPENBAO_RESTORED_PROBE_TOKEN_FILE" != "$OPENBAO_OPERATOR_TOKEN_FILE" ]]',
            WORKFLOW,
        )
        self.assertNotIn("OPENBAO_RESTORED_PROBE_TOKEN:", WORKFLOW)


if __name__ == "__main__":
    unittest.main()
