from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class RuntimeDeployGuardTests(unittest.TestCase):
    def test_runtime_deploy_is_exact_disabled_recoverable_and_non_destructive(self) -> None:
        source = (ROOT / "scripts/deploy_runtime.sh").read_text(encoding="utf-8")
        for required in (
            "DEPLOY_EXACT_OPENBAO_RUNTIME_",
            ".runtimeApplyAuthorized",
            "verify_environment_approval.sh",
            "OPENBAO_PRECHANGE_BACKUP_EVIDENCE",
            "docker pull --platform linux/amd64",
            "--no-build --pull never",
            "previous_container",
            "RAFT_DATA_DELETED=NO",
            "verify_ssh_unchanged.py",
        ):
            self.assertIn(required, source)
        for forbidden in ("rm -rf", "volume rm", "operator init", "raft snapshot restore"):
            self.assertNotIn(forbidden, source)

    def test_rollback_retains_failed_runtime_and_raft_data(self) -> None:
        source = (ROOT / "scripts/rollback.sh").read_text(encoding="utf-8")
        for required in (
            "ROLLBACK_OPENBAO_RUNTIME_TO_",
            "OPENBAO_PRECHANGE_BACKUP_EVIDENCE",
            "verify_environment_approval.sh",
            "failed-rollback-",
            "RAFT_DATA_DELETED=NO",
            "RECOVERY_MATERIAL_CHANGED=NO",
            "verify_ssh_unchanged.py",
        ):
            self.assertIn(required, source)
        for forbidden in ("rm -rf", "docker rm", "volume rm", "operator init", "snapshot restore"):
            self.assertNotIn(forbidden, source)

    def test_workflow_consumes_only_successful_exact_head_plugin_artifact(self) -> None:
        workflow = (ROOT / ".github/workflows/runtime-deploy.yml").read_text(encoding="utf-8")
        self.assertIn(".head_sha == $sha", workflow)
        self.assertIn('.conclusion == "success"', workflow)
        self.assertIn("openbao-runtime-plugin-${{ inputs.expected_source_sha }}", workflow)
        self.assertIn("Production is not initialized", workflow)
        self.assertIn("persist-credentials: false", workflow)

    def test_compose_has_no_public_ports_and_preserves_key_file_modes(self) -> None:
        compose = (ROOT / "deploy/compose/compose.yaml").read_text(encoding="utf-8")
        self.assertNotIn("ports:", compose)
        self.assertNotIn("secrets:", compose)
        self.assertIn("openbao-server-key:ro", compose)
        self.assertIn("read_only: true", compose)


if __name__ == "__main__":
    unittest.main()
