import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class RecoveryContractTests(unittest.TestCase):
    def test_backup_is_encrypted_verified_immutable_and_off_host(self) -> None:
        backup = (ROOT / "scripts/backup.sh").read_text()
        for control in (
            "bao operator raft snapshot save",
            "age --encrypt --recipients-file",
            "age --decrypt --identity",
            "bao operator raft snapshot inspect",
            "rclone copyto --immutable",
            "rclone cat",
            '"$remote_checksum" == "$(cat "$checksum")"',
        ):
            self.assertIn(control, backup)

        policy = json.loads((ROOT / "config/recovery/backup.v1.json").read_text())
        self.assertTrue(policy["localProtectedCopyRequired"])
        self.assertTrue(policy["offHostCopyRequired"])
        self.assertTrue(policy["offHostImmutabilityRequired"])
        self.assertTrue(policy["isolatedRestoreRequired"])

    def test_restore_is_isolated_and_never_targets_production(self) -> None:
        restore = (ROOT / "scripts/restore-test.sh").read_text()
        self.assertIn('[[ "$environment" != production ]]', restore)
        self.assertIn('"$target_cluster_id" != "$production_cluster_id"', restore)
        self.assertIn("OPENBAO_ISOLATED_RESTORE_ACKNOWLEDGED", restore)
        self.assertIn("bao operator raft snapshot restore -force", restore)
        self.assertIn("verify_secret_hash.py", restore)

        workflow = (ROOT / ".github/workflows/backup-restore-test.yml").read_text()
        self.assertIn("codestra-openbao-restore", workflow)
        self.assertNotIn("options: [development, test, staging, production]", workflow)
        self.assertIn("Upload only sanitized restore certification evidence", workflow)


if __name__ == "__main__":
    unittest.main()
