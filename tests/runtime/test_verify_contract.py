from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class VerifyContractTests(unittest.TestCase):
    def test_image_readback_checks_repo_digest_not_config_object_id(self) -> None:
        source = (ROOT / "scripts/verify.sh").read_text(encoding="utf-8")
        self.assertIn("docker image inspect", source)
        self.assertIn(".[0].RepoDigests | index($expected) != null", source)
        self.assertNotIn('[[ "$actual_image" == "$expected_image"', source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
