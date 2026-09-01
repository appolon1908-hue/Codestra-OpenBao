#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
VALIDATOR_PATH = ROOT / "scripts/validate_repository.py"
SPEC = importlib.util.spec_from_file_location("validate_repository", VALIDATOR_PATH)
assert SPEC and SPEC.loader
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


class RepositorySecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.upstream = json.loads((ROOT / "CODESTRA_UPSTREAM.json").read_text())
        self.sync_source = (ROOT / ".github/workflows/upstream-source-sync.yml").read_text()
        self.sync_document = yaml.safe_load(self.sync_source)

    def test_current_repository_security_contract(self) -> None:
        VALIDATOR.validate_repository()

    def test_upstream_ref_must_be_an_exact_commit(self) -> None:
        self.upstream["upstream_ref"] = "main"
        with self.assertRaisesRegex(ValueError, "upstream_ref_must_be_exact_commit"):
            VALIDATOR.validate_upstream_authority(self.upstream)

    def test_upstream_sync_opens_reviewed_pr_and_never_pushes_protected_branches(self) -> None:
        VALIDATOR.validate_sync_workflow(self.sync_source, self.sync_document)
        unsafe = self.sync_source.replace(
            'git push origin "HEAD:refs/heads/${SYNC_BRANCH}"',
            "git push origin HEAD:main",
        )
        with self.assertRaisesRegex(ValueError, "protected_branch_sync_forbidden"):
            VALIDATOR.validate_sync_workflow(unsafe, self.sync_document)

    def test_workflow_actions_are_immutable(self) -> None:
        validate_source = (ROOT / ".github/workflows/validate.yml").read_text()
        VALIDATOR.validate_workflow_pins(self.sync_source + "\n" + validate_source)

    def test_exact_upstream_retry_preserves_lock_timestamp(self) -> None:
        self.assertIn(
            "previous_lock.get('upstream_commit') == os.environ['UPSTREAM_SHA']",
            self.sync_source,
        )
        self.assertIn(
            "synchronized_at = previous_lock.get('synchronized_at', synchronized_at)",
            self.sync_source,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
