#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import tempfile
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

    def test_whitespace_gate_checks_the_committed_base_to_head_range(self) -> None:
        source = (ROOT / ".github/workflows/validate.yml").read_text()
        self.assertIn("fetch-depth: 0", source)
        self.assertIn('base_sha="${{ github.event.pull_request.base.sha }}"', source)
        self.assertIn(
            'git diff --check "$base_sha" "$GITHUB_SHA" -- . \':(exclude)upstream\'',
            source,
        )

    def test_exact_upstream_retry_preserves_lock_timestamp(self) -> None:
        self.assertIn(
            "previous_lock.get('upstream_commit') == os.environ['UPSTREAM_SHA']",
            self.sync_source,
        )

    def test_generated_sync_pr_explicitly_dispatches_validation(self) -> None:
        self.assertEqual(
            self.sync_document["permissions"],
            {"actions": "write", "contents": "write", "pull-requests": "write"},
        )
        self.assertIn(
            'gh workflow run validate.yml --repo "$GITHUB_REPOSITORY" --ref "$SYNC_BRANCH"',
            self.sync_source,
        )
        validate_document = yaml.safe_load(
            (ROOT / ".github/workflows/validate.yml").read_text()
        )
        triggers = validate_document.get("on") or validate_document.get(True) or {}
        self.assertIn("workflow_dispatch", triggers)

    def test_only_exactly_sanitized_secret_fixture_paths_are_allowed(self) -> None:
        expected = {
            Path("upstream/sdk/helper/testhelpers/pki/cert.p12"):
                "OPENBAO_PKCS12_TEST_FIXTURE_REMOVED_FOR_GITHUB_ARCHIVAL\n",
            Path("upstream/command/testdata/ossl-key.pem"):
                "OPENBAO_PRIVATE_KEY_TEST_FIXTURE_REMOVED_FOR_GITHUB_ARCHIVAL\n",
        }
        self.assertEqual(VALIDATOR.SANITIZED_SECRET_FIXTURES, expected)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative, contents in expected.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(contents)
            VALIDATOR.validate_secret_file_policy(root)

            drifted = root / "upstream/command/testdata/ossl-key.pem"
            drifted.write_text("not sanitized\n")
            with self.assertRaisesRegex(ValueError, "sanitized_fixture_content_drift"):
                VALIDATOR.validate_secret_file_policy(root)

            drifted.write_text(expected[Path("upstream/command/testdata/ossl-key.pem")])
            unexpected = root / "upstream/runtime/private.pem"
            unexpected.parent.mkdir(parents=True)
            unexpected.write_text("also not allowed\n")
            with self.assertRaisesRegex(ValueError, "forbidden_secret_file"):
                VALIDATOR.validate_secret_file_policy(root)
        self.assertIn(
            "synchronized_at = previous_lock.get('synchronized_at', synchronized_at)",
            self.sync_source,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
