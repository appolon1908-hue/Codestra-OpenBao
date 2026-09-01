#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import subprocess
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

    def test_upstream_image_authority_must_be_an_exact_digest(self) -> None:
        self.upstream["image_reference"] = "ghcr.io/openbao/openbao:2.6.2"
        with self.assertRaisesRegex(ValueError, "upstream_authority_drift:image_reference"):
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
        VALIDATOR.validate_all_workflows()
        mutable = self.sync_source.replace(
            "actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09",
            "actions/checkout@main",
        )
        with self.assertRaisesRegex(ValueError, "unapproved_or_mutable"):
            VALIDATOR.validate_workflow_pins(mutable)
        unapproved = self.sync_source + "\n      - uses: vendor/action@" + ("a" * 40) + "\n"
        with self.assertRaisesRegex(ValueError, "unapproved_or_mutable"):
            VALIDATOR.validate_workflow_pins(unapproved)

    def test_checkout_credentials_are_disabled_except_reviewed_sync_writer(self) -> None:
        VALIDATOR.validate_all_workflows()
        validate_path = ROOT / ".github/workflows/validate.yml"
        source = validate_path.read_text(encoding="utf-8")
        document = yaml.safe_load(source)
        document["jobs"]["source-authority"]["steps"][0]["with"][
            "persist-credentials"
        ] = True
        with self.assertRaisesRegex(ValueError, "checkout_credential_boundary_drift"):
            VALIDATOR.validate_workflow_security(validate_path, source, document)

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

    def test_existing_sync_branch_is_reused_without_a_sibling_commit(self) -> None:
        branch_lookup = self.sync_source.index("git ls-remote --exit-code --heads")
        branch_switch = self.sync_source.index(
            'git switch --create "$SYNC_BRANCH" --track'
        )
        lock_read = self.sync_source.index(
            "lock_path = Path('CODESTRA_UPSTREAM_LOCK.json')"
        )
        commit = self.sync_source.index("git commit -m")
        pr_lookup = self.sync_source.index("gh pr list", commit)
        self.assertLess(branch_lookup, branch_switch)
        self.assertLess(branch_switch, lock_read)
        self.assertLess(lock_read, commit)
        self.assertLess(commit, pr_lookup)
        self.assertIn(
            '[[ "$(git show -s --format=%P "refs/remotes/origin/${SYNC_BRANCH}")" == "$GITHUB_SHA" ]]',
            self.sync_source,
        )
        self.assertIn(
            "Existing sync branch differs from deterministic rebuild.",
            self.sync_source,
        )

    def test_secret_scan_includes_imported_test_directories(self) -> None:
        scanner = ROOT / "scripts/reject_repository_secrets.sh"
        source = scanner.read_text()
        VALIDATOR.validate_secret_scanner(source)
        self.assertNotIn("--exclude-dir=tests", source)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            clean = root / "clean.txt"
            clean.write_text("no credential material\n")
            result = subprocess.run(
                [scanner, root], check=False, capture_output=True, text=True
            )
            self.assertEqual(result.returncode, 0)
            imported = root / "upstream/tests/credentials.json"
            imported.parent.mkdir(parents=True)
            imported.write_text(
                '{"'
                + "Author"
                + "ization"
                + '":"'
                + "Bearer "
                + ("A" * 32)
                + '"}\n'
            )
            result = subprocess.run(
                [scanner, root], check=False, capture_output=True, text=True
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("upstream/tests/credentials.json", result.stderr)

    def test_secret_scan_rejects_provider_tokens_and_private_keys(self) -> None:
        scanner = ROOT / "scripts/reject_repository_secrets.sh"
        cases = {
            "github.txt": "gh" + "p_" + ("A" * 24),
            "aws.txt": "AK" + "IA" + ("A" * 16),
            "encrypted-key.txt": "-----BEGIN " + "ENCRYPTED PRIVATE KEY-----\n",
            "dsa-key.txt": "-----BEGIN " + "DSA PRIVATE KEY-----\n",
            "openbao-token.txt": "hv" + "s." + ("A" * 16),
        }
        for name, contents in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / name
                path.write_text(contents)
                result = subprocess.run(
                    [scanner, directory], check=False, capture_output=True, text=True
                )
                self.assertEqual(result.returncode, 1)
                self.assertIn(name, result.stderr)

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
