#!/usr/bin/env python3
from __future__ import annotations

import ast
import importlib.util
import json
import re
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

    def test_upstream_sync_opens_reviewed_pr_and_never_pushes_protected_branches(self) -> None:
        VALIDATOR.validate_sync_workflow(self.sync_source, self.sync_document)
        unsafe = self.sync_source.replace(
            'git push origin "HEAD:refs/heads/${SYNC_BRANCH}"',
            "git push origin HEAD:main",
        )
        with self.assertRaisesRegex(ValueError, "protected_branch_sync_forbidden"):
            VALIDATOR.validate_sync_workflow(unsafe, self.sync_document)
        for destination in (
            "HEAD:refs/heads/main",
            "HEAD:refs/heads/staging",
            "HEAD:refs/heads/production",
            "refs/heads/main",
        ):
            with self.subTest(destination=destination):
                unsafe = self.sync_source.replace(
                    'git push origin "HEAD:refs/heads/${SYNC_BRANCH}"',
                    f"git push origin {destination}",
                )
                with self.assertRaisesRegex(
                    ValueError, "protected_branch_sync_forbidden"
                ):
                    VALIDATOR.validate_sync_workflow(unsafe, yaml.safe_load(unsafe))

    def test_every_push_refspec_is_validated(self) -> None:
        safe = 'git push origin "HEAD:refs/heads/${SYNC_BRANCH}"'
        for suffix in (
            " HEAD:refs/heads/main",
            " HEAD:refs/heads/staging",
            " HEAD:refs/heads/production",
            " \\\n            HEAD:refs/heads/main",
        ):
            with self.subTest(suffix=suffix):
                unsafe = self.sync_source.replace(safe, safe + suffix)
                with self.assertRaisesRegex(
                    ValueError, "protected_branch_sync_forbidden"
                ):
                    VALIDATOR.validate_sync_workflow(unsafe, yaml.safe_load(unsafe))

    def test_attached_shell_separators_cannot_hide_protected_refspec(self) -> None:
        for command in (
            "git push origin HEAD:refs/heads/main;echo ok",
            "git push origin HEAD:refs/heads/staging&&echo ok",
            "git push origin HEAD:refs/heads/production|echo ok",
            "git pu\\sh origin HEAD:refs/heads/main",
        ):
            with self.subTest(command=command):
                with self.assertRaisesRegex(
                    ValueError, "protected_branch_sync_forbidden"
                ):
                    VALIDATOR.reject_protected_pushes(command)

    def test_all_shell_metacharacters_and_git_paths_are_tokenized(self) -> None:
        for command in (
            "(git push origin HEAD:refs/heads/main)",
            "git push origin HEAD:refs/heads/staging>/dev/null",
            "/usr/bin/git -c protocol.version=2 push origin HEAD:refs/heads/main",
        ):
            with self.subTest(command=command):
                with self.assertRaisesRegex(
                    ValueError, "protected_branch_sync_forbidden"
                ):
                    VALIDATOR.reject_protected_pushes(command)

    def test_redirection_before_refspec_cannot_hide_protected_destination(self) -> None:
        for command in (
            "git push origin 2>/dev/null HEAD:refs/heads/main",
            "git push origin >/dev/null HEAD:refs/heads/staging",
        ):
            with self.subTest(command=command):
                with self.assertRaisesRegex(
                    ValueError, "protected_branch_sync_forbidden:push_not_exact"
                ):
                    VALIDATOR.reject_protected_pushes(command)

    def test_nested_shell_cannot_escape_sync_branch_authority(self) -> None:
        command = (
            "bash -c 'SYNC_BRANCH=main; "
            "git push origin HEAD:refs/heads/${SYNC_BRANCH}'"
        )
        with self.assertRaisesRegex(
            ValueError, "protected_branch_sync_forbidden:push_not_exact"
        ):
            VALIDATOR.reject_protected_pushes(command)

    def test_only_exact_approved_push_form_is_allowed(self) -> None:
        VALIDATOR.reject_protected_pushes(
            'git push origin "HEAD:refs/heads/${SYNC_BRANCH}"'
        )
        for command in (
            "git -c remote.origin.push=HEAD:refs/heads/main push origin",
            "git push origin HEAD:refs/heads/{main,topic}",
            "git push origin HEAD:refs/heads/${SYNC_BRANCH} HEAD:refs/heads/main",
        ):
            with self.subTest(command=command):
                with self.assertRaisesRegex(
                    ValueError, "protected_branch_sync_forbidden:push_not_exact"
                ):
                    VALIDATOR.reject_protected_pushes(command)

    def test_sync_branch_destination_is_immutable_and_fully_resolved(self) -> None:
        assignment = 'readonly SYNC_BRANCH="sync/openbao-upstream-${UPSTREAM_REF}"'
        self.assertIn(assignment, self.sync_source)
        reassigned = self.sync_source.replace(
            assignment, assignment + "\n          SYNC_BRANCH=main"
        )
        with self.assertRaisesRegex(ValueError, "sync_branch_authority_invalid"):
            VALIDATOR.validate_sync_workflow(reassigned, yaml.safe_load(reassigned))
        with self.assertRaisesRegex(ValueError, "protected_branch_sync_forbidden"):
            VALIDATOR.reject_protected_pushes(
                "git push origin HEAD:refs/heads/${UNTRUSTED_BRANCH}"
            )

    def test_workflow_actions_are_immutable(self) -> None:
        validate_source = (ROOT / ".github/workflows/validate.yml").read_text()
        combined = self.sync_source + "\n" + validate_source
        VALIDATOR.validate_workflow_pins(combined)
        mutable = self.sync_source.replace(
            "actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
            "actions/checkout@main",
        )
        with self.assertRaisesRegex(ValueError, "unapproved_or_mutable"):
            VALIDATOR.validate_workflow_pins(mutable + "\n" + validate_source)
        unapproved = combined + "\n      - uses: vendor/action@" + ("a" * 40) + "\n"
        with self.assertRaisesRegex(ValueError, "unapproved_or_mutable"):
            VALIDATOR.validate_workflow_pins(unapproved)

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

            imported.unlink()
            credential_shapes = (
                "gh" + "p_" + ("A" * 24),
                "github" + "_pat_" + ("G" * 24),
                "AK" + "IA" + ("B" * 16),
                "AS" + "IA" + ("B" * 16),
                "hv" + "s." + ("C" * 16),
                "s." + ("D" * 24),
                "S" + "K" + ("a" * 32),
                "xo" + "xb-" + ("E" * 20),
                "xa" + "pp-" + ("F" * 20),
            )
            for credential in credential_shapes:
                imported.write_text(credential + "\n")
                result = subprocess.run(
                    [scanner, root], check=False, capture_output=True, text=True
                )
                self.assertEqual(result.returncode, 1, credential[:4])
                imported.unlink()

            for label in ("ENCRYPTED", "DSA"):
                imported.write_text(
                    "-----BEGIN " + label + " PRIVATE" + " KEY-----\nfixture\n"
                )
                result = subprocess.run(
                    [scanner, root], check=False, capture_output=True, text=True
                )
                self.assertEqual(result.returncode, 1, label)
                imported.unlink()

            imported.write_text(
                "-----BEGIN PGP PRIVATE" + " KEY BLOCK-----\nfixture\n"
            )
            result = subprocess.run(
                [scanner, root], check=False, capture_output=True, text=True
            )
            self.assertEqual(result.returncode, 1, "PGP")

    def test_temporary_aws_access_key_fixture_is_sanitized_and_scanned(self) -> None:
        marker = "(?:AKIA|ASIA)[0-9A-Z]{12,}"
        self.assertIn(marker, self.sync_source)
        weakened = self.sync_source.replace(marker, "AKIA[0-9A-Z]{12,}")
        with self.assertRaisesRegex(ValueError, "reviewed_sync_boundary_missing"):
            VALIDATOR.validate_sync_workflow(weakened, yaml.safe_load(weakened))
        match = re.search(
            r"\(r'\(\?:AKIA\|ASIA\)\[0-9A-Z\]\{12,\}',\s*"
            r"'AWS_ACCESS_KEY_ID_FIXTURE_INVALID',\s*0\)",
            self.sync_source,
        )
        self.assertIsNotNone(match)
        self.assertEqual(
            re.sub(
                r"(?:AKIA|ASIA)[0-9A-Z]{12,}",
                "AWS_ACCESS_KEY_ID_FIXTURE_INVALID",
                "ASIA" + ("Q" * 16),
            ),
            "AWS_ACCESS_KEY_ID_FIXTURE_INVALID",
        )

    def test_client_secret_fixture_sanitization_matches_scanner_policy(self) -> None:
        scanner = ROOT / "scripts/reject_repository_secrets.sh"
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / "upstream/tests/oidc.conf"
            fixture.parent.mkdir(parents=True)
            fixture.write_text('oidc_client_' + 'secret = "test"\n')
            rejected = subprocess.run(
                [scanner, directory], check=False, capture_output=True, text=True
            )
            self.assertEqual(rejected.returncode, 1)
            fixture.write_text(
                'oidc_client_' + 'secret = "<CODESTRA_CLIENT_SECRET_FIXTURE_INVALID>"\n'
            )
            accepted = subprocess.run(
                [scanner, directory], check=False, capture_output=True, text=True
            )
            self.assertEqual(accepted.returncode, 0)

    def test_client_secret_sanitization_preserves_supported_syntax(self) -> None:
        heredoc = self.sync_source.rsplit("python3 - <<'PY'\n", 1)[1].split(
            "\n          PY", 1
        )[0]
        embedded = "\n".join(
            line[10:] if line.startswith("          ") else line
            for line in heredoc.splitlines()
        )
        tree = ast.parse(embedded)
        selected = [ast.Import(names=[ast.alias(name="re")])]
        selected.extend(
            node
            for node in tree.body
            if (
                isinstance(node, ast.Assign)
                and any(
                    isinstance(target, ast.Name)
                    and target.id == "CLIENT_SECRET_ASSIGNMENT"
                    for target in node.targets
                )
            )
            or (
                isinstance(node, ast.FunctionDef)
                and node.name == "sanitize_client_secret_assignment"
            )
        )
        namespace: dict[str, object] = {}
        exec(compile(ast.fix_missing_locations(ast.Module(selected, [])), "<sync>", "exec"), namespace)
        pattern = namespace["CLIENT_SECRET_ASSIGNMENT"]
        replacement = namespace["sanitize_client_secret_assignment"]
        self.assertIsInstance(pattern, re.Pattern)

        secret_key = "client_" + "secret"
        supported = {
            f'oidc_{secret_key} = "test"':
                f'oidc_{secret_key} = "<CODESTRA_CLIENT_SECRET_FIXTURE_INVALID>"',
            f"{secret_key}: 'fixture' # kept":
                f"{secret_key}: '<CODESTRA_CLIENT_SECRET_FIXTURE_INVALID>' # kept",
            f'  "{secret_key}": "fixture",':
                f'  "{secret_key}": "<CODESTRA_CLIENT_SECRET_FIXTURE_INVALID>",',
        }
        for original, expected in supported.items():
            with self.subTest(original=original):
                self.assertEqual(pattern.sub(replacement, original), expected)

        unsupported = (
            f'{secret_key} := "test"',
            f'{secret_key} == "test"',
            f'"{secret_key}": null',
            f'{secret_key} = unquoted',
            f'{secret_key} = "test" + suffix',
        )
        for original in unsupported:
            with self.subTest(original=original):
                self.assertEqual(pattern.sub(replacement, original), original)

    def test_sanitization_ledger_order_is_deterministic(self) -> None:
        self.assertIn(
            "for p in sorted(Path('upstream').rglob('*'), key=lambda item: item.as_posix())",
            self.sync_source,
        )
        self.assertIn(
            "sanitizations.sort(key=lambda item: (item['path'], item['rule']))",
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
