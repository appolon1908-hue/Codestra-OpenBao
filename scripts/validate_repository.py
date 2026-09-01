#!/usr/bin/env python3
"""Fail-closed validation for the Codestra OpenBao source authority."""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
UPSTREAM_PATH = ROOT / "CODESTRA_UPSTREAM.json"
SYNC_WORKFLOW_PATH = ROOT / ".github/workflows/upstream-source-sync.yml"
VALIDATE_WORKFLOW_PATH = ROOT / ".github/workflows/validate.yml"
WORKFLOW_DIR = ROOT / ".github/workflows"
SECRET_SCANNER_PATH = ROOT / "scripts/reject_repository_secrets.sh"

APPROVED_ACTION_REFERENCES = {
    "actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09",
    "actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1",
    "actions/setup-go@40f1582b2485089dde7abd97c1529aa768e1baff",
    "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
    "actions/download-artifact@634f93cb2916e3fdff6788551b99b062d0335ce0",
    "actions/attest-build-provenance@43d14bc2b83dec42d39ecae14e916627a18bb661",
    "sigstore/cosign-installer@d7543c93d881b35a8faa02e8e3605f69b7a1ce62",
    "./.github/workflows/_deploy-saved-plan.yml",
}

SANITIZED_SECRET_FIXTURES = {
    Path("upstream/sdk/helper/testhelpers/pki/cert.p12"):
        "OPENBAO_PKCS12_TEST_FIXTURE_REMOVED_FOR_GITHUB_ARCHIVAL\n",
    Path("upstream/command/testdata/ossl-key.pem"):
        "OPENBAO_PRIVATE_KEY_TEST_FIXTURE_REMOVED_FOR_GITHUB_ARCHIVAL\n",
}

EXPECTED_UPSTREAM_SHA = "dd9c19c37a878cf4a81b18efb8d6f0599c7da923"
EXPECTED_IMAGE_DIGEST = (
    "sha256:e29524ba7c3f20d01f562c481e3eccbad6c91df45a2f2531433da4951e408cff"
)


def validate_upstream_authority(data: dict) -> None:
    expected = {
        "schema_version": "2.0",
        "component": "OpenBao",
        "codestra_role": "principal-secrets-and-encryption-authority",
        "upstream_repository": "openbao/openbao",
        "upstream_clone_url": "https://github.com/openbao/openbao.git",
        "upstream_version": "2.6.2",
        "upstream_tag": "v2.6.2",
        "upstream_release_url": "https://github.com/openbao/openbao/releases/tag/v2.6.2",
        "image_registry": "ghcr.io/openbao/openbao",
        "image_reference": f"ghcr.io/openbao/openbao@{EXPECTED_IMAGE_DIGEST}",
        "image_index_digest": "sha256:11fd73a2102cda9c55d5d881a8c3210303146a7ec1e8ac76f526e175c6d24641",
        "image_digest": EXPECTED_IMAGE_DIGEST,
        "image_architecture": "linux/amd64",
        "source_identity_verified_at": "2026-09-01",
        "import_path": "upstream",
        "deployment_enabled": False,
        "secret_material_allowed_in_git": False,
        "sanitized_fixture_manifest_required": True,
        "direct_environment_push_allowed": False,
        "branch_promotion": [
            "development",
            "test",
            "staging",
            "production",
            "main",
        ],
    }
    for key, value in expected.items():
        if data.get(key) != value:
            raise ValueError(f"upstream_authority_drift:{key}")
    upstream_ref = data.get("upstream_ref")
    if not isinstance(upstream_ref, str) or re.fullmatch(r"[0-9a-f]{40}", upstream_ref) is None:
        raise ValueError("upstream_ref_must_be_exact_commit")
    if upstream_ref != EXPECTED_UPSTREAM_SHA:
        raise ValueError("upstream_authority_drift:upstream_ref")


def validate_sync_workflow(source: str, document: dict) -> None:
    permissions = document.get("permissions") or {}
    expected_permissions = {
        "actions": "write",
        "contents": "write",
        "pull-requests": "write",
    }
    if permissions != expected_permissions:
        raise ValueError("sync_permissions_must_only_support_reviewed_pr")
    forbidden_patterns = (
        r"git\s+push\s+origin\s+HEAD:(?:main|staging|production)(?:\s|$)",
        r"git\s+push\s+origin\s+(?:main|staging|production)(?:\s|$)",
        r"git\s+pull\s+--rebase\s+origin\s+main",
        r"git\s+push\s+--force",
    )
    for pattern in forbidden_patterns:
        if re.search(pattern, source):
            raise ValueError(f"protected_branch_sync_forbidden:{pattern}")
    required = (
        "[[ \"$UPSTREAM_REF\" =~ ^[0-9a-f]{40}$ ]]",
        "[[ \"$UPSTREAM_SHA\" == \"$UPSTREAM_REF\" ]]",
        'SYNC_BRANCH="sync/openbao-upstream-${UPSTREAM_REF}"',
        'git push origin "HEAD:refs/heads/${SYNC_BRANCH}"',
        "gh pr create",
        'gh workflow run validate.yml --repo "$GITHUB_REPOSITORY" --ref "$SYNC_BRANCH"',
        "--base development",
        "Deployment remains disabled",
        "CODESTRA_UPSTREAM_SANITIZATION.json",
        "original_block_sha256",
        "PRIVATE_KEY_TEST_FIXTURE_REMOVED",
        "previous_lock.get('upstream_commit') == os.environ['UPSTREAM_SHA']",
        "synchronized_at = previous_lock.get('synchronized_at', synchronized_at)",
        'git ls-remote --exit-code --heads origin "refs/heads/${SYNC_BRANCH}"',
        '[[ "$(git show -s --format=%P "refs/remotes/origin/${SYNC_BRANCH}")" == "$GITHUB_SHA" ]]',
        'git switch --create "$SYNC_BRANCH" --track',
        "(( existing_sync_branch == 1 )) || exit 0",
        "Existing sync branch differs from deterministic rebuild.",
        'gh pr list --repo "$GITHUB_REPOSITORY" --state open --base development',
        "Multiple open pull requests claim the sync branch.",
    )
    for token in required:
        if token not in source:
            raise ValueError(f"reviewed_sync_boundary_missing:{token}")


def validate_workflow_pins(source: str) -> None:
    use_keys = re.findall(r"(?m)^[ \t]*(?:-[ \t]*)?uses[ \t]*:", source)
    references = re.findall(
        r"(?m)^[ \t]*(?:-[ \t]*)?uses[ \t]*:[ \t]*([^\s#]+)[ \t]*(?:#.*)?$",
        source,
    )
    if not references or len(references) != len(use_keys):
        raise ValueError("action_reference_must_be_explicit")
    for reference in references:
        if reference not in APPROVED_ACTION_REFERENCES:
            raise ValueError(f"unapproved_or_mutable_action_reference:{reference}")


def validate_workflow_security(path: Path, source: str, document: dict) -> None:
    validate_workflow_pins(source)
    permissions = document.get("permissions")
    if not isinstance(permissions, dict) or not permissions:
        raise ValueError(f"workflow_permissions_must_be_explicit:{path.name}")
    write_permissions = {
        key for key, value in permissions.items() if str(value).lower() == "write"
    }
    allowed_write_permissions = {
        "upstream-source-sync.yml": {"actions", "contents", "pull-requests"},
        "release.yml": {"attestations", "id-token"},
    }.get(path.name, set())
    if write_permissions != allowed_write_permissions:
        raise ValueError(f"workflow_write_permissions_drift:{path.name}")

    jobs = document.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        raise ValueError(f"workflow_jobs_missing:{path.name}")
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            raise ValueError(f"workflow_job_invalid:{path.name}:{job_name}")
        steps = job.get("steps", [])
        if not isinstance(steps, list):
            raise ValueError(f"workflow_steps_invalid:{path.name}:{job_name}")
        for step in steps:
            if not isinstance(step, dict):
                continue
            reference = step.get("uses")
            if not isinstance(reference, str) or not reference.startswith("actions/checkout@"):
                continue
            options = step.get("with") or {}
            expected = path.name == "upstream-source-sync.yml"
            if options.get("persist-credentials") is not expected:
                raise ValueError(
                    f"checkout_credential_boundary_drift:{path.name}:{job_name}"
                )


def validate_all_workflows() -> None:
    for path in sorted(WORKFLOW_DIR.glob("*.yml")):
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"workflow_must_be_regular_file:{path.name}")
        source = path.read_text(encoding="utf-8")
        document = yaml.safe_load(source)
        if not isinstance(document, dict):
            raise ValueError(f"workflow_document_invalid:{path.name}")
        validate_workflow_security(path, source, document)


def validate_whitespace_gate(source: str) -> None:
    required = (
        "fetch-depth: 0",
        'base_sha="${{ github.event.pull_request.base.sha }}"',
        'git diff --check "$base_sha" "$GITHUB_SHA" -- . \':(exclude)upstream\'',
    )
    for token in required:
        if token not in source:
            raise ValueError(f"committed_whitespace_gate_missing:{token}")
    if re.search(r"^\s*git diff --check\s*$", source, re.MULTILINE):
        raise ValueError("whitespace_check_must_use_committed_range")


def validate_secret_scanner(source: str) -> None:
    if "--exclude-dir=tests" in source or '$search_root/tests' in source:
        raise ValueError("imported_tests_must_be_secret_scanned")
    if re.search(r"grep\s+-[^\n]*I", source):
        raise ValueError("binary_secret_scan_must_not_be_skipped")
    required = (
        'find "$search_root"',
        '-path "$search_root/.git"',
        "-type f -o -type l",
        '[[ -L "$path" ]]',
        "grep -aEiq",
        "find_status=$?",
        "secret_scan_status=$?",
        'exit "$secret_scan_status"',
    )
    for token in required:
        if token not in source:
            raise ValueError(f"secret_scan_boundary_missing:{token}")
    if re.search(r"!\s+grep\s+-R", source):
        raise ValueError("secret_scan_errors_must_fail_closed")


def validate_secret_file_policy(root: Path) -> None:
    forbidden_suffixes = (
        ".pem",
        ".key",
        ".p12",
        ".pfx",
        ".jks",
        ".keystore",
        ".unseal",
        ".token",
        ".secret",
    )
    for path in root.rglob("*"):
        if ".git" in path.parts or not path.is_file():
            continue
        relative = path.relative_to(root)
        if path.name != ".gitignore" and path.name.lower().endswith(forbidden_suffixes):
            expected_fixture = SANITIZED_SECRET_FIXTURES.get(relative)
            if expected_fixture is not None:
                if path.read_text(encoding="utf-8") != expected_fixture:
                    raise ValueError(f"sanitized_fixture_content_drift:{relative}")
                continue
            raise ValueError(f"forbidden_secret_file:{relative}")


def validate_repository() -> None:
    for path in (
        UPSTREAM_PATH,
        SYNC_WORKFLOW_PATH,
        VALIDATE_WORKFLOW_PATH,
        SECRET_SCANNER_PATH,
    ):
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"required_regular_file_missing:{path.relative_to(ROOT)}")
    upstream = json.loads(UPSTREAM_PATH.read_text(encoding="utf-8"))
    sync_source = SYNC_WORKFLOW_PATH.read_text(encoding="utf-8")
    sync_document = yaml.safe_load(sync_source)
    validate_source = VALIDATE_WORKFLOW_PATH.read_text(encoding="utf-8")
    secret_scanner_source = SECRET_SCANNER_PATH.read_text(encoding="utf-8")
    yaml.safe_load(validate_source)
    validate_upstream_authority(upstream)
    validate_sync_workflow(sync_source, sync_document)
    validate_all_workflows()
    validate_whitespace_gate(validate_source)
    validate_secret_scanner(secret_scanner_source)

    validate_secret_file_policy(ROOT)


if __name__ == "__main__":
    try:
        validate_repository()
    except (OSError, ValueError, json.JSONDecodeError, yaml.YAMLError) as error:
        raise SystemExit(f"OPENBAO_SOURCE_VALIDATION=FAIL ERROR={error}") from error
    print("OPENBAO_SOURCE_VALIDATION=PASS")
    print("UPSTREAM_COMMIT_PINNED=YES")
    print("SYNC_THROUGH_REVIEWED_PR=YES")
    print("DEPLOYMENT_ENABLED=NO")
