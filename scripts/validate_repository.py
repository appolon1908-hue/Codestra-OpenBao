#!/usr/bin/env python3
"""Fail-closed validation for the Codestra OpenBao source authority."""

from __future__ import annotations

import json
import re
import shlex
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
UPSTREAM_PATH = ROOT / "CODESTRA_UPSTREAM.json"
SYNC_WORKFLOW_PATH = ROOT / ".github/workflows/upstream-source-sync.yml"
VALIDATE_WORKFLOW_PATH = ROOT / ".github/workflows/validate.yml"
SECRET_SCANNER_PATH = ROOT / "scripts/reject_repository_secrets.sh"

APPROVED_ACTION_REFERENCES = {
    "actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
    "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065",
}

SANITIZED_SECRET_FIXTURES = {
    Path("upstream/sdk/helper/testhelpers/pki/cert.p12"):
        "OPENBAO_PKCS12_TEST_FIXTURE_REMOVED_FOR_GITHUB_ARCHIVAL\n",
    Path("upstream/command/testdata/ossl-key.pem"):
        "OPENBAO_PRIVATE_KEY_TEST_FIXTURE_REMOVED_FOR_GITHUB_ARCHIVAL\n",
}


def _logical_shell_lines(source: str) -> tuple[str, ...]:
    records: list[str] = []
    pending = ""
    for raw in source.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        pending = f"{pending} {line}".strip()
        if pending.endswith("\\"):
            pending = pending[:-1].rstrip()
            continue
        records.append(pending)
        pending = ""
    if pending:
        records.append(pending)
    return tuple(records)


def reject_protected_pushes(source: str) -> None:
    protected = {"main", "staging", "production"}
    separators = {";", "&&", "||", "|", "&"}
    for line in _logical_shell_lines(source):
        if re.search(r"\bgit\b.*\bpush\b", line) is None:
            continue
        try:
            words = shlex.split(line, comments=True, posix=True)
        except ValueError as exc:
            raise ValueError("sync_shell_parse_failed") from exc
        for index, word in enumerate(words):
            if word != "git":
                continue
            command_index = index + 1
            while command_index < len(words) and words[command_index].startswith("-"):
                option = words[command_index]
                command_index += 2 if option in {"-c", "-C", "--git-dir", "--work-tree"} else 1
            if command_index >= len(words) or words[command_index] != "push":
                continue
            for candidate in words[command_index + 1 :]:
                if candidate in separators:
                    break
                if candidate in {
                    "--all",
                    "--branches",
                    "--force",
                    "--force-with-lease",
                    "--mirror",
                    "-f",
                } or candidate.startswith(("--force=", "--force-with-lease=")):
                    raise ValueError("protected_branch_sync_forbidden:push_option")
                refspec = candidate.lstrip("+")
                if any(marker in refspec for marker in ("*", "?", "[")):
                    raise ValueError("protected_branch_sync_forbidden:wildcard")
                destination = refspec.rsplit(":", 1)[-1].removeprefix("refs/heads/")
                if destination in protected:
                    raise ValueError("protected_branch_sync_forbidden:refspec")


def validate_upstream_authority(data: dict) -> None:
    expected = {
        "schema_version": "1.0",
        "component": "OpenBao",
        "codestra_role": "principal-secrets-and-encryption-authority",
        "upstream_repository": "openbao/openbao",
        "upstream_clone_url": "https://github.com/openbao/openbao.git",
        "import_path": "upstream",
        "deployment_enabled": False,
        "secret_material_allowed_in_git": False,
    }
    for key, value in expected.items():
        if data.get(key) != value:
            raise ValueError(f"upstream_authority_drift:{key}")
    upstream_ref = data.get("upstream_ref")
    if not isinstance(upstream_ref, str) or re.fullmatch(r"[0-9a-f]{40}", upstream_ref) is None:
        raise ValueError("upstream_ref_must_be_exact_commit")


def validate_sync_workflow(source: str, document: dict) -> None:
    permissions = document.get("permissions") or {}
    expected_permissions = {
        "actions": "write",
        "contents": "write",
        "pull-requests": "write",
    }
    if permissions != expected_permissions:
        raise ValueError("sync_permissions_must_only_support_reviewed_pr")
    reject_protected_pushes(source)
    forbidden_patterns = (
        r"git\s+push\s+origin\s+['\"]?HEAD:(?:refs/heads/)?(?:main|staging|production)['\"]?(?:\s|$)",
        r"git\s+push\s+origin\s+['\"]?(?:refs/heads/)?(?:main|staging|production)['\"]?(?:\s|$)",
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
        "--base main",
        "Deployment remains disabled",
        "previous_lock.get('upstream_commit') == os.environ['UPSTREAM_SHA']",
        "synchronized_at = previous_lock.get('synchronized_at', synchronized_at)",
        'git ls-remote --exit-code --heads origin "refs/heads/${SYNC_BRANCH}"',
        '[[ "$(git show -s --format=%P "refs/remotes/origin/${SYNC_BRANCH}")" == "$GITHUB_SHA" ]]',
        'git switch --create "$SYNC_BRANCH" --track',
        "(( existing_sync_branch == 1 )) || exit 0",
        "Existing sync branch differs from deterministic rebuild.",
        "for p in sorted(Path('upstream').rglob('*'), key=lambda item: item.as_posix())",
        "sanitizations.sort(key=lambda item: (item['path'], item['rule']))",
        "CODESTRA_CLIENT_SECRET_FIXTURE_INVALID",
        "(?:AKIA|ASIA)[0-9A-Z]{12,}",
        'gh pr list --repo "$GITHUB_REPOSITORY" --state open --base main',
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
    if not APPROVED_ACTION_REFERENCES <= set(references):
        raise ValueError("required_action_reference_missing")
    for reference in references:
        if reference not in APPROVED_ACTION_REFERENCES:
            raise ValueError(f"unapproved_or_mutable_action_reference:{reference}")
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
    if "[^[:space:]<\\\"']+" not in source:
        raise ValueError("sanitized_client_secret_placeholder_must_not_match")
    required = (
        'find "$search_root"',
        '-path "$search_root/.git"',
        "-type f -o -type l",
        '[[ -L "$path" ]]',
        "grep -aEiq",
        "find_status=$?",
        "secret_scan_status=$?",
        'exit "$secret_scan_status"',
        "(AKIA|ASIA)[0-9A-Z]{12,}",
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
    validate_workflow_pins(sync_source + "\n" + validate_source)
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
