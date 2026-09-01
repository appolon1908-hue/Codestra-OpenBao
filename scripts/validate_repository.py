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
    if permissions.get("contents") != "write" or permissions.get("pull-requests") != "write":
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
        'SYNC_BRANCH="sync/openbao-upstream-${UPSTREAM_SHA}"',
        'git push origin "HEAD:refs/heads/${SYNC_BRANCH}"',
        "gh pr create",
        "--base main",
        "Deployment remains disabled",
    )
    for token in required:
        if token not in source:
            raise ValueError(f"reviewed_sync_boundary_missing:{token}")


def validate_workflow_pins(source: str) -> None:
    if "actions/checkout@11d5960a326750d5838078e36cf38b85af677262" not in source:
        raise ValueError("checkout_action_not_pinned")
    if "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065" not in source:
        raise ValueError("setup_python_action_not_pinned")
    if re.search(r"uses:\s+actions/(?:checkout|setup-python)@v\d+", source):
        raise ValueError("mutable_action_reference")


def validate_repository() -> None:
    for path in (UPSTREAM_PATH, SYNC_WORKFLOW_PATH, VALIDATE_WORKFLOW_PATH):
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"required_regular_file_missing:{path.relative_to(ROOT)}")
    upstream = json.loads(UPSTREAM_PATH.read_text(encoding="utf-8"))
    sync_source = SYNC_WORKFLOW_PATH.read_text(encoding="utf-8")
    sync_document = yaml.safe_load(sync_source)
    validate_source = VALIDATE_WORKFLOW_PATH.read_text(encoding="utf-8")
    yaml.safe_load(validate_source)
    validate_upstream_authority(upstream)
    validate_sync_workflow(sync_source, sync_document)
    validate_workflow_pins(sync_source + "\n" + validate_source)

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
    for path in ROOT.rglob("*"):
        if ".git" in path.parts or not path.is_file():
            continue
        if path.name != ".gitignore" and path.name.lower().endswith(forbidden_suffixes):
            raise ValueError(f"forbidden_secret_file:{path.relative_to(ROOT)}")


if __name__ == "__main__":
    try:
        validate_repository()
    except (OSError, ValueError, json.JSONDecodeError, yaml.YAMLError) as error:
        raise SystemExit(f"OPENBAO_SOURCE_VALIDATION=FAIL ERROR={error}") from error
    print("OPENBAO_SOURCE_VALIDATION=PASS")
    print("UPSTREAM_COMMIT_PINNED=YES")
    print("SYNC_THROUGH_REVIEWED_PR=YES")
    print("DEPLOYMENT_ENABLED=NO")
