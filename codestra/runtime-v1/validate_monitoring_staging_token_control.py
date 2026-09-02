#!/usr/bin/env python3
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BUSINESSES = (
    "codestra",
    "moneybee",
    "beyvra",
    "breero",
    "larim-a",
    "transportation",
    "booked4seasons",
    "social",
    "klyrow",
    "telnexa",
    "kyqra",
    "restaurant",
    "provisioning",
)


def main() -> None:
    data = json.loads((ROOT / "monitoring-staging-token-control.v1.json").read_text())
    assert data["schema_version"] == "1.2"
    assert data["status"] == "SOURCE_PREPARED_NOT_APPLIED"
    assert data["environment"] == "staging"
    assert data["secret_authority"] == "OpenBao"
    assert data["identity_authority"] == "Keycloak"
    keycloak_source = json.loads(
        (ROOT / "keycloak-monitoring-readonly.v1.json").read_text()
    )
    assert keycloak_source == {
        "schema_version": "1.0",
        "source_repository": "appolon1908-hue/Keycloak",
        "source_branch": "safety/monitoring-readonly-exact-audience-20260902",
        "source_sha": keycloak_source["source_sha"],
        "source_files": [
            {
                "path": "config/clients/monitoring-readonly.json",
                "sha256": "sha256:04dfb317ba4df345d4d326d4845d18eb3da8aeda2218e8e3c8bb629888b51f11",
            },
            {
                "path": "config/client-scopes/health.read.json",
                "sha256": "sha256:540fa67431c8c5c482acd5fa11a9578d51822b0e80a95d430bc188ccac0f346c",
            },
            {
                "path": "config/client-scopes/metrics.read.json",
                "sha256": "sha256:cd46f1a3883d5161e85cb7a9ebaf0c45fab5c06922554c89c7e01f4c94c86bc2",
            },
        ],
        "client": {
            "client_id": "monitoring-readonly",
            "protocol_mapper_names": ["audience-middleware-api"],
            "audiences": ["middleware-api"],
            "default_client_scopes": [],
            "optional_client_scopes": ["health.read", "metrics.read"],
            "full_scope_allowed": False,
            "service_accounts_enabled": True,
        },
        "client_scopes": [
            {
                "name": "health.read",
                "include_in_token_scope": True,
                "protocol_mappers": [],
            },
            {
                "name": "metrics.read",
                "include_in_token_scope": True,
                "protocol_mappers": [],
            },
        ],
        "secret_values_included": False,
    }
    assert re.fullmatch(r"[0-9a-f]{40}", keycloak_source["source_sha"])
    client = data["client"]
    assert client == {
        "client_id": "monitoring-readonly",
        "audience": "middleware-api",
        "client_secret_path": "kv-platform/data/observability/middleware/staging/keycloak-client",
        "client_secret_committed_to_git": False,
        "keycloak_source_contract": "keycloak-monitoring-readonly.v1.json",
        "scope_authority": "Keycloak optional client scopes",
        "required_returned_scopes": ["health.read", "metrics.read"],
    }
    assert client["client_id"] == keycloak_source["client"]["client_id"]
    assert [client["audience"]] == keycloak_source["client"]["audiences"]
    assert client["required_returned_scopes"] == keycloak_source["client"]["optional_client_scopes"]
    tokens = data["runtime_tokens"]
    assert len(tokens) == 2
    assert {(item["required_scope"], item["endpoint"]) for item in tokens} == {
        ("metrics.read", "/metrics"),
        ("health.read", "/v1/runtime/safety"),
    }
    assert all(item["maximum_ttl_seconds"] == 300 and item["file_mode"] == "0600" and item["persist_after_evidence"] is False for item in tokens)
    oauth = data["prometheus_oauth2"]
    assert oauth == {
        "uses_client_secret_file": True,
        "requested_scopes": ["metrics.read"],
        "scope_claim_authority": "Keycloak optional client scope request",
        "required_returned_scope": "metrics.read",
        "stores_access_token": False,
        "automatic_short_lived_token_refresh": True,
    }
    assert data["evidence_rules"]["returned_scopes_must_be_validated"] is True
    assert all(value is False for value in data["activation"].values())

    policy_path = ROOT / "staging-policies/monitoring-staging-evidence.hcl"
    assert policy_path.is_file()
    assert not (ROOT / "policies/monitoring-staging-evidence.hcl").exists()
    policy = policy_path.read_text()
    assert 'kv-platform/data/observability/middleware/staging/keycloak-client' in policy
    assert 'kv-platform/metadata/observability/middleware/staging/keycloak-client' in policy
    assert policy.count('capabilities = ["read"]') == 3
    assert 'path "kv-*' not in policy

    expected_denies = {
        f"kv-{business}/data/{suffix}"
        for business in BUSINESSES
        for suffix in (
            "providers/*",
            "communications/delivery/*",
            "marketing/provider-write/*",
        )
    }
    expected_denies.add("kv-beyvra/data/execution/*")
    for denied in expected_denies:
        assert f'path "{denied}"' in policy, denied
    assert policy.count('capabilities = ["deny"]') == len(expected_denies) == 40
    print("OPENBAO_MONITORING_STAGING_TOKEN_CONTROL=PASS")


if __name__ == "__main__":
    main()
