#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def main() -> None:
    data = json.loads((ROOT / "monitoring-staging-token-control.v1.json").read_text())
    assert data["schema_version"] == "1.0"
    assert data["status"] == "SOURCE_PREPARED_NOT_APPLIED"
    assert data["environment"] == "staging"
    assert data["secret_authority"] == "OpenBao"
    assert data["identity_authority"] == "Keycloak"
    client = data["client"]
    assert client == {
        "client_id": "monitoring-readonly",
        "audience": "middleware-api",
        "client_secret_path": "kv-platform/data/observability/middleware/staging/keycloak-client",
        "client_secret_committed_to_git": False,
    }
    tokens = data["runtime_tokens"]
    assert len(tokens) == 2
    assert {(item["scope"], item["endpoint"]) for item in tokens} == {
        ("metrics.read", "/metrics"),
        ("health.read", "/v1/runtime/safety"),
    }
    assert all(item["maximum_ttl_seconds"] == 300 and item["file_mode"] == "0600" and item["persist_after_evidence"] is False for item in tokens)
    assert data["prometheus_oauth2"]["uses_client_secret_file"] is True
    assert data["prometheus_oauth2"]["automatic_short_lived_token_refresh"] is True
    assert all(value is False for value in data["activation"].values())

    policy_path = ROOT / "staging-policies/monitoring-staging-evidence.hcl"
    assert policy_path.is_file()
    assert not (ROOT / "policies/monitoring-staging-evidence.hcl").exists()
    policy = policy_path.read_text()
    assert 'kv-platform/data/observability/middleware/staging/keycloak-client' in policy
    assert 'capabilities = ["read"]' in policy
    for denied in (
        'kv-*/data/providers/*',
        'kv-*/data/beyvra/execution/*',
        'kv-*/data/communications/delivery/*',
        'kv-*/data/marketing/provider-write/*',
    ):
        assert denied in policy
    assert policy.count('capabilities = ["deny"]') == 4
    print("OPENBAO_MONITORING_STAGING_TOKEN_CONTROL=PASS")


if __name__ == "__main__":
    main()
