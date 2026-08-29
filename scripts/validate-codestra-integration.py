#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "config" / "codestra" / "runtime.v1.json"
LISTENER = ROOT / "config" / "codestra" / "openbao.hcl.example"
OIDC_PLAN = ROOT / "config" / "codestra" / "oidc-plan.v1.json"
EXPECTED_REDIRECTS = [
    "https://bao.codestra.media/v1/auth/oidc/callback",
    "https://bao.codestra.media/ui/vault/auth/oidc/oidc/callback",
    "http://localhost:8250/oidc/callback",
]


def fail(message: str) -> None:
    print(f"OPENBAO_CODESTRA_VALIDATION_ERROR={message}", file=sys.stderr)
    raise SystemExit(1)


def load(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot parse {path}: {exc}")
    if not isinstance(value, dict):
        fail(f"{path} must contain an object")
    return value


def assert_all_false(mapping: dict, label: str) -> None:
    enabled = [key for key, value in mapping.items() if value is True]
    if enabled:
        fail(f"{label} must remain inactive: {enabled}")


def main() -> None:
    runtime = load(RUNTIME)
    plan = load(OIDC_PLAN)
    listener = LISTENER.read_text(encoding="utf-8")

    if runtime.get("hostname") != "bao.codestra.media":
        fail("canonical hostname mismatch")
    if runtime.get("hostBind") != "127.0.0.1:8200":
        fail("OpenBao API must bind to loopback")
    if runtime.get("clusterBind") != "127.0.0.1:8201":
        fail("OpenBao cluster listener must bind to loopback in this plan")
    if runtime.get("publicNativePortAllowed") is not False:
        fail("native OpenBao port must not be public")

    network = runtime.get("networkPolicy", {})
    if network.get("caddySourceAllowlistRequired") is not True:
        fail("Caddy source allowlist is required")
    if network.get("nativeApiInternetExposureAllowed") is not False:
        fail("native API Internet exposure is prohibited")

    oidc = runtime.get("oidc", {})
    if oidc.get("issuer") != "https://auth.codestra.co/realms/codestra":
        fail("issuer mismatch")
    if oidc.get("clientId") != "openbao-secrets":
        fail("client ID mismatch")
    if oidc.get("clientSecretFile") != "/run/secrets/openbao_oidc_client_secret":
        fail("client secret file mismatch")
    if oidc.get("redirectUris") != EXPECTED_REDIRECTS:
        fail("runtime redirect URI set mismatch")
    if oidc.get("nativePolicyEnforcementRequired") is not True:
        fail("native OpenBao policies remain mandatory")

    storage = runtime.get("storage", {})
    if storage.get("backend") != "unselected":
        fail("storage backend must remain unselected on this branch")
    if not all(
        storage.get(key) is True
        for key in ("haDesignRequired", "backupRestoreRequired", "sealDesignRequired")
    ):
        fail("storage, HA, backup, and seal prerequisites are incomplete")
    assert_all_false(runtime.get("activation", {}), "runtime activation")

    if plan.get("applyMode") != "plan-only":
        fail("OIDC configuration must remain plan-only")
    config = plan.get("config", {})
    if config.get("oidcDiscoveryUrl") != "https://auth.codestra.co/realms/codestra":
        fail("OIDC discovery URL mismatch")
    if config.get("oidcClientId") != "openbao-secrets":
        fail("OIDC plan client ID mismatch")
    if config.get("oidcClientSecretFile") != "/run/secrets/openbao_oidc_client_secret":
        fail("OIDC plan secret source mismatch")
    if config.get("defaultRole") != "":
        fail("a default OpenBao OIDC role is prohibited")

    roles = plan.get("roles")
    expected_roles = {
        "codestra-secrets-operator": ("secrets-operator", "codestra-secrets-operator"),
        "codestra-secrets-admin": ("secrets-admin", "codestra-secrets-admin"),
    }
    if not isinstance(roles, list) or {role.get("name") for role in roles} != set(expected_roles):
        fail("exact operator/admin OIDC roles are required")
    for role in roles:
        expected_claim, expected_policy = expected_roles[role["name"]]
        if role.get("roleType") != "oidc":
            fail(f"{role['name']}: role type must be oidc")
        if role.get("boundAudiences") != ["openbao-secrets"]:
            fail(f"{role['name']}: audience mismatch")
        if role.get("allowedRedirectUris") != EXPECTED_REDIRECTS:
            fail(f"{role['name']}: callback mismatch")
        if role.get("groupsClaim") != "/realm_access/roles":
            fail(f"{role['name']}: groups claim mismatch")
        if role.get("boundClaims") != {"/realm_access/roles": [expected_claim]}:
            fail(f"{role['name']}: bound role claim mismatch")
        if role.get("policies") != [expected_policy]:
            fail(f"{role['name']}: policy mismatch")

    prerequisites = plan.get("policyPrerequisites", {})
    if prerequisites.get("rootOrDefaultBroadPolicyAllowed") is not False:
        fail("broad/root policy assignment is prohibited")
    if prerequisites.get("oidcAuthenticationReplacesOpenBaoPolicies") is not False:
        fail("OIDC must not replace OpenBao policy enforcement")
    assert_all_false(plan.get("activation", {}), "OIDC activation")

    required_listener_fragments = (
        'api_addr = "https://bao.codestra.media"',
        'address         = "127.0.0.1:8200"',
        'cluster_address = "127.0.0.1:8201"',
        'tls_disable = true',
    )
    if any(fragment not in listener for fragment in required_listener_fragments):
        fail("listener example is incomplete")
    if "0.0.0.0" in listener:
        fail("public wildcard listeners are prohibited")
    if "storage \"" in listener or "seal \"" in listener:
        fail("storage/seal must not be selected in this branch")

    combined = RUNTIME.read_text(encoding="utf-8") + OIDC_PLAN.read_text(encoding="utf-8")
    for forbidden in ("oidcClientSecret\":", "root_token", "unseal_key"):
        if forbidden in combined:
            fail(f"prohibited secret-bearing material found: {forbidden}")

    print("OPENBAO_CODESTRA_INTEGRATION_VALID=1")


if __name__ == "__main__":
    main()
