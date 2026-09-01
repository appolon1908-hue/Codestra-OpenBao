#!/usr/bin/env python3
"""Fail-closed source validator for Codestra OpenBao workload authority."""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "config" / "workload-secret-authority.v1.json"
IDENTITY = re.compile(r"^[a-z][a-z0-9-]+$")
EXPECTED_SERVICES = {
    "kong-gateway", "middleware-api", "middleware-worker",
    "n8n-automation", "odoo-integration",
}
EXPECTED_NAMESPACES = {
    "kong-gateway": "kong/",
    "middleware-api": "middleware/api/",
    "middleware-worker": "middleware/worker/",
    "n8n-automation": "n8n/middleware-client/",
    "odoo-integration": "odoo/integration/",
}
FORBIDDEN_PATH_PARTS = {"*", "..", "//"}


def fail(message: str) -> None:
    raise SystemExit(f"OPENBAO_SOURCE_AUTHORITY=FAIL: {message}")


def validate(policy: dict) -> None:
    expected_top = {
        "schemaVersion", "status", "runtimeApplyAuthorized", "issuer",
        "authMethod", "audience", "requiredClaims", "maximumTokenLifetimeSeconds",
        "defaultPolicy", "secretInjection", "rotation", "roles", "explicitDeny",
        "requiredEvidence",
    }
    if set(policy) != expected_top:
        fail("top-level fields drifted")
    if policy["schemaVersion"] != 1 or policy["status"] != "PREPARED_DISABLED":
        fail("source authority must remain prepared and disabled")
    if policy["runtimeApplyAuthorized"] is not False:
        fail("runtime apply must not be authorized by source")
    if policy["issuer"] != "https://auth.codestra.co/realms/codestra":
        fail("issuer drift")
    if policy["authMethod"] != "jwt" or policy["audience"] != "openbao":
        fail("workload authentication drift")
    if policy["requiredClaims"] != ["iss", "sub", "aud", "azp", "iat", "exp", "jti"]:
        fail("required claims drift")
    if not 1 <= policy["maximumTokenLifetimeSeconds"] <= 300:
        fail("workload token lifetime is not short-lived")
    if policy["defaultPolicy"] != "deny":
        fail("default policy must deny")

    injection = policy["secretInjection"]
    if injection != {
        "method": "agent-rendered-file",
        "environmentVariablesAllowed": False,
        "containerImageBakeAllowed": False,
        "gitMaterializationAllowed": False,
        "fileMode": "0400",
        "staticKvSecretLeaseRenewalRequired": False,
        "staticKvRerenderOnChangeRequired": True,
        "agentAuthTokenRenewalRequired": True,
        "dynamicSecretLeaseRenewalRequired": True,
        "dynamicSecretRevocationOnShutdownRequired": True,
    }:
        fail("secret injection must be file-based and fail closed")
    rotation = policy["rotation"]
    if rotation != {
        "ownerRequired": True,
        "maximumAgeDays": 90,
        "overlapRequired": True,
        "revocationTestRequired": True,
        "auditEventRequired": True,
    }:
        fail("rotation controls drift")

    roles = policy["roles"]
    if not isinstance(roles, list) or not roles:
        fail("roles missing")
    seen: set[tuple[str, str]] = set()
    coverage: dict[str, set[str]] = {"production": set(), "staging": set()}
    for role in roles:
        if set(role) != {"environment", "serviceIdentity", "boundClaims", "pathPrefixes", "operations"}:
            fail("role fields drifted")
        environment = role["environment"]
        identity = role["serviceIdentity"]
        if environment not in coverage or not IDENTITY.fullmatch(identity):
            fail("invalid environment or service identity")
        key = (environment, identity)
        if key in seen:
            fail("duplicate environment/service role")
        seen.add(key)
        coverage[environment].add(identity)
        if role["boundClaims"] != {
            "azp": identity,
            "codestra_environment": environment,
        }:
            fail("JWT role is not bound to exact service and environment claims")
        if role["operations"] != ["read"]:
            fail("workloads may only read exact secret prefixes")
        prefixes = role["pathPrefixes"]
        if not isinstance(prefixes, list) or not prefixes:
            fail("role path prefix missing")
        required_prefixes = [
            f"codestra/{environment}/{EXPECTED_NAMESPACES[identity]}"
        ]
        if prefixes != required_prefixes:
            fail("role grant is outside its exact service namespace")
        required_root = f"codestra/{environment}/"
        for prefix in prefixes:
            if not prefix.startswith(required_root) or not prefix.endswith("/"):
                fail("cross-environment or malformed path prefix")
            if any(part in prefix for part in FORBIDDEN_PATH_PARTS):
                fail("wildcard or traversal path prefix")
    if any(services != EXPECTED_SERVICES for services in coverage.values()):
        fail("environment service coverage mismatch")

    denies = policy["explicitDeny"]
    required_n8n_denies = {
        "codestra/production/beyvra/", "codestra/production/klyrow/",
        "codestra/production/telnexa/", "codestra/production/vicidial/",
    }
    if set(denies.get("n8n-automation", [])) != required_n8n_denies:
        fail("n8n provider/trading deny boundary drift")
    if denies.get("observability") != ["codestra/production/"]:
        fail("observability production-secret deny boundary drift")
    for role in roles:
        denied_prefixes = denies.get(role["serviceIdentity"], [])
        for granted in role["pathPrefixes"]:
            if any(
                granted.startswith(denied) or denied.startswith(granted)
                for denied in denied_prefixes
            ):
                fail("role grant overlaps an explicit deny boundary")

    required_evidence = {
        "agent_auth_token_accessor_hash", "audit_event",
        "dynamic_lease_id_hash_if_applicable", "policy_name", "role_name",
        "sanitized_path_prefix", "secret_version", "service_identity",
    }
    if policy["requiredEvidence"] != sorted(required_evidence):
        fail("required evidence drift")


def main() -> int:
    try:
        policy = json.loads(POLICY.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(str(exc))
    validate(policy)
    print("OPENBAO_SOURCE_AUTHORITY=PASS")
    print("OPENBAO_RUNTIME_APPLY_AUTHORIZED=NO")
    print("PLAINTEXT_SECRET_INJECTION=DISALLOWED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
