#!/usr/bin/env python3
"""Fail-closed validation for the Codestra OpenBao corporate overlay."""

from __future__ import annotations

import json
import pathlib
import re
import sys
from typing import Any

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
CODESTRA = ROOT / "codestra"
RUNTIME = CODESTRA / "runtime-v1" / "runtime.v1.json"
CONTROL = CODESTRA / "runtime-v1" / "secret-control-plane.v1.json"
CONFIG = CODESTRA / "runtime-v1" / "openbao.hcl.example"
POLICIES = CODESTRA / "runtime-v1" / "policies"
OPERATING_MODEL = CODESTRA / "docs" / "OPERATING-MODEL.md"
CORPORATE_FEATURES = CODESTRA / "docs" / "CORPORATE-FEATURES.md"
UPSTREAM_WORKFLOW = ROOT / ".github" / "workflows" / "upstream-source-sync.yml"

BUSINESSES = {
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
}
POLICY_FILES = {
    "business-admin-template.hcl",
    "workload-read-template.hcl",
    "auditor.hcl",
    "beyvra-execution-template.hcl",
}


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def require_file(path: pathlib.Path) -> str:
    if not path.is_file():
        fail(f"missing required file: {path.relative_to(ROOT)}")
    return path.read_text(encoding="utf-8")


def load_json(path: pathlib.Path) -> Any:
    try:
        return json.loads(require_file(path))
    except Exception as exc:
        fail(f"invalid JSON {path.relative_to(ROOT)}: {exc}")


def validate_runtime() -> None:
    runtime = load_json(RUNTIME)
    if runtime.get("schemaVersion") != "1.0" or runtime.get("component") != "openbao":
        fail("OpenBao runtime identity mismatch")
    if runtime.get("canonicalHostname") != "bao.codestra.media":
        fail("canonical OpenBao hostname mismatch")
    if runtime.get("status") != "CONFIG_PREPARED_NOT_DEPLOYED":
        fail("OpenBao runtime must remain source-only")
    if set(runtime.get("businessScope", [])) != BUSINESSES:
        fail("OpenBao business catalogue mismatch")
    if set(runtime.get("environmentScope", [])) != {
        "development",
        "test",
        "staging",
        "production",
    }:
        fail("OpenBao environment catalogue mismatch")

    storage = runtime.get("storage", {})
    if storage.get("backend") != "integrated-raft":
        fail("OpenBao must use integrated Raft")
    if storage.get("haRequired") is not True:
        fail("OpenBao HA must remain required")
    if int(storage.get("minimumVotingNodesProduction", 0)) < 3:
        fail("OpenBao production requires at least three voting nodes")
    for field in (
        "autopilotRequired",
        "snapshotsEncryptedAndTested",
        "snapshotRestoreValidationRequired",
    ):
        if storage.get(field) is not True:
            fail(f"OpenBao storage control missing: {field}")

    transport = runtime.get("transport", {})
    if transport.get("minimumVersion") != "TLS13":
        fail("OpenBao transport must require TLS 1.3")
    for field in ("tlsRequired", "clusterTlsRequired"):
        if transport.get(field) is not True:
            fail(f"OpenBao TLS control missing: {field}")
    for field in ("plaintextListener", "publicNativePort", "prometheusUnauthenticatedMetrics"):
        if transport.get(field) is not False:
            fail(f"OpenBao transport boundary must remain false: {field}")

    human = runtime.get("identity", {}).get("human", {})
    if human.get("method") != "keycloak-oidc":
        fail("OpenBao human identity must use Keycloak OIDC")
    if human.get("issuer") != "https://auth.codestra.co/realms/codestra":
        fail("OpenBao issuer mismatch")
    if human.get("pkce") != "S256" or human.get("mfaRequiredForPrivilegedRoles") is not True:
        fail("OpenBao privileged human access must require PKCE and MFA")
    if human.get("rootTokenDailyUse") is not False:
        fail("daily root-token use must remain prohibited")

    workload = runtime.get("identity", {}).get("workload", {})
    if workload.get("preferredMethod") != "jwt" or workload.get("requiredAudience") != "openbao":
        fail("OpenBao workload identity must use audience-bound JWT")
    if workload.get("staticLongLivedTokens") is not False:
        fail("static long-lived workload tokens must remain disabled")
    if int(workload.get("tokenTtlMinutes", 0)) > 15:
        fail("OpenBao workload token TTL exceeds 15 minutes")
    if int(workload.get("tokenMaxTtlMinutes", 0)) > 60:
        fail("OpenBao workload maximum TTL exceeds one hour")

    isolation = runtime.get("businessIsolation", {})
    for field in ("mountPerBusiness", "environmentPathIsolation"):
        if isolation.get(field) is not True:
            fail(f"OpenBao isolation control missing: {field}")
    for field in (
        "crossBusinessWildcardPolicies",
        "customerControlledPolicyNames",
        "observabilityMayReadSecretValues",
        "supersetMayReadSecretValues",
        "n8nMayReadUnscopedSecretValues",
    ):
        if isolation.get(field) is not False:
            fail(f"OpenBao isolation boundary must remain false: {field}")

    beyvra = runtime.get("beyvraHighSecurityCompartment", {})
    if beyvra.get("mount") != "kv-beyvra/" or beyvra.get("transitMount") != "transit-beyvra/":
        fail("Beyvra high-security mount mismatch")
    if beyvra.get("brokerExchangeCustodySigningEnabledByDefault") is not False:
        fail("Beyvra signing must remain disabled by default")
    if beyvra.get("browserSecretValueAccess") is not False:
        fail("Beyvra browser secret access must remain disabled")
    if beyvra.get("dualApprovalForSigningActivation") is not True:
        fail("Beyvra signing activation must require dual approval")

    activation = runtime.get("activation", {})
    if not activation or any(value is not False for value in activation.values()):
        fail("all OpenBao activation gates must remain false")


def validate_control_plane() -> None:
    control = load_json(CONTROL)
    if control.get("status") != "CONTROL_PLANE_PREPARED_NOT_APPLIED":
        fail("OpenBao control plane must remain unapplied")
    if set(control.get("businesses", [])) != BUSINESSES:
        fail("OpenBao control-plane business catalogue mismatch")

    mount_plan = control.get("mountPlan", {})
    if mount_plan.get("kvV2PerBusiness") != "kv-<business>/":
        fail("OpenBao KV mount pattern mismatch")
    if mount_plan.get("transitDedicatedBeyvra") != "transit-beyvra/":
        fail("OpenBao Beyvra transit mount mismatch")

    workload = control.get("workloadRoleTemplate", {})
    if workload.get("requiredAudience") != "openbao":
        fail("OpenBao workload role audience mismatch")
    claims = workload.get("boundClaims", {})
    if set(claims) != {"codestra_business", "application", "environment"}:
        fail("OpenBao workload role must bind business, application and environment")
    if int(workload.get("tokenTtlMinutes", 0)) > 15 or int(workload.get("tokenMaximumTtlMinutes", 0)) > 60:
        fail("OpenBao workload role TTL is too broad")
    if workload.get("periodicWithoutMaximum") is not False:
        fail("unbounded periodic workload tokens are prohibited")

    policy_rules = control.get("policyRules", {})
    for field in (
        "wildcardAcrossBusinessMounts",
        "policyNameFromCustomerInput",
        "mountAdministrationForWorkloads",
        "sysRawAccessForWorkloads",
        "tokenCreationForWorkloads",
        "identityMutationForWorkloads",
    ):
        if policy_rules.get(field) is not False:
            fail(f"OpenBao policy boundary must remain false: {field}")

    pki = control.get("pkiRoles", {})
    if pki.get("allowAnyName") is not False or pki.get("allowIpSansDefault") is not False:
        fail("OpenBao PKI names must remain constrained")
    if int(pki.get("ttlHours", 0)) > 24 or int(pki.get("maxTtlHours", 0)) > 168:
        fail("OpenBao PKI TTL exceeds policy")

    beyvra = control.get("beyvra", {})
    if beyvra.get("brokerExchangeCustodyPrefixDefaultEnabled") is not False:
        fail("Beyvra broker/exchange/custody prefix must remain disabled")
    for field in ("generalAnalyticsAccess", "observabilityAccess", "n8nAccess", "exportableSigningKeys"):
        if beyvra.get(field) is not False:
            fail(f"Beyvra secret boundary must remain false: {field}")

    release_gates = control.get("releaseGates", {})
    if not release_gates or any(value is not False for value in release_gates.values()):
        fail("all OpenBao release gates must remain false")


def validate_hcl_and_policies() -> None:
    config = require_file(CONFIG)
    for fragment in (
        'storage "raft"',
        'path = "/openbao/data"',
        'listener "tcp"',
        'tls_disable = 0',
        'tls_min_version = "tls13"',
        'unauthenticated_metrics_access = false',
        'default_lease_ttl = "15m"',
        'max_lease_ttl = "1h"',
        'disable_mlock = false',
        'raw_storage_endpoint = false',
    ):
        if fragment not in config:
            fail(f"OpenBao HCL template omits control: {fragment}")
    for forbidden in (
        "tls_disable = 1",
        'tls_min_version = "tls10"',
        'tls_min_version = "tls11"',
        'tls_min_version = "tls12"',
        "disable_mlock = true",
        "unauthenticated_metrics_access = true",
        "http://",
        "token =",
    ):
        if forbidden in config:
            fail(f"OpenBao HCL template contains forbidden content: {forbidden}")

    files = {path.name for path in POLICIES.glob("*.hcl")}
    if files != POLICY_FILES:
        fail(f"OpenBao policy set mismatch: {sorted(files)}")
    business_admin = require_file(POLICIES / "business-admin-template.hcl")
    if 'path "kv-__BUSINESS__/data/*"' not in business_admin:
        fail("business administrator policy is not business-scoped")
    if 'path "kv-__BUSINESS__/destroy/*"' not in business_admin or '["deny"]' not in business_admin:
        fail("business administrator policy must deny permanent destroy")
    workload = require_file(POLICIES / "workload-read-template.hcl")
    if 'path "kv-__BUSINESS__/data/__APPLICATION__/__ENVIRONMENT__/*"' not in workload:
        fail("workload policy is not application/environment scoped")
    if 'path "auth/token/create*"' not in workload:
        fail("workload policy must explicitly deny child-token creation")
    auditor = require_file(POLICIES / "auditor.hcl")
    if 'path "kv-*/data/*"' not in auditor or 'capabilities = ["deny"]' not in auditor:
        fail("auditor policy must deny business secret values")
    beyvra = require_file(POLICIES / "beyvra-execution-template.hcl")
    if "DO NOT APPLY by default" not in beyvra:
        fail("Beyvra execution template must remain disabled by default")
    if 'path "transit-beyvra/export/*"' not in beyvra:
        fail("Beyvra policy must deny signing-key export")


def validate_upstream_import_governance() -> None:
    workflow_text = require_file(UPSTREAM_WORKFLOW)
    try:
        yaml.safe_load(workflow_text)
    except Exception as exc:
        fail(f"invalid OpenBao upstream workflow YAML: {exc}")
    for fragment in (
        "CODESTRA_UPSTREAM_SANITIZATION.json",
        "original_block_sha256",
        "PRIVATE_KEY_TEST_FIXTURE_REMOVED",
        "--base development",
        "gh pr create",
        "pull-requests: write",
    ):
        if fragment not in workflow_text:
            fail(f"OpenBao upstream importer omits governance control: {fragment}")
    for forbidden in (
        "git push origin HEAD:main",
        "git push origin HEAD:staging",
        "git push origin HEAD:production",
        "--base production",
        "--base staging",
    ):
        if forbidden in workflow_text:
            fail(f"OpenBao upstream importer contains direct environment push: {forbidden}")


def validate_docs_and_secret_safety() -> None:
    for path in (OPERATING_MODEL, CORPORATE_FEATURES):
        text = require_file(path).lower()
        for token in ("keycloak", "business", "rotation", "audit", "beyvra"):
            if token not in text:
                fail(f"OpenBao documentation {path.name} omits {token}")

    private_key_pattern = re.compile(
        r"-----BEGIN (?:OPENSSH |RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY-----",
    )
    for path in CODESTRA.rglob("*"):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if private_key_pattern.search(text):
            fail(f"private-key material found in {path.relative_to(ROOT)}")
        for signature in ("AKIA", "hvs.", "hvr.", "hvb.", "hvp."):
            if signature in text:
                fail(f"secret-shaped material found in {path.relative_to(ROOT)}")


def main() -> None:
    validate_runtime()
    validate_control_plane()
    validate_hcl_and_policies()
    validate_upstream_import_governance()
    validate_docs_and_secret_safety()
    print("Codestra OpenBao corporate configuration validation PASS")


if __name__ == "__main__":
    main()
