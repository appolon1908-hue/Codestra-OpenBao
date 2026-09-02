from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "openbao_validator", ROOT / "scripts" / "validate_workload_secret_authority.py"
)
assert SPEC is not None and SPEC.loader is not None
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


class WorkloadSecretAuthorityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.policy = json.loads(VALIDATOR.POLICY.read_text(encoding="utf-8"))

    def reject(self, policy: dict) -> None:
        with self.assertRaises(SystemExit):
            VALIDATOR.validate(policy)

    def test_canonical_policy_passes(self) -> None:
        VALIDATOR.validate(copy.deepcopy(self.policy))

    def test_runtime_activation_is_rejected(self) -> None:
        policy = copy.deepcopy(self.policy)
        policy["runtimeApplyAuthorized"] = True
        self.reject(policy)

    def test_boolean_schema_version_is_rejected(self) -> None:
        policy = copy.deepcopy(self.policy)
        policy["schemaVersion"] = True
        self.reject(policy)

    def test_duplicate_json_object_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            candidate = Path(temporary_directory)
            policy_path = candidate / "config" / "workload-secret-authority.v1.json"
            policy_path.parent.mkdir()
            serialized = json.dumps(self.policy)
            policy_path.write_text(
                serialized.replace(
                    '"runtimeApplyAuthorized": false',
                    '"runtimeApplyAuthorized": true, '
                    '"runtimeApplyAuthorized": false',
                    1,
                ),
                encoding="utf-8",
            )
            with self.assertRaises(SystemExit):
                VALIDATOR.main(policy_path, candidate)

    def test_non_integer_token_lifetimes_are_rejected(self) -> None:
        for malformed_lifetime in (True, 1.5):
            with self.subTest(malformed_lifetime=malformed_lifetime):
                policy = copy.deepcopy(self.policy)
                policy["maximumTokenLifetimeSeconds"] = malformed_lifetime
                self.reject(policy)

    def test_nested_control_types_are_exact(self) -> None:
        mutations = (
            ("secretInjection", "environmentVariablesAllowed", 0),
            ("secretInjection", "agentAuthTokenRenewalRequired", 1),
            ("rotation", "maximumAgeDays", 90.0),
        )
        for section, field, malformed_value in mutations:
            with self.subTest(section=section, field=field):
                policy = copy.deepcopy(self.policy)
                policy[section][field] = malformed_value
                self.reject(policy)

    def test_workflow_has_trusted_and_candidate_validation_boundaries(self) -> None:
        workflow = (
            ROOT / ".github" / "workflows" / "workload-secret-authority.yml"
        ).read_text(encoding="utf-8")
        trigger = workflow.split("permissions:", maxsplit=1)[0]
        assert "pull_request: {}" in trigger
        assert "pull_request_target:" in trigger
        assert "paths:" not in trigger
        assert "fetch-depth: 0" in workflow
        assert "gitleaks dir" not in workflow
        assert "git --redact --no-banner" in workflow
        assert (
            '--log-opts="${scan_base}..${OPENBAO_SOURCE_SHA} '
            '--diff-merges=first-parent"' in workflow
        )
        assert 'test -d "$PWD/candidate/.git"' in workflow
        assert 'git -C candidate rev-list --count' in workflow
        assert 'git -C candidate diff --check' in workflow
        security_job = workflow.index("  trusted-source-security:")
        candidate_security_job = workflow.index("  candidate-source-security:")
        validation_job = workflow.index("  candidate-validation:")
        scanner = workflow.index("Reject secrets across exact commit range")
        validator = workflow.index("Validate authority and mutation coverage")
        assert security_job < scanner < candidate_security_job < validation_job < validator
        trusted = workflow[security_job:candidate_security_job]
        candidate = workflow[validation_job:]
        assert "if: github.event_name != 'pull_request'" in trusted
        assert "if: github.event_name == 'pull_request'" in candidate
        assert "Check out untrusted candidate as data" in trusted
        assert "Check out trusted validator" in trusted
        assert "Validate candidate policy with trusted base code" in trusted
        assert "python3 trusted/scripts/validate_workload_secret_authority.py" in trusted
        assert "python3 candidate/" not in trusted
        assert "test ! -L candidate/config" in trusted
        assert "candidate_root=\"$(realpath -e candidate)\"" in trusted
        assert "policy_path=\"$(realpath -e candidate/config/" in trusted
        assert (
            'test "$policy_path" = \\\n'
            '            "$candidate_root/config/workload-secret-authority.v1.json"'
            in trusted
        )
        assert '--volume "$PWD/trusted:/trusted:ro"' in trusted
        assert "--config=/trusted/.github/gitleaks-trusted.toml" in trusted
        assert (
            "--gitleaks-ignore-path=/trusted/.github/gitleaks-trusted.ignore"
            in trusted
        )
        assert "--ignore-gitleaks-allow" in trusted
        assert "--config=/repo/.gitleaks.toml" not in trusted
        assert "needs: candidate-source-security" in candidate
        assert "python3 scripts/validate_workload_secret_authority.py" in candidate

    def test_symlinked_policy_ancestor_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            candidate = temporary_root / "candidate"
            trusted_config = temporary_root / "trusted" / "config"
            candidate.mkdir()
            trusted_config.mkdir(parents=True)
            trusted_policy = trusted_config / "workload-secret-authority.v1.json"
            trusted_policy.write_text("{}", encoding="utf-8")
            (candidate / "config").symlink_to(trusted_config, target_is_directory=True)
            with self.assertRaises(SystemExit):
                VALIDATOR.resolve_policy_path(
                    candidate,
                    candidate / "config" / "workload-secret-authority.v1.json",
                )

    def test_cross_environment_path_is_rejected(self) -> None:
        policy = copy.deepcopy(self.policy)
        role = next(item for item in policy["roles"] if item["environment"] == "staging")
        role["pathPrefixes"] = ["codestra/production/middleware/"]
        self.reject(policy)

    def test_environment_claim_drift_is_rejected(self) -> None:
        policy = copy.deepcopy(self.policy)
        role = next(item for item in policy["roles"] if item["environment"] == "staging")
        role["boundClaims"]["codestra_environment"] = "production"
        self.reject(policy)

    def test_environment_root_path_is_rejected(self) -> None:
        policy = copy.deepcopy(self.policy)
        role = next(item for item in policy["roles"] if item["environment"] == "production")
        role["pathPrefixes"] = ["codestra/production/"]
        self.reject(policy)

    def test_cross_service_path_is_rejected(self) -> None:
        policy = copy.deepcopy(self.policy)
        role = next(
            item for item in policy["roles"]
            if item["serviceIdentity"] == "kong-gateway"
            and item["environment"] == "production"
        )
        role["pathPrefixes"] = ["codestra/production/middleware/api/"]
        self.reject(policy)

    def test_wildcard_path_is_rejected(self) -> None:
        policy = copy.deepcopy(self.policy)
        policy["roles"][0]["pathPrefixes"] = ["codestra/production/*/"]
        self.reject(policy)

    def test_n8n_provider_secret_access_is_rejected(self) -> None:
        policy = copy.deepcopy(self.policy)
        role = next(
            item for item in policy["roles"]
            if item["environment"] == "production"
            and item["serviceIdentity"] == "n8n-automation"
        )
        role["pathPrefixes"] = ["codestra/production/telnexa/"]
        self.reject(policy)

    def test_plaintext_environment_injection_is_rejected(self) -> None:
        policy = copy.deepcopy(self.policy)
        policy["secretInjection"]["environmentVariablesAllowed"] = True
        self.reject(policy)

    def test_static_kv_lease_model_drift_is_rejected(self) -> None:
        policy = copy.deepcopy(self.policy)
        policy["secretInjection"]["staticKvSecretLeaseRenewalRequired"] = True
        self.reject(policy)

        policy = copy.deepcopy(self.policy)
        policy["secretInjection"]["staticKvRerenderOnChangeRequired"] = False
        self.reject(policy)

        policy = copy.deepcopy(self.policy)
        policy["secretInjection"]["agentAuthTokenRenewalRequired"] = False
        self.reject(policy)

    def test_dynamic_secret_lease_controls_are_required(self) -> None:
        policy = copy.deepcopy(self.policy)
        policy["secretInjection"]["dynamicSecretLeaseRenewalRequired"] = False
        self.reject(policy)

        policy = copy.deepcopy(self.policy)
        policy["secretInjection"]["dynamicSecretRevocationOnShutdownRequired"] = False
        self.reject(policy)

    def test_static_and_dynamic_evidence_are_distinguished(self) -> None:
        for required in (
            "agent_auth_token_accessor_hash",
            "secret_version",
            "dynamic_lease_id_hash_if_applicable",
        ):
            policy = copy.deepcopy(self.policy)
            policy["requiredEvidence"].remove(required)
            self.reject(policy)

    def test_cross_service_wildcard_role_is_rejected(self) -> None:
        policy = copy.deepcopy(self.policy)
        policy["roles"][0]["serviceIdentity"] = "all-services"
        self.reject(policy)


if __name__ == "__main__":
    unittest.main()
