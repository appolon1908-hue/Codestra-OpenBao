import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class RuntimeIntegrationContractTests(unittest.TestCase):
    def test_ci_runs_policy_and_stateful_replay_integrations(self) -> None:
        workflow = (ROOT / ".github/workflows/policy-tests.yml").read_text()
        self.assertIn("scripts/integration_test.sh", workflow)
        self.assertIn("scripts/integration_test_jti_plugin.sh", workflow)

        replay = (ROOT / "scripts/integration_test_jti_plugin.sh").read_text()
        for marker in (
            "JWT_SEQUENTIAL_REPLAY=DENIED",
            "JWT_CONCURRENT_SUCCESS_COUNT=",
            "JWT_CONCURRENT_DENY_COUNT=",
            "JWT_NEGATIVE_SECURITY=PASS",
            "WORKLOAD_AUTHORIZED_PATH=PASS",
            "CROSS_SERVICE_ACCESS=DENIED",
            "CROSS_ENVIRONMENT_ACCESS=DENIED",
            "ANONYMOUS_ACCESS=DENIED",
            "SYSTEM_ADMIN_ACCESS=DENIED",
            "PATH_TRAVERSAL_ACCESS=DENIED",
        ):
            self.assertIn(marker, replay)
        for negative in (
            "wrongIssuer",
            "wrongAudience",
            "wrongEnvironment",
            "wrongClient",
            "expired",
            "overlong",
            "futureIssuedAt",
            "missingSubject",
            "missingJTI",
        ):
            self.assertIn(negative, replay)


if __name__ == "__main__":
    unittest.main()
