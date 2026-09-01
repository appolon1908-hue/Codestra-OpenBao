from __future__ import annotations

import json
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


class MonitoringContractTests(unittest.TestCase):
    def test_prometheus_uses_private_mtls_and_file_token(self) -> None:
        config = yaml.safe_load((ROOT / "monitoring/prometheus/openbao-scrape.yml").read_text())
        job = config["scrape_configs"][0]
        self.assertEqual(job["scheme"], "https")
        self.assertEqual(job["authorization"]["credentials_file"], "/run/secrets/openbao-prometheus-token")
        self.assertFalse(job["tls_config"]["insecure_skip_verify"])
        self.assertNotIn("bearer_token", job)
        self.assertEqual(job["static_configs"][0]["targets"], ["codestra-bao-production-01:8200"])

    def test_alerts_cover_required_failures_without_secret_labels(self) -> None:
        source = (ROOT / "monitoring/alerts/openbao-alerts.yml").read_text()
        alerts = yaml.safe_load(source)["groups"][0]["rules"]
        names = {item["alert"] for item in alerts}
        self.assertTrue({
            "OpenBaoSealed", "OpenBaoNoActiveLeader", "OpenBaoAuditRequestFailure",
            "OpenBaoAuthFailureSurge", "OpenBaoBackupStale", "OpenBaoBackupFailure",
            "OpenBaoRotationFailure", "OpenBaoRevocationFailure", "OpenBaoDriftDetected",
        } <= names)
        for forbidden in ("secret_value", "client_secret", "root_token", "unseal_key"):
            self.assertNotIn(forbidden, source.lower())

    def test_dashboard_is_read_only_and_source_backed(self) -> None:
        dashboard = json.loads((ROOT / "monitoring/dashboards/codestra-openbao.json").read_text())
        self.assertFalse(dashboard["editable"])
        self.assertGreaterEqual(len(dashboard["panels"]), 8)
        self.assertEqual(dashboard["uid"], "codestra-openbao-v1")


if __name__ == "__main__":
    unittest.main(verbosity=2)
