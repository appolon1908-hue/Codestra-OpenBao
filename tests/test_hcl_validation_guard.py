#!/usr/bin/env python3
"""Regression tests for deterministic OpenBao HCL validation."""

from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class HclValidationGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = (ROOT / "scripts/validate_hcl.sh").read_text(encoding="utf-8")

    def test_exact_image_is_pulled_before_bounded_startup(self) -> None:
        pull = self.source.index(
            'timeout --signal=TERM 120s docker pull --platform linux/amd64 "$image"'
        )
        startup = self.source.index(
            'timeout --signal=TERM 8s docker run --rm --pull=never --platform linux/amd64'
        )
        self.assertLess(pull, startup)
        self.assertIn('docker image inspect "$image" >/dev/null', self.source)

    def test_server_probe_does_not_hide_pull_or_startup_failure(self) -> None:
        self.assertIn("OpenBao image pull failed with status", self.source)
        self.assertIn(
            "OpenBao server did not reach the started state inside the bounded probe.",
            self.source,
        )
        self.assertIn("sed -n '1,80p'", self.source)

    def test_all_runtime_validation_uses_local_exact_image(self) -> None:
        self.assertEqual(self.source.count("--pull=never"), 2)
        self.assertEqual(self.source.count("--platform linux/amd64"), 3)
        self.assertIn(
            "ghcr.io/openbao/openbao@sha256:e29524ba7c3f20d01f562c481e3eccbad6c91df45a2f2531433da4951e408cff",
            self.source,
        )

    def test_container_keeps_least_privilege_boundary(self) -> None:
        self.assertIn("--cap-drop ALL", self.source)
        self.assertIn('--user "$(id -u):$(id -g)"', self.source)
        self.assertIn("--entrypoint bao", self.source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
