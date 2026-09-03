#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "validate_grpc_go_exact_image_gate.py"
SPEC = importlib.util.spec_from_file_location("grpc_gate", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class GrpcGoExactImageGateTests(unittest.TestCase):
    def test_version_ordering(self) -> None:
        self.assertLess(MODULE.version_tuple("1.82.1"), MODULE.version_tuple("1.83.1"))
        self.assertEqual(MODULE.version_tuple("1.83.1"), (1, 83, 1))
        self.assertGreater(MODULE.version_tuple("1.84.0"), MODULE.version_tuple("1.83.1"))

    def test_nonempty_reference_rejects_placeholders(self) -> None:
        self.assertFalse(MODULE.nonempty_reference(None))
        self.assertFalse(MODULE.nonempty_reference(""))
        self.assertFalse(MODULE.nonempty_reference("REPLACE_WITH_SBOM"))
        self.assertTrue(MODULE.nonempty_reference("artifact://sbom/openbao.spdx.json"))

    def test_source_module_declares_exactly_one_grpc_version(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "go.mod"
            path.write_text(
                "module example.test/openbao\n\nrequire google.golang.org/grpc v1.83.1\n",
                encoding="utf-8",
            )
            self.assertEqual(MODULE.parse_source_version(path), "1.83.1")

    def test_gate_is_fail_closed_in_repository(self) -> None:
        gate_path = ROOT / "codestra" / "vulnerability-gates" / "grpc-go-cve-2026-84304.v1.json"
        gate = json.loads(gate_path.read_text(encoding="utf-8"))
        self.assertEqual(gate["exact_image_gate"], "BLOCKED")
        self.assertIsNone(gate["exact_image_digest"])
        self.assertTrue(all(value is False for value in gate["activation"].values()))
        self.assertFalse(gate["vex"]["runtime_authority_allowed"])
        self.assertFalse(gate["vex"]["temporary_source_only_disposition_allowed"])


if __name__ == "__main__":
    unittest.main()
