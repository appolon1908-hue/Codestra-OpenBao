#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "prepare_openbao_source_build.py"
SPEC = importlib.util.spec_from_file_location("source_build_patch", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class SourceBuildPatchTests(unittest.TestCase):
    def create_source(self, directory: str) -> Path:
        source = Path(directory)
        source.joinpath("go.mod").write_text(
            "module example.test/openbao\n\nrequire (\n"
            + MODULE.OLD_MOD_LINE
            + "\n)\n",
            encoding="utf-8",
        )
        source.joinpath("go.sum").write_text(
            "unrelated.example/module v1.0.0 h1:example=\n"
            + "\n".join(MODULE.OLD_SUM_LINES)
            + "\n",
            encoding="utf-8",
        )
        return source

    def test_exact_transform_replaces_module_and_checksums(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = self.create_source(directory)
            evidence = MODULE.apply(source)
            self.assertEqual(evidence["status"], "PASS")
            self.assertEqual(evidence["new_version"], "0.3.2")
            go_mod = source.joinpath("go.mod").read_text(encoding="utf-8")
            go_sum = source.joinpath("go.sum").read_text(encoding="utf-8")
            self.assertIn(MODULE.NEW_MOD_LINE, go_mod)
            self.assertNotIn(MODULE.OLD_MOD_LINE, go_mod)
            for line in MODULE.NEW_SUM_LINES:
                self.assertIn(line, go_sum)
            for line in MODULE.OLD_SUM_LINES:
                self.assertNotIn(line, go_sum)

    def test_transform_rejects_unexpected_upstream_version(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = self.create_source(directory)
            source.joinpath("go.mod").write_text(
                source.joinpath("go.mod").read_text().replace("v0.2.0", "v0.2.1"),
                encoding="utf-8",
            )
            with self.assertRaises(SystemExit):
                MODULE.apply(source)

    def test_transform_cannot_run_twice(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = self.create_source(directory)
            MODULE.apply(source)
            with self.assertRaises(SystemExit):
                MODULE.apply(source)

    def test_missing_checksum_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = self.create_source(directory)
            content = source.joinpath("go.sum").read_text(encoding="utf-8")
            source.joinpath("go.sum").write_text(
                content.replace(MODULE.OLD_SUM_LINES[0] + "\n", ""),
                encoding="utf-8",
            )
            with self.assertRaises(SystemExit):
                MODULE.apply(source)


if __name__ == "__main__":
    unittest.main()
