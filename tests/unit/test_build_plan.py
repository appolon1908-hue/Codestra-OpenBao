from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts/build_plan.py"
SPEC = importlib.util.spec_from_file_location("build_plan", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class BuildPlanTests(unittest.TestCase):
    def live(self) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        (root / "policies").mkdir()
        (root / "jwt-roles").mkdir()
        for name, value in {
            "mounts.json": {}, "auth.json": {}, "audit.json": {},
            "policies.json": [], "jwt-config.json": {}, "jwt-roles.json": [],
            "plugin-info.json": {},
        }.items():
            (root / name).write_text(json.dumps(value), encoding="utf-8")
        return root

    def test_empty_runtime_creates_without_destroy(self) -> None:
        plan = MODULE.build("development", self.live(), "a" * 40)
        self.assertGreater(plan["counts"]["create"], 0)
        self.assertEqual(plan["counts"]["destroy"], 0)
        self.assertTrue(plan["planOnly"])
        self.assertFalse(plan["runtimeApplyAuthorized"])
        self.assertFalse(any(item["action"] == "delete" for item in plan["operations"]))
        plugin = next(item for item in plan["operations"] if item["kind"] == "auth_plugin")
        self.assertEqual(plugin["payload"]["sha256"], "609c33db8bcbedc8a3e37ed336efe635cb9ef00b6a633fa91f8f2fd08d2d1db3")
        auth = next(item for item in plan["operations"] if item["kind"] == "auth_method")
        self.assertEqual(auth["payload"]["plugin_name"], "codestra-jwt-replay")

    def test_incompatible_mount_warns_and_never_replaces(self) -> None:
        live = self.live()
        (live / "mounts.json").write_text(json.dumps({"codestra/": {"type": "database"}}))
        plan = MODULE.build("test", live, "b" * 40)
        self.assertTrue(any("replacement is prohibited" in warning for warning in plan["warnings"]))
        self.assertFalse(any(item["kind"] == "secret_engine" for item in plan["operations"]))
        self.assertEqual(plan["counts"]["destroy"], 0)

    def test_environment_plan_contains_only_environment_roles(self) -> None:
        plan = MODULE.build("staging", self.live(), "c" * 40)
        names = [item["name"] for item in plan["operations"] if item["kind"] in {"policy", "jwt_role"}]
        self.assertTrue(names)
        self.assertTrue(all("staging" in name for name in names))
        self.assertFalse(any("production" in name for name in names))

    def test_builtin_jwt_mount_is_never_replaced_or_configured(self) -> None:
        live = self.live()
        (live / "auth.json").write_text(json.dumps({"jwt-codestra/": {"type": "jwt"}}))
        plan = MODULE.build("staging", live, "d" * 40)
        self.assertTrue(any("automatic replacement is prohibited" in item for item in plan["warnings"]))
        self.assertFalse(any(item["kind"] in {"auth_method", "auth_config", "jwt_role"} for item in plan["operations"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
