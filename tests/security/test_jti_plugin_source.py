from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class JtiPluginSourceTests(unittest.TestCase):
    def test_plugin_is_exact_upstream_wrapper_with_transactional_hash_cache(self) -> None:
        source = (ROOT / "plugins/codestra-jwt-replay/backend.go").read_text(encoding="utf-8")
        for required in (
            "jwtauth.Factory",
            "response.Auth == nil",
            "sha256.Sum256",
            "logical.StartTxStorage",
            "logical.EndTxStorage",
            "physical.ErrTransactionCommitFailure",
            'logical.ErrorResponse("JWT replay rejected")',
        ):
            self.assertIn(required, source)
        self.assertNotIn('json:"jti"', source)
        self.assertIn("digest := claimKey(claims)", source)

    def test_plugin_manifest_locks_reproducible_binary_but_remains_runtime_disabled(self) -> None:
        manifest = json.loads(
            (ROOT / "plugins/codestra-jwt-replay/plugin.v1.json").read_text(encoding="utf-8")
        )
        self.assertEqual(manifest["upstreamSha"], "dd9c19c37a878cf4a81b18efb8d6f0599c7da923")
        self.assertEqual(
            manifest["binarySha256"],
            "609c33db8bcbedc8a3e37ed336efe635cb9ef00b6a633fa91f8f2fd08d2d1db3",
        )
        self.assertEqual(manifest["goVersion"], "1.25.13")
        self.assertEqual(manifest["securityDependencyOverride"]["version"], "v0.55.0")
        self.assertGreaterEqual(manifest["reproducibleBuildsVerified"], 2)
        self.assertEqual(manifest["sequentialReplayTest"], "PASS")
        self.assertEqual(manifest["concurrentReplayTest"], "PASS")
        self.assertEqual(manifest["negativeClaimTests"], "PASS")
        self.assertFalse(manifest["runtimeApplyAuthorized"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
