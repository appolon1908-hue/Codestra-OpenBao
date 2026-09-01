from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class GitleaksConfigTests(unittest.TestCase):
    def test_only_exact_documented_false_positive_is_allowed(self) -> None:
        source = (ROOT / ".gitleaks.toml").read_text(encoding="utf-8")
        self.assertEqual(source.count("[[allowlists]]"), 1)
        self.assertIn("useDefault = true", source)
        self.assertIn(r"^codestra/runtime-v1/desired-state\.json$", source)
        self.assertIn(r"^15m-default-1h-maximum$", source)
        self.assertIn("Non-secret database lease policy duration", source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
