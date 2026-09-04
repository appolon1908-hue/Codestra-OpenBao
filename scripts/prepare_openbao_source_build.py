#!/usr/bin/env python3
"""Apply the reviewed deterministic OpenBao source-build dependency overlay.

The imported upstream tree remains byte-for-byte provenance evidence. Builds use this
small, source-controlled transform to replace the vulnerable indirect archive module.
The transform fails unless the exact reviewed old module and checksum records exist.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

OLD_VERSION = "v0.2.0"
NEW_VERSION = "v0.3.2"
MODULE = "github.com/moby/go-archive"
OLD_MOD_LINE = f"\t{MODULE} {OLD_VERSION} // indirect"
NEW_MOD_LINE = f"\t{MODULE} {NEW_VERSION} // indirect"
OLD_SUM_LINES = (
    f"{MODULE} {OLD_VERSION} h1:zg5QDUM2mi0JIM9fdQZWC7U8+2ZfixfTYoHL7rWUcP8=",
    f"{MODULE} {OLD_VERSION}/go.mod h1:mNeivT14o8xU+5q1YnNrkQVpK+dnNe/K6fHqnTg4qPU=",
)
NEW_SUM_LINES = (
    f"{MODULE} {NEW_VERSION} h1:x893kC3zRygv2C+k4Y9kMxYRPLCj4XEJB0srbAP06Hw=",
    f"{MODULE} {NEW_VERSION}/go.mod h1:Npdv43fFqlhZW7Xo8fbm3ZMYFvAGNviUPqX21VERbcE=",
)


def fail(message: str) -> None:
    print(f"OPENBAO_SOURCE_BUILD_PATCH_ERROR={message}", file=sys.stderr)
    raise SystemExit(1)


def replace_exactly_once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        fail(f"{label} expected exactly once, found {count}")
    return text.replace(old, new, 1)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def apply(source_root: Path, report: Path | None = None) -> dict[str, object]:
    go_mod = source_root / "go.mod"
    go_sum = source_root / "go.sum"
    if not go_mod.is_file() or not go_sum.is_file():
        fail("source root must contain go.mod and go.sum")

    original_mod = go_mod.read_text(encoding="utf-8")
    original_sum = go_sum.read_text(encoding="utf-8")
    if NEW_MOD_LINE in original_mod or any(line in original_sum for line in NEW_SUM_LINES):
        fail("build overlay appears to have been applied already")

    updated_mod = replace_exactly_once(
        original_mod, OLD_MOD_LINE, NEW_MOD_LINE, "go.mod archive requirement"
    )
    updated_sum = original_sum
    for old, new in zip(OLD_SUM_LINES, NEW_SUM_LINES, strict=True):
        updated_sum = replace_exactly_once(
            updated_sum, old, new, "go.sum archive checksum"
        )

    go_mod.write_text(updated_mod, encoding="utf-8")
    go_sum.write_text(updated_sum, encoding="utf-8")

    if updated_mod.count(NEW_MOD_LINE) != 1:
        fail("updated go.mod does not contain the exact security-fixed requirement")
    if any(updated_sum.count(line) != 1 for line in NEW_SUM_LINES):
        fail("updated go.sum does not contain exact security-fixed checksums")
    if OLD_MOD_LINE in updated_mod or any(line in updated_sum for line in OLD_SUM_LINES):
        fail("vulnerable archive module records remain after transform")

    evidence: dict[str, object] = {
        "schema_version": 1,
        "status": "PASS",
        "module": MODULE,
        "old_version": OLD_VERSION.removeprefix("v"),
        "new_version": NEW_VERSION.removeprefix("v"),
        "go_mod_sha256_before": hashlib.sha256(original_mod.encode()).hexdigest(),
        "go_mod_sha256_after": sha256(go_mod),
        "go_sum_sha256_before": hashlib.sha256(original_sum.encode()).hexdigest(),
        "go_sum_sha256_after": sha256(go_sum),
        "source_tree_modified_for_build_only": True,
        "repository_source_mutated": False,
    }
    if report is not None:
        report.parent.mkdir(parents=True, exist_ok=True)
        report.write_text(
            json.dumps(evidence, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, default=Path("upstream"))
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    evidence = apply(args.source_root, args.report)
    print(f"OPENBAO_ARCHIVE_MODULE={evidence['module']}")
    print(f"OPENBAO_ARCHIVE_VERSION={evidence['new_version']}")
    print("OPENBAO_SOURCE_BUILD_PATCH=PASS")
    return 0


if __name__ == "__main__":
    main()
