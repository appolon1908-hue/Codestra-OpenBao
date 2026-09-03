#!/usr/bin/env python3
"""Fail-closed source and exact-image gate for CVE-2026-84304."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
GATE_PATH = ROOT / "codestra" / "vulnerability-gates" / "grpc-go-cve-2026-84304.v1.json"
VERSION_RE = re.compile(r"(?m)^\s*google\.golang\.org/grpc\s+v(\d+\.\d+\.\d+)(?:\s|$)")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def fail(message: str) -> None:
    print(f"OPENBAO_GRPC_GO_GATE_ERROR={message}", file=sys.stderr)
    raise SystemExit(1)


def version_tuple(value: str) -> tuple[int, int, int]:
    if not re.fullmatch(r"\d+\.\d+\.\d+", value):
        fail(f"invalid semantic version: {value}")
    return tuple(int(part) for part in value.split("."))  # type: ignore[return-value]


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot parse {path.relative_to(ROOT)}: {exc}")
    if not isinstance(value, dict):
        fail(f"{path.relative_to(ROOT)} must contain an object")
    return value


def parse_source_version(path: Path) -> str:
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as exc:
        fail(f"cannot read {path.relative_to(ROOT)}: {exc}")
    matches = VERSION_RE.findall(content)
    if len(matches) != 1:
        fail(f"expected exactly one grpc-go module declaration, found {len(matches)}")
    return matches[0]


def nonempty_reference(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip()) and "REPLACE" not in value.upper()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--require-remediated-image", action="store_true")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()

    gate = load_json(GATE_PATH)
    if gate.get("schema_version") != 1 or gate.get("cve") != "CVE-2026-84304":
        fail("gate identity mismatch")
    if gate.get("module") != "google.golang.org/grpc":
        fail("module authority mismatch")

    minimum = str(gate.get("minimum_remediated_version", ""))
    source_path = ROOT / str(gate.get("source_module_file", ""))
    source_version = parse_source_version(source_path)
    source_remediated = version_tuple(source_version) >= version_tuple(minimum)

    activation = gate.get("activation")
    if not isinstance(activation, dict) or not activation:
        fail("activation map must be a non-empty object")
    enabled = sorted(name for name, value in activation.items() if value is not False)
    if enabled:
        fail(f"runtime activation must remain false until exact-image proof: {enabled}")

    vex = gate.get("vex")
    if not isinstance(vex, dict):
        fail("VEX boundary is missing")
    if vex.get("temporary_source_only_disposition_allowed") is not False:
        fail("temporary source-only VEX may not authorize this production image gate")
    if vex.get("runtime_authority_allowed") is not False:
        fail("VEX may not authorize runtime activation")
    expiry_text = str(vex.get("expires_at", ""))
    try:
        expiry = dt.datetime.fromisoformat(expiry_text.replace("Z", "+00:00"))
    except ValueError as exc:
        fail(f"invalid VEX expiry: {exc}")
    if expiry.tzinfo is None:
        fail("VEX expiry must be timezone-aware")

    digest = gate.get("exact_image_digest")
    image_version = gate.get("image_dependency_version")
    image_remediated = (
        isinstance(image_version, str)
        and re.fullmatch(r"\d+\.\d+\.\d+", image_version) is not None
        and version_tuple(image_version) >= version_tuple(minimum)
    )
    artifact_fields = (
        "image_sbom_reference",
        "image_provenance_reference",
        "image_signature_reference",
        "image_scan_reference",
    )
    artifact_complete = all(nonempty_reference(gate.get(name)) for name in artifact_fields)
    image_complete = bool(DIGEST_RE.fullmatch(str(digest or ""))) and image_remediated and artifact_complete

    if gate.get("source_dependency_gate") == "PASS" and not source_remediated:
        fail("source dependency gate claims PASS below the remediated version")
    if gate.get("exact_image_gate") == "PASS" and not image_complete:
        fail("exact image gate claims PASS without digest, remediated SBOM, provenance, signature and scan")

    report = {
        "schema_version": 1,
        "cve": gate["cve"],
        "minimum_remediated_version": minimum,
        "source_dependency_version": source_version,
        "source_dependency_remediated": source_remediated,
        "exact_image_digest_present": bool(DIGEST_RE.fullmatch(str(digest or ""))),
        "image_dependency_version": image_version,
        "image_dependency_remediated": image_remediated,
        "artifact_evidence_complete": artifact_complete,
        "exact_image_gate_complete": image_complete,
        "runtime_activation_authorized": False,
    }
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(f"OPENBAO_GRPC_GO_SOURCE_VERSION={source_version}")
    print(f"OPENBAO_GRPC_GO_SOURCE_REMEDIATED={'PASS' if source_remediated else 'FAIL'}")
    print(f"OPENBAO_GRPC_GO_EXACT_IMAGE_GATE={'PASS' if image_complete else 'BLOCKED'}")
    print("OPENBAO_RUNTIME_ACTIVATION=NO")
    if args.require_remediated_image and not image_complete:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
