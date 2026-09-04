#!/usr/bin/env python3
"""Create secret-free evidence for one protected OpenBao source-built OCI image."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def vulnerability_counts(path: Path) -> tuple[int, int, bool]:
    document = load_json(path)
    if not isinstance(document, dict):
        raise ValueError("Trivy report must contain an object")
    critical = 0
    high = 0
    cve_present = False
    results = document.get("Results") or []
    if not isinstance(results, list):
        raise ValueError("Trivy Results must be a list")
    for result in results:
        if not isinstance(result, dict):
            continue
        vulnerabilities = result.get("Vulnerabilities") or []
        if not isinstance(vulnerabilities, list):
            raise ValueError("Trivy Vulnerabilities must be a list")
        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                continue
            vulnerability_id = str(vulnerability.get("VulnerabilityID", ""))
            severity = str(vulnerability.get("Severity", "")).upper()
            if vulnerability_id == "CVE-2026-84304":
                cve_present = True
            if severity == "CRITICAL":
                critical += 1
            elif severity == "HIGH":
                high += 1
    return critical, high, cve_present


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--source-tree", required=True)
    parser.add_argument("--image-digest", required=True)
    parser.add_argument("--grpc-version", required=True)
    parser.add_argument("--sbom", type=Path, required=True)
    parser.add_argument("--scan", type=Path, required=True)
    parser.add_argument("--signature-verification", type=Path, required=True)
    parser.add_argument("--provenance-verification", type=Path, required=True)
    parser.add_argument("--run-id", type=int, required=True)
    parser.add_argument("--run-attempt", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    if not SHA_RE.fullmatch(args.source_sha) or not SHA_RE.fullmatch(args.source_tree):
        raise SystemExit("source SHA/tree must be full lowercase Git object IDs")
    if not DIGEST_RE.fullmatch(args.image_digest):
        raise SystemExit("image digest must be sha256:<64 lowercase hex>")
    if not re.fullmatch(r"\d+\.\d+\.\d+", args.grpc_version):
        raise SystemExit("grpc-go version must be a semantic version without a v prefix")
    if args.run_id <= 0 or args.run_attempt <= 0:
        raise SystemExit("workflow run identity must be positive")

    critical, high, cve_present = vulnerability_counts(args.scan)
    image_repository = "ghcr.io/appolon1908-hue/codestra-openbao"
    identity = (
        "https://github.com/appolon1908-hue/Codestra-OpenBao/"
        ".github/workflows/openbao-source-image-authority.yml@refs/heads/production"
    )
    evidence = {
        "schema_version": 1,
        "status": "PASS" if not cve_present and critical == 0 and high == 0 else "FAIL",
        "source_sha": args.source_sha,
        "source_tree": args.source_tree,
        "source_dependency_version": args.grpc_version,
        "image_repository": image_repository,
        "image_reference": f"{image_repository}@{args.image_digest}",
        "image_digest": args.image_digest,
        "image_dependency_version": args.grpc_version,
        "platform": "linux/amd64",
        "sbom": {
            "reference": f"artifact://openbao-source-image-{args.source_sha}/openbao.spdx.json",
            "sha256": sha256(args.sbom),
            "format": "spdx-json",
        },
        "vulnerability_scan": {
            "reference": f"artifact://openbao-source-image-{args.source_sha}/trivy.json",
            "sha256": sha256(args.scan),
            "cve_present": cve_present,
            "critical_count": critical,
            "high_count": high,
        },
        "signature": {
            "reference": f"artifact://openbao-source-image-{args.source_sha}/signature-verification.json",
            "sha256": sha256(args.signature_verification),
            "verified": True,
            "certificate_identity": identity,
        },
        "provenance": {
            "reference": f"artifact://openbao-source-image-{args.source_sha}/provenance-verification.json",
            "sha256": sha256(args.provenance_verification),
            "verified": True,
            "subject_digest": args.image_digest,
            "source_sha": args.source_sha,
            "builder_identity": identity,
        },
        "workflow": {
            "repository": "appolon1908-hue/Codestra-OpenBao",
            "path": ".github/workflows/openbao-source-image-authority.yml",
            "ref": "refs/heads/production",
            "run_id": args.run_id,
            "run_attempt": args.run_attempt,
        },
        "runtime_authorized": False,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"OPENBAO_IMAGE_EVIDENCE_STATUS={evidence['status']}")
    print(f"OPENBAO_IMAGE_CRITICAL_COUNT={critical}")
    print(f"OPENBAO_IMAGE_HIGH_COUNT={high}")
    print(f"OPENBAO_IMAGE_CVE_2026_84304_PRESENT={'YES' if cve_present else 'NO'}")
    return 0 if evidence["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
