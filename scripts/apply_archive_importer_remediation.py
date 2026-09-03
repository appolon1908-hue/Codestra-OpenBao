#!/usr/bin/env python3
"""Apply the reviewed archive-integrity hook to the persistent upstream importer.

This is a deterministic, one-shot source transformation. Every insertion is
anchored to an exact unique source fragment and the resulting workflow is
checked for the complete fail-closed contract.
"""

from __future__ import annotations

from pathlib import Path

WORKFLOW = Path(".github/workflows/upstream-source-sync.yml")


def replace_once(text: str, source: str, replacement: str, label: str) -> str:
    count = text.count(source)
    if count != 1:
        raise RuntimeError(f"{label}: expected one source occurrence, found {count}")
    return text.replace(source, replacement, 1)


def apply() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    text = replace_once(
        text,
        "      - .github/workflows/upstream-source-sync.yml\n",
        "      - .github/workflows/upstream-source-sync.yml\n"
        "      - scripts/repair_upstream_archive_integrity.py\n",
        "workflow trigger path",
    )
    text = replace_once(
        text,
        "          import hashlib, json, os, re, subprocess, tempfile\n",
        "          import hashlib, json, os, re, subprocess, sys, tempfile\n",
        "inline importer sys import",
    )
    text = replace_once(
        text,
        "          from pathlib import Path\n\n          sanitizations=[]\n",
        "          from pathlib import Path\n\n"
        "          sys.path.insert(0, str((Path.cwd() / 'scripts').resolve(strict=True)))\n"
        "          from repair_upstream_archive_integrity import repair_known_upstream_archives\n\n"
        "          sanitizations=[]\n",
        "archive repair module import",
    )

    scanner_marker = (
        "          # Run the exact pinned scanner used by required CI. Its default rules\n"
    )
    repair_block = """          raw_archive_integrity_repairs = repair_known_upstream_archives(
              Path('upstream'),
              repository_root=workspace_root,
          )
          manifested_paths = {item['path'] for item in sanitizations}
          archive_integrity_repairs = []
          for repair in raw_archive_integrity_repairs:
              if repair['changed'] and repair['repository_path'] not in manifested_paths:
                  raise RuntimeError(
                      'archive checksum repair changed a path without a prior sanitization record: '
                      + repair['repository_path']
                  )
              archive_integrity_repairs.append({
                  'archive': repair['repository_path'],
                  'archive_sha256_after': repair['archive_sha256_after'],
                  'archive_sha256_before': repair['archive_sha256_before'],
                  'archive_size_preserved': repair['archive_size_preserved'],
                  'focused_test': repair['focused_test'],
                  'member': repair['member'],
                  'member_order_and_metadata_preserved': (
                      repair['member_order_preserved']
                      and repair['member_metadata_preserved']
                  ),
                  'member_payloads_changed': (
                      [repair['checksum_member']] if repair['changed'] else []
                  ),
                  'reason': (
                      'recompute embedded SHA256SUMS after deterministic '
                      'private-key fixture sanitization'
                  ),
                  'sanitized_member_sha256': repair['actual_sha256'],
                  'secret_values_recorded': False,
                  'stale_embedded_sha256': repair['stale_sha256'],
              })

"""
    text = replace_once(
        text,
        scanner_marker,
        repair_block + scanner_marker,
        "archive repair invocation",
    )
    text = replace_once(
        text,
        "              'sanitization_count': len(sanitizations),\n"
        "              'sanitization_scope':",
        "              'sanitization_count': len(sanitizations),\n"
        "              'archive_integrity_repairs': archive_integrity_repairs,\n"
        "              'archive_integrity_verified': all(\n"
        "                  item['archive_size_preserved']\n"
        "                  and item['member_order_and_metadata_preserved']\n"
        "                  and item['secret_values_recorded'] is False\n"
        "                  for item in archive_integrity_repairs\n"
        "              ),\n"
        "              'sanitization_scope':",
        "archive repair lock evidence",
    )

    required = (
        "scripts/repair_upstream_archive_integrity.py",
        "from repair_upstream_archive_integrity import repair_known_upstream_archives",
        "raw_archive_integrity_repairs = repair_known_upstream_archives(",
        "if repair['changed'] and repair['repository_path'] not in manifested_paths:",
        "'archive_integrity_repairs': archive_integrity_repairs",
        "'archive_integrity_verified': all(",
    )
    for statement in required:
        if text.count(statement) != 1:
            raise RuntimeError(
                f"resulting importer contract is not unique: {statement!r}"
            )
    WORKFLOW.write_text(text, encoding="utf-8")


if __name__ == "__main__":
    apply()
