#!/usr/bin/env python3
"""Repair embedded SHA256SUMS entries after deterministic fixture sanitization.

The upstream synchronizer intentionally neutralizes secret-shaped material in
reviewed test/example/documentation fixtures. Some fixtures are tar archives
that contain both a payload and a SHA256SUMS member. A same-length payload
rewrite preserves the tar layout but makes the embedded checksum stale.

This module updates only the 64-byte hexadecimal digest inside the checksum
member. It never repacks the archive and fails closed on path, layout, member,
or checksum ambiguity.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tarfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

SHA256_RE = re.compile(rb"^[0-9a-fA-F]{64}$")
CHECKSUM_LINE_RE = re.compile(
    rb"(?m)^(?P<digest>[0-9a-fA-F]{64})(?P<separator>[ \t]+)(?P<marker>\*?)(?P<name>[^\r\n]+)$"
)


@dataclass(frozen=True)
class KnownArchive:
    relative_path: str
    payload_member: str
    checksum_member: str


KNOWN_ARCHIVES = (
    KnownArchive(
        relative_path="physical/raft/snapshot/testdata/spaces-meta.tar",
        payload_member="state.bin",
        checksum_member="SHA256SUMS",
    ),
)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _member_identity(member: tarfile.TarInfo) -> tuple[Any, ...]:
    return (
        member.name,
        member.mode,
        member.uid,
        member.gid,
        member.size,
        member.mtime,
        member.type,
        member.linkname,
        member.uname,
        member.gname,
        tuple(sorted(member.pax_headers.items())),
        member.devmajor,
        member.devminor,
    )


def _regular_members(archive: tarfile.TarFile) -> list[tarfile.TarInfo]:
    members = archive.getmembers()
    if any(member.issym() or member.islnk() for member in members):
        raise ValueError("archive integrity repair rejects link members")
    return members


def _select_member(
    members: list[tarfile.TarInfo], expected_name: str
) -> tarfile.TarInfo:
    normalized = PurePosixPath(expected_name).as_posix()
    matches = [
        member
        for member in members
        if member.name == normalized
        or PurePosixPath(member.name).name == PurePosixPath(normalized).name
    ]
    if len(matches) != 1:
        raise ValueError(
            f"expected exactly one archive member matching {expected_name!r}; "
            f"found {len(matches)}"
        )
    member = matches[0]
    if not member.isfile():
        raise ValueError(f"archive member is not a regular file: {member.name}")
    return member


def _read_member(archive: tarfile.TarFile, member: tarfile.TarInfo) -> bytes:
    extracted = archive.extractfile(member)
    if extracted is None:
        raise ValueError(f"cannot read archive member: {member.name}")
    data = extracted.read()
    if len(data) != member.size:
        raise ValueError(f"short archive member read: {member.name}")
    return data


def _select_checksum_match(
    checksum_bytes: bytes, payload_member_name: str
) -> re.Match[bytes]:
    payload_name = PurePosixPath(payload_member_name).as_posix()
    payload_basename = PurePosixPath(payload_name).name
    matches: list[re.Match[bytes]] = []
    for match in CHECKSUM_LINE_RE.finditer(checksum_bytes):
        raw_name = match.group("name").strip()
        try:
            candidate = raw_name.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("checksum member contains non-UTF-8 path data") from exc
        normalized = PurePosixPath(candidate).as_posix()
        if normalized == payload_name or PurePosixPath(normalized).name == payload_basename:
            matches.append(match)
    if len(matches) != 1:
        raise ValueError(
            "expected exactly one SHA256SUMS line for "
            f"{payload_member_name!r}; found {len(matches)}"
        )
    match = matches[0]
    if not SHA256_RE.fullmatch(match.group("digest")):
        raise ValueError("checksum digest is not an exact SHA-256 value")
    return match


def _repository_relative(path: Path, repository_root: Path | None) -> str:
    if repository_root is None:
        return path.as_posix()
    root = repository_root.resolve(strict=True)
    resolved = path.resolve(strict=True)
    try:
        return resolved.relative_to(root).as_posix()
    except ValueError as exc:
        raise ValueError(f"archive escapes repository root: {path}") from exc


def repair_archive_checksum(
    archive_path: Path | str,
    *,
    payload_member: str,
    checksum_member: str = "SHA256SUMS",
    repository_root: Path | str | None = None,
) -> dict[str, Any]:
    """Repair one embedded checksum by changing only its 64 digest bytes."""

    path = Path(archive_path)
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"required regular archive is missing: {path}")
    root = Path(repository_root) if repository_root is not None else None

    archive_bytes_before = path.read_bytes()
    archive_size_before = len(archive_bytes_before)
    archive_sha256_before = _sha256_bytes(archive_bytes_before)

    with tarfile.open(path, mode="r:") as archive:
        members_before = _regular_members(archive)
        identities_before = tuple(_member_identity(member) for member in members_before)
        order_before = tuple(member.name for member in members_before)
        payload_info = _select_member(members_before, payload_member)
        checksum_info = _select_member(members_before, checksum_member)
        payload_before = _read_member(archive, payload_info)
        checksum_before = _read_member(archive, checksum_info)

    checksum_match = _select_checksum_match(checksum_before, payload_info.name)
    stale_sha256 = checksum_match.group("digest").decode("ascii").lower()
    actual_sha256 = _sha256_bytes(payload_before)
    digest_offset = checksum_info.offset_data + checksum_match.start("digest")
    digest_end = digest_offset + 64
    if digest_end > archive_size_before:
        raise ValueError("checksum digest offset escapes archive")

    changed = stale_sha256 != actual_sha256
    if changed:
        expected_bytes = bytearray(archive_bytes_before)
        expected_bytes[digest_offset:digest_end] = actual_sha256.encode("ascii")
        with path.open("r+b", buffering=0) as handle:
            handle.seek(digest_offset)
            written = handle.write(actual_sha256.encode("ascii"))
            if written != 64:
                raise OSError("short checksum digest write")
            handle.flush()
            os.fsync(handle.fileno())
        archive_bytes_after = path.read_bytes()
        if archive_bytes_after != bytes(expected_bytes):
            raise ValueError("archive changed outside the embedded checksum digest")
    else:
        archive_bytes_after = archive_bytes_before

    archive_size_after = len(archive_bytes_after)
    archive_sha256_after = _sha256_bytes(archive_bytes_after)

    with tarfile.open(path, mode="r:") as archive:
        members_after = _regular_members(archive)
        identities_after = tuple(_member_identity(member) for member in members_after)
        order_after = tuple(member.name for member in members_after)
        payload_after_info = _select_member(members_after, payload_member)
        checksum_after_info = _select_member(members_after, checksum_member)
        payload_after = _read_member(archive, payload_after_info)
        checksum_after = _read_member(archive, checksum_after_info)

    verified_match = _select_checksum_match(checksum_after, payload_after_info.name)
    verified_digest = verified_match.group("digest").decode("ascii").lower()
    verified_payload_digest = _sha256_bytes(payload_after)
    if verified_digest != verified_payload_digest or verified_digest != actual_sha256:
        raise ValueError("embedded checksum verification failed after repair")
    if payload_after != payload_before:
        raise ValueError("archive payload changed during checksum repair")
    if archive_size_before != archive_size_after:
        raise ValueError("archive size changed during checksum repair")
    if identities_before != identities_after:
        raise ValueError("archive member metadata changed during checksum repair")
    if order_before != order_after:
        raise ValueError("archive member order changed during checksum repair")

    repository_path = _repository_relative(path, root)
    relative_path = repository_path
    if repository_path.startswith("upstream/"):
        relative_path = repository_path.removeprefix("upstream/")

    return {
        "path": relative_path,
        "repository_path": repository_path,
        "member": payload_after_info.name,
        "checksum_member": checksum_after_info.name,
        "stale_sha256": stale_sha256,
        "actual_sha256": actual_sha256,
        "archive_sha256_before": archive_sha256_before,
        "archive_sha256_after": archive_sha256_after,
        "archive_size_preserved": True,
        "member_order_preserved": True,
        "member_metadata_preserved": True,
        "payload_preserved": True,
        "only_checksum_digest_changed": True,
        "changed": changed,
        "secret_material": False,
        "focused_test": "tests/security/test_upstream_archive_integrity.py",
    }


def repair_known_upstream_archives(
    upstream_root: Path | str,
    *,
    repository_root: Path | str | None = None,
) -> list[dict[str, Any]]:
    root = Path(upstream_root)
    if not root.is_dir() or root.is_symlink():
        raise ValueError(f"required upstream root is missing: {root}")
    return [
        repair_archive_checksum(
            root / known.relative_path,
            payload_member=known.payload_member,
            checksum_member=known.checksum_member,
            repository_root=repository_root,
        )
        for known in KNOWN_ARCHIVES
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream-root", type=Path, default=Path("upstream"))
    parser.add_argument("--repository-root", type=Path, default=Path.cwd())
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    records = repair_known_upstream_archives(
        args.upstream_root,
        repository_root=args.repository_root,
    )
    if args.check and any(record["changed"] for record in records):
        raise SystemExit("archive integrity drift was repaired during check-only validation")
    print(json.dumps(records, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
