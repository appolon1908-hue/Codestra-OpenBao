from __future__ import annotations

import importlib.util
import shutil
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts" / "repair_upstream_archive_integrity.py"
SPEC = importlib.util.spec_from_file_location("repair_upstream_archive_integrity", MODULE_PATH)
assert SPEC and SPEC.loader
REPAIR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REPAIR)

SOURCE_ARCHIVE = (
    ROOT
    / "upstream"
    / "physical"
    / "raft"
    / "snapshot"
    / "testdata"
    / "spaces-meta.tar"
)


def member_state(path: Path) -> tuple[tuple[tuple[object, ...], ...], tuple[str, ...], bytes]:
    with tarfile.open(path, mode="r:") as archive:
        members = archive.getmembers()
        identities = tuple(REPAIR._member_identity(member) for member in members)
        order = tuple(member.name for member in members)
        payload_info = REPAIR._select_member(members, "state.bin")
        payload = REPAIR._read_member(archive, payload_info)
    return identities, order, payload


class UpstreamArchiveIntegrityTest(unittest.TestCase):
    def copy_source(self, directory: Path) -> Path:
        self.assertTrue(SOURCE_ARCHIVE.is_file(), SOURCE_ARCHIVE)
        destination = directory / "upstream" / "physical" / "raft" / "snapshot" / "testdata" / "spaces-meta.tar"
        destination.parent.mkdir(parents=True)
        shutil.copyfile(SOURCE_ARCHIVE, destination)
        return destination

    def test_checked_in_archive_is_self_consistent(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            archive = self.copy_source(directory)
            record = REPAIR.repair_archive_checksum(
                archive,
                payload_member="state.bin",
                checksum_member="SHA256SUMS",
                repository_root=directory,
            )
            self.assertFalse(record["changed"])
            self.assertEqual(record["stale_sha256"], record["actual_sha256"])
            self.assertEqual(
                record["archive_sha256_before"], record["archive_sha256_after"]
            )
            self.assertEqual(
                record["repository_path"],
                "upstream/physical/raft/snapshot/testdata/spaces-meta.tar",
            )

    def test_repairs_only_checksum_digest_after_payload_rewrite(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            archive = self.copy_source(directory)

            with tarfile.open(archive, mode="r:") as handle:
                members = handle.getmembers()
                payload_info = REPAIR._select_member(members, "state.bin")
                payload = REPAIR._read_member(handle, payload_info)
            self.assertGreater(len(payload), 0)

            changed_payload = bytearray(payload)
            changed_payload[0] ^= 0x01
            with archive.open("r+b", buffering=0) as handle:
                handle.seek(payload_info.offset_data)
                self.assertEqual(handle.write(changed_payload), len(changed_payload))
                handle.flush()

            archive_size_before = archive.stat().st_size
            identities_before, order_before, payload_before = member_state(archive)
            record = REPAIR.repair_archive_checksum(
                archive,
                payload_member="state.bin",
                checksum_member="SHA256SUMS",
                repository_root=directory,
            )
            identities_after, order_after, payload_after = member_state(archive)

            self.assertTrue(record["changed"])
            self.assertNotEqual(record["stale_sha256"], record["actual_sha256"])
            self.assertNotEqual(
                record["archive_sha256_before"], record["archive_sha256_after"]
            )
            self.assertEqual(archive.stat().st_size, archive_size_before)
            self.assertEqual(identities_after, identities_before)
            self.assertEqual(order_after, order_before)
            self.assertEqual(payload_after, payload_before)
            self.assertTrue(record["archive_size_preserved"])
            self.assertTrue(record["member_order_preserved"])
            self.assertTrue(record["member_metadata_preserved"])
            self.assertTrue(record["payload_preserved"])
            self.assertTrue(record["only_checksum_digest_changed"])
            self.assertFalse(record["secret_material"])

            second = REPAIR.repair_archive_checksum(
                archive,
                payload_member="state.bin",
                checksum_member="SHA256SUMS",
                repository_root=directory,
            )
            self.assertFalse(second["changed"])
            self.assertEqual(
                second["archive_sha256_before"], second["archive_sha256_after"]
            )

    def test_known_archive_set_fails_closed_when_missing(self) -> None:
        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            upstream = directory / "upstream"
            upstream.mkdir()
            with self.assertRaisesRegex(ValueError, "required regular archive is missing"):
                REPAIR.repair_known_upstream_archives(
                    upstream,
                    repository_root=directory,
                )

    def test_checksum_selection_rejects_ambiguous_payload_lines(self) -> None:
        checksum = (
            ("0" * 64) + "  state.bin\n" + ("1" * 64) + " *state.bin\n"
        ).encode("ascii")
        with self.assertRaisesRegex(ValueError, "found 2"):
            REPAIR._select_checksum_match(checksum, "state.bin")


if __name__ == "__main__":
    unittest.main()
