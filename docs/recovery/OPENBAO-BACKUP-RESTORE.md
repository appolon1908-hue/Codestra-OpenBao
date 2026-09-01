# OpenBao backup and restore

The implemented Raft backup path creates a snapshot, verifies it, encrypts it
with age X25519, independently decrypts and inspects it, stores a mode-`0400`
local copy, writes a SHA-256, and copies both objects to an immutable rclone
destination. The destination must attest object lock and at least 30 days of
retention. Daily, weekly and monthly targets are 30/12/12; RPO is 24 hours and
RTO is four hours.

`scripts/backup.sh` never prints or uploads snapshot data. GitHub may retain
only sanitized backup metadata. A snapshot command without local artifact,
checksum, decrypt/inspect proof and off-host read-back is not a passing backup.
`scheduled-backup.yml` is the daily 02:17 UTC production trigger after final
promotion; its environment is restricted to `main`, it checks out and verifies
the exact `production` branch, and it artifacts only the sanitized evidence
JSON.

## Isolated restore

`backup-restore-test.yml` moves the encrypted artifact directly from off-host
storage to a dedicated restore runner; GitHub artifacts never transport it.
`scripts/restore-test.sh` requires:

- a non-production target address identifying an already isolated cluster;
- a target cluster ID different from the source/production cluster;
- explicit isolated-restore acknowledgement;
- protected age identity and unseal shares;
- checksum and snapshot inspection;
- a representative non-production secret hash; and
- measured restore duration.

The restore forcibly loads the snapshot only after those exclusion checks,
unseals from protected files and validates the representative hash without
printing its value.

## Current evidence

No scheduled production backup run, protected immutable off-host destination
attestation or successful isolated restore evidence was observed on 2026-09-01.
Therefore `BACKUP=FAIL`, `OFFHOST_BACKUP=FAIL`, `RESTORE=FAIL`, `RPO=FAIL` and
`RTO=FAIL`. The scheduled source is prepared; the runtime gates have not passed.
