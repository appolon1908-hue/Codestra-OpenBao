# OpenBao operations

## Routine read-only checks

Use mTLS and a short-lived operator or observer token from a protected local
file. Never pass a secret on the command line or enable shell tracing.

```bash
bao status -format=json
bao operator raft list-peers -format=json
bao audit list -format=json
bao auth list -format=json
bao secrets list -format=json
scripts/drift.sh
scripts/verify.sh
```

Evidence must omit token values, secret values, private keys and unseal shares.

## Initialization and unseal

Initialization is a one-time custody operation. First confirm the exact target,
empty/new storage, `initialized=false`, protected offline destination and human
authorization. `scripts/initialize.sh` is the only implementation and refuses
initialized or ambiguous state. Its JSON output goes directly to offline
custody and is never logged or uploaded.

Unseal shares are read from distinct protected files by
`scripts/unseal_from_files.py`; only the number submitted is printed. Never
reinitialize, replace recovery material or reset Raft to resolve drift.

## Plan and apply

1. Promote and validate the exact environment branch.
2. Run the protected `plan.yml` workflow on a private runner.
3. Inspect the sanitized plan and its SHA-256. Destruction or warnings block
   apply.
4. Dispatch the matching `deploy-<environment>.yml` with exact source SHA, plan
   run ID, plan hash and confirmation.
5. Obtain protected-environment approval from `@kazan555`.
6. Preflight exact image/source/HA/network/memory state.
7. Take and verify encrypted local and immutable off-host Raft snapshots.
8. Apply only the downloaded saved plan; never regenerate it during apply.
9. Read back every operation, runtime identity and SSH hash baseline.

Apply supports only creation/update of the reviewed KV v2 engine, JWT auth,
CEL roles, policies and file audit device. Delete, mount replacement, audit
disable and initialization are unsupported.

## Shutdown and restart

Before a planned restart, verify a current off-host snapshot, healthy Raft
quorum and recovery custody. Restart one voter at a time. Confirm leader,
peers, unsealed state, audit, metrics and workload renewals before proceeding.
Dynamic consumers must revoke child leases on shutdown.

## Incidents

Seal state, audit failure, unavailable leader, auth surge, denial surge,
rotation/revocation failure, backup age and drift page the platform-security
owner. Preserve logs and sanitized accessors; never paste credentials into an
incident channel.

The current production container is uninitialized and must not be initialized
until the production release, HA, custody and preflight gates are satisfied.
