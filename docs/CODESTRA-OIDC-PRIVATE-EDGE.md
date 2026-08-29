# Codestra OpenBao OIDC and Private Edge

## Authority

This repository is the principal source for the OpenBao secrets/encryption runtime at:

```text
https://bao.codestra.media
```

Caddy owns public TLS and the additional source-network gate. Keycloak owns identity. OpenBao policies remain the final authorization boundary for secret access.

## Network boundary

The OpenBao API listener is planned on:

```text
127.0.0.1:8200
```

The cluster listener is planned on:

```text
127.0.0.1:8201
```

The listener example disables native TLS only because Caddy terminates TLS on the same host and the listener is loopback-only. Do not use that setting if the network boundary changes. Native port 8200 must never be published to the Internet.

Caddy permits `bao.codestra.media` only from reviewed source CIDRs and proxies to the private listener. Keycloak and OpenBao authentication are still required after the network check.

## Identity contract

Keycloak client:

```text
openbao-secrets
```

Discovery URL:

```text
https://auth.codestra.co/realms/codestra
```

Exact callbacks:

```text
https://bao.codestra.media/v1/auth/oidc/callback
https://bao.codestra.media/ui/vault/auth/oidc/oidc/callback
http://localhost:8250/oidc/callback
```

The client secret is supplied from:

```text
/run/secrets/openbao_oidc_client_secret
```

and must never enter Git, logs, shell history, or generated evidence.

## OIDC roles and policies

The plan defines no default role. Users must select an allowed role, and the token must contain the matching Keycloak realm role.

```text
Keycloak secrets-operator -> OpenBao role codestra-secrets-operator
Keycloak secrets-admin    -> OpenBao role codestra-secrets-admin
```

Each OpenBao OIDC role binds audience `openbao-secrets` and the nested claim `/realm_access/roles`.

OIDC authentication does not grant secret permissions by itself. Before any apply, create separately reviewed OpenBao policies named:

```text
codestra-secrets-operator
codestra-secrets-admin
```

Those policies must enumerate exact approved mounts/paths and capabilities. Do not attach `root`, `default` with broad access, wildcard administrative paths, or an all-secrets policy merely to make login succeed.

## Storage, seal, and recovery blocker

This branch deliberately leaves the storage backend and seal design unselected. Production deployment is blocked until the following are reviewed and tested:

- storage backend and HA topology;
- seal/unseal strategy;
- initialization custody and recovery shares;
- snapshot/backup encryption and off-host retention;
- restore rehearsal;
- audit device configuration;
- disaster recovery and break-glass procedure;
- version/image pinning and rollback.

Never initialize an OpenBao cluster casually or expose unseal/recovery material in automation output.

## Non-applying plan

`config/codestra/oidc-plan.v1.json` is desired state only. It does not enable an auth mount, install a client secret, write roles, or install policies.

Validation:

```bash
python3 scripts/validate-codestra-integration.py
```

## Controlled installation sequence

1. Accept storage, HA, seal, backup, audit, and recovery designs.
2. Build/pin the reviewed OpenBao artifact.
3. Deploy the API and cluster listeners on private interfaces only.
4. Initialize through an approved operator ceremony and secure recovery material.
5. Install narrowly scoped operator/admin policies.
6. Extend and apply the reviewed Keycloak client contract through protected GitOps.
7. Inject the OIDC client secret through the approved secret path.
8. Enable the OIDC auth method and write config/roles from the exact accepted plan.
9. Validate operator/admin claim and policy separation.
10. Validate Caddy source allowlist and TLS configuration.
11. Run backup/restore, seal/restart, token-revocation, audit-log, and rollback tests.
12. Run external port tests proving 8200/8201 are not public.
13. Obtain explicit production approval.

## Required negative tests

- source IP outside the Caddy allowlist receives `403`;
- user with only observability roles cannot log in to an OpenBao secrets role;
- `secrets-operator` cannot acquire admin policy;
- wrong audience, issuer, callback, or missing role fails;
- revoked Keycloak session/token cannot continue indefinitely;
- native API port is unreachable externally;
- no secret value appears in Caddy/OpenBao/CI logs;
- failed configuration leaves the previous working state recoverable.

A merge does not authorize initialization, unseal, OIDC apply, Caddy reload, or production access.
