# Codestra OpenBao

This repository is the canonical Git authority for Codestra OpenBao policy,
authentication, server configuration, recovery automation, monitoring and
reviewed deployment evidence. The canonical hostname is
`bao.codestra.media`; the current DNS target is `37.27.128.39`.

The source is deliberately fail-closed. `runtimeApplyAuthorized=false` remains
set while staging, replay prevention, backup/restore, HA, host-memory and
production preflight gates are incomplete. Merging source does not initialize
OpenBao, apply a policy, migrate a secret, deploy a container or enable a
provider/business effect.

## Authority and promotion

All implementation work starts from `development` and follows only:

```text
remediation/openbao-production-completion-v1
  -> development -> test -> staging -> production -> main
```

Protected branches must not be force-pushed or bypassed. The stable required
check names are declared in `.github/workflows/validate.yml`, `security.yml`,
`policy-tests.yml` and `image-build.yml`.

## Current immutable upstream

- OpenBao: `v2.6.2`
- upstream Git SHA: `dd9c19c37a878cf4a81b18efb8d6f0599c7da923`
- platform: `linux/amd64`
- image: `ghcr.io/openbao/openbao@sha256:e29524ba7c3f20d01f562c481e3eccbad6c91df45a2f2531433da4951e408cff`

`CODESTRA_UPSTREAM.json` is the machine-readable authority. Supply-chain
evidence and checksums are under `artifacts/supply-chain/`.

## Local validation

Run:

```bash
scripts/validate.sh
scripts/security.sh
scripts/integration_test.sh
```

The integration test uses an ephemeral local OpenBao dev container. It does
not contact or mutate a deployed environment.

## Runtime safety

- Never commit or artifact secret values, root/bootstrap tokens, unseal or
  recovery shares, private keys, database passwords or provider credentials.
- Never initialize an existing cluster. `scripts/initialize.sh` is the only
  initialization path and writes directly to offline custody.
- A runtime plan is read-only, sanitized, checksummed and destroy-free.
- Apply accepts only that exact saved plan after a protected-environment
  approval from `@kazan555` and a verified off-host backup.
- SSH configuration, keys, users, ports, root policy and SSH firewall rules are
  out of scope and must remain unchanged.
- Secret availability never enables email, SMS, dialing, Odoo writes, n8n
  external effects, publishing, advertising, trading or payments.

Production status and blockers are recorded in
`docs/production/OPENBAO-PRODUCTION-CERTIFICATION.md`.
