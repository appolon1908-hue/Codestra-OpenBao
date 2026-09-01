# OpenBao production checklist

The only valid states in this checklist are `PASS`, `WARNING`, `FAIL` and
`N/A`. A source implementation is not a runtime `PASS`.

## Source and release

- PASS — exact OpenBao v2.6.2 Git/image identity and linux/amd64 SBOM.
- PASS — local configuration, policy, HCL, Compose, secret and history scans.
- PASS — exact-digest fresh vulnerability scan has zero unresolved exploitable
  HIGH/CRITICAL findings under expiring VEX review.
- WARNING — remediation branch is local and not yet protected/promoted.
- FAIL — immutable signed production release and provenance have not run.
- FAIL — required checks/protections/environments are not yet installed on all
  remote promotion branches.

## Staging and recovery

- FAIL — development runtime certification.
- FAIL — test runtime certification.
- FAIL — production-equivalent three-voter staging deployment.
- FAIL — Keycloak authentication and negative JWT/replay suite.
- FAIL — rotation, revocation and cross-environment denial runtime evidence.
- FAIL — soak, failure injection, backup and isolated restore.

## Production pre-change

- FAIL — desired image/source read-back.
- FAIL — initialized/unsealed healthy three-voter Raft.
- FAIL — native TLS/mTLS and Caddy edge ownership.
- FAIL — encrypted or disabled swap.
- FAIL — audit, Alloy/Loki, Prometheus, dashboard and alert evidence.
- FAIL — fresh verified immutable off-host backup.
- PASS — no public 8200/8201 listener observed.
- PASS — SSH access state unchanged.

## Deployment and consumers

- FAIL — protected exact saved-plan apply has not run.
- FAIL — production read-back has not passed.
- FAIL — no consumer migration is certified.
- PASS — live email, SMS, dialing, Odoo writes, n8n external effects, social
  publishing, advertising, trading and payments were not enabled by this work.

`PRODUCTION_DEPLOYMENT_AUTHORIZED=NO`
