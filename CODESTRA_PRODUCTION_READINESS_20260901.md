# Codestra Production Readiness Gate — OpenBao

Status: NOT PRODUCTION CERTIFIED

Governed by `Infustruction-repo/CODESTRA_PRODUCTION_READINESS_WAVE_20260901.md`.

Required: reconcile current workload-secret authority and hardened runtime work; exact image/source pin; HCL/policy tests; Critical=0; High=0; Keycloak JWT workload auth; least-privilege per-workload paths; no plaintext/env/Git secret injection; audit device; private Prometheus telemetry; Raft health; backup/off-host snapshot; isolated restore; rotation/revocation; staging consumer tests; runtime read-back; rollback.

Do not auto-initialize or destroy an existing cluster. Do not expose 8200/8201 publicly. Do not modify SSH access. `runtimeApplyAuthorized` must remain false until certification evidence supports activation.
