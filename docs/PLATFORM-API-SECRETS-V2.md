# Codestra Platform API Secrets V2

This branch completes source-side OpenBao policies and workload-auth roles for the governed platform API. It does not initialize, unseal, rekey or mutate a live OpenBao cluster.

## Staging policy namespaces

```text
codestra/staging/middleware/*
codestra/staging/prometheus/monitoring-readonly
codestra/staging/alertmanager/middleware
codestra/staging/provider-adapters/marketing
codestra/staging/provider-adapters/ai
codestra/staging/provider-adapters/email
codestra/staging/provider-adapters/sms
codestra/staging/provider-adapters/social
```

## Workload identities

- Middleware API and worker have separate policies.
- Prometheus may read only the monitoring client credential required to request `metrics.read` tokens.
- Alertmanager may read only its Middleware alert-ingestion credential.
- Each provider adapter may read only its own provider namespace.
- Marketing, AI, Communication, Social, n8n, Odoo, Grafana and browser applications receive no provider-adapter secret access.

## Invariants

- workload identity or short-lived brokered access;
- bounded TTL, non-renewable one-shot access where appropriate;
- no broad recursive read or root-like policy;
- no access-token storage;
- no customer, form, survey, message, lead or provider payload storage;
- rotation and revocation procedures;
- audit-device contract;
- policy mutation tests;
- OpenBao upstream image digest and Codestra configuration SHA recorded separately;
- runtime use remains blocked until the official upstream image/config provenance is verified.

## Safety

```text
OPENBAO_RUNTIME_APPLY=false
SECRETS_WRITTEN=false
TOKENS_ISSUED=false
PROVIDER_WRITES=false
PRODUCTION_CHANGED=false
```
