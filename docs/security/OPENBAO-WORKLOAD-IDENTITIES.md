# OpenBao workload identities

`config/policies/workload-identities.v1.json` is the owner and eligibility
inventory. `config/workload-secret-authority.v1.json` is generated authority;
`openbao/auth/jwt-roles.v1.json` contains the exact CEL roles. There are 32
prepared roles across four environments. All runtime bindings remain disabled.

| Identity | Owner | Environments | Purpose |
| --- | --- | --- | --- |
| `kong-gateway` | platform-edge | all | gateway runtime/upstream material |
| `middleware-api` | middleware-platform | all | API-only integration credentials |
| `middleware-worker` | middleware-platform | all | approved provider effect executor, split by provider family |
| `n8n-automation` | automation-platform | all | Middleware client/orchestration credential only |
| `odoo-integration` | business-systems | all | exact Odoo integration credential only |
| `prometheus-openbao` | observability | all | authenticated metrics only; no general secret reads |
| `klyrow-email-adapter` | Klyrow/email | staging, production | exact email adapter path; live effects remain disabled |
| `telnexa-sms-adapter` | Telnexa/SMS | staging, production | exact SMS adapter path; live effects remain disabled |
| `vicidial-adapter` | communications | staging, production | exact telephony adapter path; dialing remains disabled |
| `crawler-adapter` | crawler platform | staging, production | exact crawler adapter path |

An identity is admitted only when its owner, runtime consumer, exact Keycloak
client, environment claim, paths, TTL, rotation procedure, revocation procedure
and audit evidence exist. General repository membership is not eligibility.

Negative tests must prove wrong issuer, audience, environment, client, expiry,
lifetime, missing claim and replay are denied. Revoking one workload must not
affect unrelated workloads. The isolated source suite proves those JWT and JTI
boundaries; each deployed environment must repeat them against its real
Keycloak identity before certification.
