# Repository Authority

Canonical service hostname: `bao.codestra.media`
Canonical DNS A target: `37.27.128.39`
DNS TTL: `600`

This repository is the principal source authority for the Codestra OpenBao deployment/configuration. Do not introduce alternate public hostnames or legacy domain names in configuration, documentation, examples, health checks, or deployment manifests.

Exposure policy: PROTECTED BROWSER/API ACCESS ONLY. `bao.codestra.media` may be routed through Caddy only with strong authentication, strict network policy, TLS, security headers, rate limits, audit logging, and least-privilege policies. Native storage/backend/admin ports must remain private. Never expose unsealed bootstrap/recovery material, root tokens, private keys, or provider credentials.

Upstream/downstream: approved platform services authenticate to OpenBao using least-privilege machine identities -> OpenBao returns scoped secrets/leases -> audit logs and operational health flow to the observability stack. OpenBao must never be used as a general data store or bypass Middleware authorization.

Persistent branch model: `development`, `test`, `staging`, `production`, `main`. Temporary branches: `remediation/*`, `feature/*`, `fix/*`, `upgrade/*`, `security/*`, `docs/*`, `hotfix/*`, `release/*`, `rollback/*`.

Promotion: `remediation/openbao-production-completion-v1 -> development -> test -> staging -> production -> main`. Upstream sync branches may target `development` through review. Never upgrade directly on test, staging, production, or main.

Runtime mutation is not implied by a merge. A checksummed plan must be created
from the exact current environment branch, independently reviewed, and applied
without regeneration only after `@kazan555` approves the protected environment.
Initialization, recovery custody, business-effect authorization and SSH access
are separate authorities.
