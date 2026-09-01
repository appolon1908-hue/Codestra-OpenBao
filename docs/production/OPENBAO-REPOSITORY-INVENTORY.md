# Codestra OpenBao repository inventory

Inventory timestamp: 2026-09-01 (Europe/Berlin)

Repository: `appolon1908-hue/Codestra-OpenBao`

Integration base: `development` at `2c199ee38ce372af4e0355c83e018f417e3afc8f`

Remediation branch: `remediation/openbao-production-completion-v1`

This inventory was produced after fetching every remote branch and pull-request
head. It records observed state; it does not claim that an unimplemented or
untested control passes.

## Protected and promotion branches

| Branch | Observed SHA | Ahead/behind `development` | Protection | Head signature |
| --- | --- | ---: | --- | --- |
| `development` | `2c199ee38ce372af4e0355c83e018f417e3afc8f` | `0/0` | none | valid |
| `test` | `6667709d257cdd97ceb22a97aeff798928c1bf28` | `2/0` | none | valid |
| `staging` | `6e092ce5cf8e1cd76587118103653ebb7e7620b0` | `3/0` | none | valid |
| `production` | `38ff3f3d7a2dcd9f03455415c26b2562a50adb34` | `0/68` | none | unsigned |
| `main` | `5f5e3583585081e450f945440a1fab503bfa8399` | `1/62` | protected | unsigned |

The ahead/behind values are shown as `<branch ahead>/<branch behind>` relative
to `development`. The promotion branches are not linear today: `test` and
`staging` contain later integration merges, while `production` and `main` do
not contain the current development line. Promotion must therefore use reviewed
pull requests and exact synthetic merge validation, not ref movement or a
force-push.

`main` currently requires one approving review, stale-review dismissal,
approval after the last push, conversation resolution, linear history, signed
commits, and enforcement for administrators. Force pushes and deletion are
disabled. It does not require a CODEOWNER review or any status-check context.
The other four promotion branches are unprotected.

## All observed remote branches

| Branch | SHA | Disposition |
| --- | --- | --- |
| `main` | `5f5e3583585081e450f945440a1fab503bfa8399` | protected release destination; not a development workspace |
| `development` | `2c199ee38ce372af4e0355c83e018f417e3afc8f` | integration authority and remediation base |
| `test` | `6667709d257cdd97ceb22a97aeff798928c1bf28` | promotion target after development certification |
| `staging` | `6e092ce5cf8e1cd76587118103653ebb7e7620b0` | promotion target after test certification |
| `production` | `38ff3f3d7a2dcd9f03455415c26b2562a50adb34` | production source target; currently stale |
| `prod-readiness-20260901` | `5f5e3583585081e450f945440a1fab503bfa8399` | exact alias of current `main`; no unique work |
| `docs/repository-profile-v1` | `32f32f889b6fd7df36351e9ac3cde22d2006c79c` | reuse accurate profile concepts; do not replace newer source-sync logic |
| `feature/codestra-corporate-suite-v1-20260829` | `b280999a774e4c8dd59a4ad7767e5a9dd74bf610` | useful intake controls already evolved and merged into `development` |
| `feature/intake-monitoring-v1-20260830` | `21759128a11c5dfeb8d4c85ea7d93fc8121a48b1` | fully represented by later development history |
| `fix/corporate-review-hardening-v1-20260830` | `f5f71fbe846713c706a997505996636edbb3312f` | fully represented by later development history |
| `feature/private-bind-keycloak-oidc-v1` | `a3f6c4469cdf7acee032b024fcc3c707b7e71645` | preserve private-listener, mTLS and exact-OIDC controls through the newer `codestra/runtime-v1` authority; do not create a duplicate `config/codestra` tree |
| `integration/marketing-platform-staging-secrets-v1-20260830` | `853b3d20985a6fb1049a9128133933c6ffaa3bf8` | later versions already merged into `development` |
| `integration/middleware-immutable-digest-lock-v1-20260830` | `8941bfa48493d562e535042033ddd3c3a6a5a594` | retain immutable digest/evidence constraints from the development integration contracts |
| `integration/codestra-observability-suite-v1-20260830` | `e84b471acff573151c8deddbe77226278417fb6e` | controlled monitoring and activation contracts already merged into `development` |
| `integration/stage6-intake-observability-v1-20260830` | `b83bc6638de5897f767dc13697fcb21d5e55fbdf` | monitoring token, deny-path and scope controls already merged into `development` |
| `remediation/workload-secret-authority` | `7294d484825c7d661e8c4531d3c48cafd4966d70` | four production-quality commits reconciled onto the remediation branch |
| `security/openbao-protected-source-gates-20260901` | `130d329006c69ca2eb34658be1e88dd84de2d48c` | five production-quality commits reconciled and hardened on the remediation branch |

## Open pull requests

| PR | Head and exact SHA | Base | State at inventory | Disposition |
| --- | --- | --- | --- | --- |
| #18, workload secret authority | `remediation/workload-secret-authority` at `7294d484825c7d661e8c4531d3c48cafd4966d70` | `main` | open; no CI check | superseded by reconciled implementation on the development-rooted remediation branch |
| #17, protected source gates | `security/openbao-protected-source-gates-20260901` at `130d329006c69ca2eb34658be1e88dd84de2d48c` | `main` | open; `validate-source` passed; latest review identified incomplete token/key scanning | superseded by reconciled implementation plus regression coverage for provider tokens and standard private-key headers |
| #9, repository profile | `docs/repository-profile-v1` at `32f32f889b6fd7df36351e9ac3cde22d2006c79c` | `main` | draft; no CI check | reuse accurate text in the canonical profile; do not merge its stale workflow wholesale |

PRs #17 and #18 incorrectly target `main` for development work. Their useful
commits were replayed selectively on `remediation/openbao-production-completion-v1`,
which is rooted in protected-source `development`. The old PRs must not be used
as promotion substitutes.

## Implementation reconciliation

The current development line already contains the latest corporate profile,
private-edge/OIDC planning, workload policy generation, marketing staging
bindings, controlled-intake contracts, immutable Middleware evidence, and
Stage 6 monitoring-token controls. Older parallel directories are therefore not
merged wholesale.

The remediation branch additionally retains and reconciles:

- the exact-source importer and reviewed sync boundary from PR #17;
- the fail-closed workload authority and mutation tests from PR #18;
- the sanitized-fixture safety change present only on `main`;
- exact OpenBao `v2.6.2` source and Linux/AMD64 image identity;
- a repository-wide provider-token and private-key scanner with path-only error
  reporting; and
- upstream synchronization into `development`, preserving the mandated
  promotion order.

No runtime authorization was enabled during reconciliation.

## Repository authority gaps observed

- `.github/CODEOWNERS` is absent from every promotion branch.
- `README.md`, `REPOSITORY_PROFILE.md`, production preflight, restore
  certification, rollback and final certification evidence are absent from the
  current development line.
- There are no GitHub deployment environments or protected-environment
  reviewers.
- Repository rulesets are empty.
- Actions permit all actions and repository-level SHA pin enforcement is off.
- Default workflow permissions are read-only and workflows cannot approve pull
  requests; individual legacy workflows still require permission review.
- Only `main` is protected; it has no required status checks and does not
  require CODEOWNER review.
- `production` has no workflow. `main` has only upstream source sync. The
  development/test/staging lines have seven legacy validators but lack the
  complete uniquely named configuration, policy, security, image, SBOM,
  provenance, integration, recovery, drift, release and environment-deployment
  checks required for production.
- Action dependencies are not repository-wide enforced as immutable SHAs.
- No release tag exists in this repository.
- Current documentation describes source-prepared, non-deployed behavior and
  cannot serve as production certification.

## Required remediation boundary

The canonical source must be completed on the development-rooted remediation
branch, tested there, and promoted only through:

```text
remediation/openbao-production-completion-v1
  -> development -> test -> staging -> production -> main
```

Branch protection will not be weakened. Any protection or environment change
must add safety gates. Runtime deployment remains prohibited until staging,
backup/restore, immutable release and production preflight evidence pass. SSH
configuration and SSH firewall rules are explicitly outside scope and must
remain unchanged.

## Remediation branch update

The remediation branch now contains CODEOWNERS, Dependabot configuration,
repository-wide immutable action validation, the eleven uniquely named CI
contexts, protected plan/saved-plan apply workflows, release signing and
provenance, backup/isolated restore and drift workflows. Those source gaps are
closed on the remediation branch. Their remote protection, environment,
private-runner and runtime execution evidence remain open until promotion; this
inventory does not retroactively mark them deployed.
