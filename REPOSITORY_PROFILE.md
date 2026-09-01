# Repository profile

| Property | Authority |
| --- | --- |
| Repository | `appolon1908-hue/Codestra-OpenBao` |
| System | Codestra principal secrets and encryption authority |
| Canonical hostname | `bao.codestra.media` |
| Current DNS target | `37.27.128.39` |
| Integration branch | `development` |
| Release branch | `production` |
| Final protected source | `main` |
| Runtime owner | `platform-security` |
| Required reviewer | `@kazan555` |
| Upstream | `openbao/openbao` v2.6.2 at exact Git and image digests |
| Storage | integrated Raft |
| Workload authentication | Keycloak JWT from `https://auth.codestra.co/realms/codestra` |
| Workload audience | `openbao` |
| Edge authority | external edge repository; this repository publishes a handoff contract only |

This repository owns desired OpenBao configuration and sanitized evidence. It
does not own DNS, host SSH access, Caddy/Nginx deployment, Keycloak realm
administration, workload application releases, provider kill switches or
production credentials.

Production consumers are admitted individually. Current source defines Kong,
Middleware API, Middleware Worker, n8n, Odoo, Prometheus and selected provider
adapters where justified. No repository receives broad OpenBao access merely
because it is a Codestra repository.

Current live production is a source-prepared bootstrap, not a certified
secrets platform: OpenBao v2.6.1 is running as one uninitialized Raft node. The
desired v2.6.2 runtime, initialization, HA, audit, monitoring, backup/restore,
workload authentication and consumer migrations are not applied.
