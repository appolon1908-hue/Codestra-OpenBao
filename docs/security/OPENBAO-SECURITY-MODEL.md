# OpenBao security model

## Trust boundaries

Git contains desired configuration and hashes, never secret values. Runtime
credentials originate from protected custody or short-lived identity. Workload
traffic is private; public browser administration terminates at the separately
owned authenticated edge.

The native listener requires TLS 1.3 and a trusted client certificate. Server
certificates, private keys and client CA files are mounted read-only from
protected paths. The Compose service uses a read-only root filesystem, drops
all capabilities, prohibits privilege escalation and publishes no host ports.
Host preflight rejects active unencrypted swap.

## Authentication

Workload JWTs must have issuer
`https://auth.codestra.co/realms/codestra`, audience `openbao`, the exact
workload `azp`, exact `codestra_environment`, and non-empty `iss`, `sub`, `aud`,
`azp`, `iat`, `exp`, `jti` and environment claims. `exp - iat` is at most 300
seconds. Wildcard client matching and the default policy are disabled.

OpenBao v2.6.2 compiles and enforces the CEL claim expression, but native JWT
authentication does not provide the required stateful one-time JTI replay
cache. Source therefore records `jtiReplayCacheImplemented=false` and refuses
runtime authorization. A reviewed stateful enforcement point plus positive and
negative replay tests is required before this gate can become true.

## Authorization and delivery

Every policy binds one service identity to one environment and exact path
prefixes. Cross-service, cross-environment, wildcard, system administration,
root and provider-master access are denied. Agent-rendered files must use
atomic replacement, mode `0400` and the service owner. Required missing files
fail startup. Dynamic leases renew and revoke on shutdown; static KV v2 values
re-render on version change.

## Audit and evidence

The prepared file audit device hashes accessors and does not log raw values.
Sanitized audit records flow to Alloy/Loki. CI rejects common credential
formats in the working tree and full Git history. Plans, read-back and
certification evidence contain paths, hashes, counts and status only.

## Separate business authorization

OpenBao access never enables live email, SMS, dialing, Odoo writes, n8n
external effects, social publishing, advertising spend, AI mutations, trading,
payments or other provider effects. Those kill switches remain false and are
outside this platform release.
