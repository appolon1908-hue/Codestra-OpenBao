# Codestra Stage 6 monitoring secret boundary.
# Source template only: this file is not part of the active policy set.
path "kv-platform/data/observability/middleware/staging/keycloak-client" {
  capabilities = ["read"]
}

path "kv-platform/metadata/observability/middleware/staging/keycloak-client" {
  capabilities = ["read"]
}

path "auth/token/lookup-self" {
  capabilities = ["read"]
}

path "kv-*/data/providers/*" {
  capabilities = ["deny"]
}

path "kv-*/data/beyvra/execution/*" {
  capabilities = ["deny"]
}

path "kv-*/data/communications/delivery/*" {
  capabilities = ["deny"]
}

path "kv-*/data/marketing/provider-write/*" {
  capabilities = ["deny"]
}
