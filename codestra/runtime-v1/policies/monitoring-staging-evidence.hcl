# Codestra Stage 6 monitoring secret boundary.
# This policy exposes only the Keycloak monitoring client material required to
# obtain short-lived read tokens. It grants no business-provider credentials.
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
