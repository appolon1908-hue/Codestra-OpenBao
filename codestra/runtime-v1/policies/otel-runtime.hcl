path "secret/data/observability/opentelemetry/runtime" {
  capabilities = ["read"]
}

path "secret/data/observability/opentelemetry/tenant-routing" {
  capabilities = ["read"]
}

path "pki_observability/issue/otel-collector" {
  capabilities = ["create", "update"]
}

path "auth/token/lookup-self" {
  capabilities = ["read"]
}

path "auth/token/renew-self" {
  capabilities = ["update"]
}

path "sys/leases/renew" {
  capabilities = ["update"]
}
