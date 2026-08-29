path "secret/data/observability/loki/runtime" {
  capabilities = ["read"]
}

path "secret/data/observability/loki/object-storage" {
  capabilities = ["read"]
}

path "pki_observability/issue/loki-server" {
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
