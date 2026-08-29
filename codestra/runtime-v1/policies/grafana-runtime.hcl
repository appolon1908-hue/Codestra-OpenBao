path "secret/data/observability/grafana/runtime" {
  capabilities = ["read"]
}

path "secret/data/observability/grafana/oauth" {
  capabilities = ["read"]
}

path "secret/data/observability/grafana/datasources/*" {
  capabilities = ["read"]
}

path "pki_observability/issue/grafana-server" {
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
