# Render __BUSINESS__, __APPLICATION__, __ENVIRONMENT__, __DATABASE_ROLE__,
# __PKI_ROLE__ and __TRANSIT_KEY__ only from reviewed deployment inventory.
# The corresponding JWT role must bind the same immutable claims and audience.

path "kv-__BUSINESS__/data/__APPLICATION__/__ENVIRONMENT__/*" {
  capabilities = ["read"]
}

path "kv-__BUSINESS__/metadata/__APPLICATION__/__ENVIRONMENT__/*" {
  capabilities = ["read", "list"]
}

path "database/creds/__DATABASE_ROLE__" {
  capabilities = ["read"]
}

path "pki-platform-issuing/issue/__PKI_ROLE__" {
  capabilities = ["update"]
}

path "transit-platform/encrypt/__TRANSIT_KEY__" {
  capabilities = ["update"]
}

path "transit-platform/decrypt/__TRANSIT_KEY__" {
  capabilities = ["update"]
}

path "sys/leases/renew" {
  capabilities = ["update"]
}

path "sys/leases/revoke" {
  capabilities = ["update"]
}

path "auth/token/create*" {
  capabilities = ["deny"]
}

path "sys/mounts/*" {
  capabilities = ["deny"]
}

path "sys/auth/*" {
  capabilities = ["deny"]
}

path "sys/audit/*" {
  capabilities = ["deny"]
}
