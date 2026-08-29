# DO NOT APPLY by default.
# This template requires a separate production change, dual approval, a bound
# Beyvra execution workload identity, non-exportable transit key evidence and
# exact provider/application/environment placeholders.

path "kv-beyvra/data/__APPLICATION__/__ENVIRONMENT__/broker-exchange-custody/__PROVIDER__/*" {
  capabilities = ["read"]
}

path "kv-beyvra/metadata/__APPLICATION__/__ENVIRONMENT__/broker-exchange-custody/__PROVIDER__/*" {
  capabilities = ["read"]
}

path "transit-beyvra/sign/__SIGNING_KEY__" {
  capabilities = ["update"]
}

path "transit-beyvra/verify/__SIGNING_KEY__" {
  capabilities = ["update"]
}

path "transit-beyvra/export/*" {
  capabilities = ["deny"]
}

path "transit-beyvra/keys/__SIGNING_KEY__/config" {
  capabilities = ["deny"]
}

path "kv-*/data/*" {
  capabilities = ["deny"]
}

# The exact allowed Beyvra path above must be added after this broad deny only
# through the generated final policy and tested with OpenBao's policy evaluator.
# The source template intentionally remains non-deployable until that generator
# and denial evidence are approved.
