path "secret/data/businesses/beyvra/trading/*" {
  capabilities = ["deny"]
}

path "secret/metadata/businesses/beyvra/trading/*" {
  capabilities = ["deny"]
}

path "transit/sign/beyvra-*" {
  capabilities = ["deny"]
}

path "transit/decrypt/beyvra-*" {
  capabilities = ["deny"]
}

path "database/creds/beyvra-trading-*" {
  capabilities = ["deny"]
}

path "ssh/sign/beyvra-*" {
  capabilities = ["deny"]
}
