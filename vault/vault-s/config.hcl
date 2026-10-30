# vault-s — the Transit auto-unseal provider. Shamir seal (1-of-1): it is the
# one node a human (or `make unseal`) unseals after every cold start.
# Runs Vault OSS; holds only the Transit autounseal key. No app secrets here.
ui            = false
disable_mlock = true

api_addr     = "https://vault-s:8200"
cluster_addr = "https://vault-s:8201"

default_lease_ttl = "1h"
max_lease_ttl     = "2160h"

listener "tcp" {
  address         = "0.0.0.0:8200"
  tls_cert_file   = "/vault/config/tls/vault.crt"
  tls_key_file    = "/vault/config/tls/vault.key"
  tls_min_version = "tls13"
}

storage "raft" {
  path    = "/vault/file"
  node_id = "vault-s"
}

log_level = "warn"
